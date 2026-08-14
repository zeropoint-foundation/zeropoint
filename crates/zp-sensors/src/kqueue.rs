//! kqueue-based sensors for macOS/FreeBSD.
//!
//! Two kqueue filter types:
//!
//! - `EVFILT_VNODE` — file change notifications. Register a file descriptor
//!   and get notified on write, rename, delete, attrib change.
//! - `EVFILT_PROC` — process lifecycle. Register a PID and get notified on
//!   exit, fork, exec.
//!
//! Both are fully event-driven — zero polling. The kqueue file descriptor
//! is monitored by tokio via `AsyncFd`.

use std::collections::HashMap;
use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use chrono::Utc;
use libc::{
    close, kevent, kqueue, EV_ADD, EV_DELETE, EV_ENABLE, EVFILT_PROC, EVFILT_VNODE,
    NOTE_DELETE, NOTE_EXIT, NOTE_EXEC, NOTE_FORK, NOTE_RENAME, NOTE_WRITE,
};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::event::{ProcessEventKind, SensorEvent};

/// Errors from kqueue operations.
#[derive(Debug, thiserror::Error)]
pub enum KqueueError {
    #[error("kqueue() syscall failed: {0}")]
    Create(std::io::Error),
    #[error("kevent() syscall failed: {0}")]
    Kevent(std::io::Error),
    #[error("failed to open file for watching: {path}: {source}")]
    FileOpen {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Commands the sensor layer sends to the kqueue task.
pub enum KqueueCommand {
    WatchFile(PathBuf),
    UnwatchFile(PathBuf),
    WatchPid { pid: u32, tool_name: String },
    UnwatchPid(u32),
}

/// State for a watched file.
struct WatchedFile {
    path: PathBuf,
    /// Keep the File open so the fd stays valid for kqueue.
    _file: File,
}

/// State for a watched process.
struct WatchedProcess {
    pid: u32,
    tool_name: String,
}

/// Newtype wrapper so `AsyncFd` can own the kqueue fd.
struct KqueueFd(RawFd);

impl AsRawFd for KqueueFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// Run the kqueue sensor as a background task.
///
/// Accepts registration commands via `cmd_rx` and emits sensor events
/// via `event_tx`. Watches files (EVFILT_VNODE) and processes (EVFILT_PROC).
pub async fn run_kqueue_sensor(
    initial_files: Vec<PathBuf>,
    mut cmd_rx: mpsc::Receiver<KqueueCommand>,
    event_tx: mpsc::Sender<SensorEvent>,
) {
    let kq_fd = unsafe { kqueue() };
    if kq_fd < 0 {
        error!(
            error = %std::io::Error::last_os_error(),
            "kqueue() syscall failed"
        );
        return;
    }

    // Ensure kq_fd is closed on exit.
    struct KqGuard(RawFd);
    impl Drop for KqGuard {
        fn drop(&mut self) {
            unsafe { close(self.0) };
        }
    }
    let _guard = KqGuard(kq_fd);

    let mut watched_files: HashMap<RawFd, WatchedFile> = HashMap::new();
    let mut watched_procs: HashMap<u32, WatchedProcess> = HashMap::new();

    // Register initial file watches.
    for path in &initial_files {
        if let Err(e) = register_file(kq_fd, path, &mut watched_files) {
            warn!(path = %path.display(), error = %e, "Failed to watch initial file");
        }
    }

    let async_fd = match AsyncFd::with_interest(KqueueFd(kq_fd), Interest::READABLE) {
        Ok(fd) => fd,
        Err(e) => {
            error!(error = %e, "Failed to create AsyncFd for kqueue");
            return;
        }
    };

    loop {
        tokio::select! {
            // Handle registration commands.
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(KqueueCommand::WatchFile(path)) => {
                        if let Err(e) = register_file(kq_fd, &path, &mut watched_files) {
                            warn!(path = %path.display(), error = %e, "Failed to watch file");
                        }
                    }
                    Some(KqueueCommand::UnwatchFile(path)) => {
                        unregister_file(kq_fd, &path, &mut watched_files);
                    }
                    Some(KqueueCommand::WatchPid { pid, tool_name }) => {
                        if let Err(e) = register_pid(kq_fd, pid, tool_name, &mut watched_procs) {
                            warn!(pid, error = %e, "Failed to watch PID");
                        }
                    }
                    Some(KqueueCommand::UnwatchPid(pid)) => {
                        unregister_pid(kq_fd, pid, &mut watched_procs);
                    }
                    None => {
                        debug!("kqueue command channel closed, shutting down");
                        return;
                    }
                }
            }

            // Wait for kqueue events.
            readable = async_fd.readable() => {
                let mut guard = match readable {
                    Ok(g) => g,
                    Err(e) => {
                        error!(error = %e, "AsyncFd readable failed");
                        return;
                    }
                };

                // Drain and translate in one block so `libc::kevent` (not Send)
                // doesn't live across an await point.
                let sensor_events: Vec<SensorEvent> = {
                    let raw = drain_kqueue_events(kq_fd);
                    raw.iter()
                        .filter_map(|ev| translate_event(ev, &watched_files, &watched_procs))
                        .collect()
                };

                for sensor_event in sensor_events {
                    if event_tx.send(sensor_event).await.is_err() {
                        debug!("Sensor event channel closed");
                        return;
                    }
                }

                guard.clear_ready();
            }
        }
    }
}

/// Register a file for EVFILT_VNODE notifications.
fn register_file(
    kq_fd: RawFd,
    path: &Path,
    watched: &mut HashMap<RawFd, WatchedFile>,
) -> Result<(), KqueueError> {
    let file = File::open(path).map_err(|e| KqueueError::FileOpen {
        path: path.to_path_buf(),
        source: e,
    })?;
    let fd = file.as_raw_fd();

    let ev = libc::kevent {
        ident: fd as usize,
        filter: EVFILT_VNODE,
        flags: EV_ADD | EV_ENABLE,
        fflags: NOTE_WRITE | NOTE_DELETE | NOTE_RENAME,
        data: 0,
        udata: std::ptr::null_mut(),
    };

    let ret = unsafe {
        kevent(
            kq_fd,
            &ev as *const libc::kevent,
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };

    if ret < 0 {
        return Err(KqueueError::Kevent(std::io::Error::last_os_error()));
    }

    debug!(path = %path.display(), fd, "Watching file");
    watched.insert(fd, WatchedFile {
        path: path.to_path_buf(),
        _file: file,
    });

    Ok(())
}

/// Unregister a file watch.
fn unregister_file(kq_fd: RawFd, path: &Path, watched: &mut HashMap<RawFd, WatchedFile>) {
    let fd = watched
        .iter()
        .find(|(_, w)| w.path == path)
        .map(|(fd, _)| *fd);

    if let Some(fd) = fd {
        let ev = libc::kevent {
            ident: fd as usize,
            filter: EVFILT_VNODE,
            flags: EV_DELETE,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };

        unsafe {
            kevent(kq_fd, &ev as *const libc::kevent, 1, std::ptr::null_mut(), 0, std::ptr::null());
        }

        watched.remove(&fd);
        debug!(path = %path.display(), "Unwatched file");
    }
}

/// Register a PID for EVFILT_PROC notifications.
fn register_pid(
    kq_fd: RawFd,
    pid: u32,
    tool_name: String,
    watched: &mut HashMap<u32, WatchedProcess>,
) -> Result<(), KqueueError> {
    let ev = libc::kevent {
        ident: pid as usize,
        filter: EVFILT_PROC,
        flags: EV_ADD | EV_ENABLE,
        fflags: NOTE_EXIT | NOTE_FORK | NOTE_EXEC,
        data: 0,
        udata: std::ptr::null_mut(),
    };

    let ret = unsafe {
        kevent(kq_fd, &ev as *const libc::kevent, 1, std::ptr::null_mut(), 0, std::ptr::null())
    };

    if ret < 0 {
        return Err(KqueueError::Kevent(std::io::Error::last_os_error()));
    }

    debug!(pid, tool = %tool_name, "Watching process");
    watched.insert(pid, WatchedProcess { pid, tool_name });

    Ok(())
}

/// Unregister a PID watch.
fn unregister_pid(kq_fd: RawFd, pid: u32, watched: &mut HashMap<u32, WatchedProcess>) {
    if watched.remove(&pid).is_some() {
        let ev = libc::kevent {
            ident: pid as usize,
            filter: EVFILT_PROC,
            flags: EV_DELETE,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };

        unsafe {
            kevent(kq_fd, &ev as *const libc::kevent, 1, std::ptr::null_mut(), 0, std::ptr::null());
        }

        debug!(pid, "Unwatched process");
    }
}

/// Drain all pending events from the kqueue fd without blocking.
fn drain_kqueue_events(kq_fd: RawFd) -> Vec<libc::kevent> {
    let mut buf = [libc::kevent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    }; 16];

    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    let n = unsafe {
        kevent(
            kq_fd,
            std::ptr::null(),
            0,
            buf.as_mut_ptr(),
            buf.len() as i32,
            &timeout,
        )
    };

    if n <= 0 {
        return Vec::new();
    }

    buf[..n as usize].to_vec()
}

/// Translate a raw kqueue event into a SensorEvent.
fn translate_event(
    ev: &libc::kevent,
    files: &HashMap<RawFd, WatchedFile>,
    procs: &HashMap<u32, WatchedProcess>,
) -> Option<SensorEvent> {
    if ev.filter == EVFILT_VNODE {
        let fd = ev.ident as RawFd;
        let watched = files.get(&fd)?;
        Some(SensorEvent::FileChanged {
            path: watched.path.clone(),
            timestamp: Utc::now(),
        })
    } else if ev.filter == EVFILT_PROC {
        let pid = ev.ident as u32;
        let watched = procs.get(&pid)?;
        let kind = if ev.fflags & NOTE_EXIT != 0 {
            ProcessEventKind::Exit
        } else if ev.fflags & NOTE_FORK != 0 {
            ProcessEventKind::Fork
        } else if ev.fflags & NOTE_EXEC != 0 {
            ProcessEventKind::Exec
        } else {
            ProcessEventKind::Signal
        };

        Some(SensorEvent::ProcessEvent {
            pid: watched.pid,
            tool_name: watched.tool_name.clone(),
            kind,
            timestamp: Utc::now(),
        })
    } else {
        None
    }
}
