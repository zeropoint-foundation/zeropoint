use std::collections::HashMap;

fn main() {
    let euid = unsafe { libc::geteuid() };
    println!("=== listeners crate visibility test ===");
    println!("user: {}", std::env::var("USER").unwrap_or_else(|_| "unknown".into()));
    println!("euid: {} ({})\n", euid, if euid == 0 { "root" } else { "unprivileged" });

    match listeners::get_all() {
        Ok(entries) => {
            // Count unique PIDs and group by process
            let mut by_process: HashMap<(u32, String), Vec<String>> = HashMap::new();
            for entry in &entries {
                by_process
                    .entry((entry.process.pid, entry.process.name.clone()))
                    .or_default()
                    .push(format!("{} {:?} {:?}", entry.socket, entry.protocol, entry.state));
            }

            println!("Total entries: {}", entries.len());
            println!("Unique processes: {}\n", by_process.len());

            let mut sorted: Vec<_> = by_process.into_iter().collect();
            sorted.sort_by_key(|((pid, _), _)| *pid);

            for ((pid, name), sockets) in &sorted {
                println!("PID {pid:>6}  {name}");
                for s in sockets {
                    println!("          {s}");
                }
            }
        }
        Err(e) => {
            eprintln!("listeners::get_all() failed: {e}");
            std::process::exit(1);
        }
    }
}
