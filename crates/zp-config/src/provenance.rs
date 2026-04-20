//! Provenance tracking — every config value knows where it came from.

use serde::Serialize;
use std::fmt;

/// Where a configuration value originated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Source {
    /// Hardcoded default in the binary.
    Default,
    /// Read from `~/ZeroPoint/config.toml`.
    SystemConfig,
    /// Read from `./zeropoint.toml` (project-local).
    ProjectConfig,
    /// Read from a `ZP_*` environment variable.
    EnvVar(String),
    /// Set via CLI flag.
    CliFlag(String),
    /// Set during genesis ceremony.
    Genesis,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::Default => write!(f, "default"),
            Source::SystemConfig => write!(f, "~/ZeroPoint/config.toml"),
            Source::ProjectConfig => write!(f, "./zeropoint.toml"),
            Source::EnvVar(var) => write!(f, "{var} env var"),
            Source::CliFlag(flag) => write!(f, "--{flag} flag"),
            Source::Genesis => write!(f, "genesis ceremony"),
        }
    }
}

impl Source {
    /// Priority for resolution. Higher wins.
    pub fn priority(&self) -> u8 {
        match self {
            Source::Default => 0,
            Source::SystemConfig => 1,
            Source::ProjectConfig => 2,
            Source::Genesis => 2, // Same level as project config
            Source::EnvVar(_) => 3,
            Source::CliFlag(_) => 4,
        }
    }
}

/// A value paired with its provenance.
#[derive(Debug, Clone, Serialize)]
pub struct Sourced<T: fmt::Debug + Clone> {
    pub value: T,
    pub source: Source,
}

impl<T: fmt::Debug + Clone> Sourced<T> {
    pub fn new(value: T, source: Source) -> Self {
        Self { value, source }
    }

    pub fn default_value(value: T) -> Self {
        Self {
            value,
            source: Source::Default,
        }
    }

    /// Replace value only if the new source has higher or equal priority.
    pub fn override_with(&mut self, value: T, source: Source) {
        if source.priority() >= self.source.priority() {
            self.value = value;
            self.source = source;
        }
    }
}

impl<T: fmt::Debug + Clone + fmt::Display> fmt::Display for Sourced<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (from {})", self.value, self.source)
    }
}
