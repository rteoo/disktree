//! `disktree-core`: scanning, layout, space accounting and deletion, with no
//! UI dependency.
//!
//! The split exists so the parts that must be *correct* — size accounting,
//! hardlink de-duplication, aspect-ratio layout, and what may be deleted — can
//! be built and tested without GPUI, a display, or a GPU.

pub mod classify;
pub mod filter;
pub mod insights;
pub mod removal;
pub mod scan;
pub mod size;
pub mod space;
pub mod tree;
pub mod treemap;

/// The current user's home directory from this platform's standard variable.
pub fn home_dir() -> Option<std::path::PathBuf> {
    let variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(variable).map(std::path::PathBuf::from)
}
