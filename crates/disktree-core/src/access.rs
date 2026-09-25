//! What the operating system keeps private from a scan.
//!
//! On macOS a process without Full Disk Access is refused parts of the home
//! directory — Mail, Messages, Safari, other apps' containers, the Trash —
//! with `EPERM`, silently. A disk tool that only counts those as errors
//! leaves the user guessing, so the app asks once whether access is granted
//! and, if not, says why folders were unreadable and where to fix it.

use std::path::Path;

/// System Settings, opened at Privacy & Security › Full Disk Access.
pub const FULL_DISK_ACCESS_SETTINGS: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles";

/// Whether this process has Full Disk Access: `Some(false)` when it is
/// refused, `None` where the question does not apply or cannot be answered.
///
/// The privacy database itself is protected by Full Disk Access, so opening
/// it for reading is the test. It never shows a prompt, unlike touching
/// Desktop or Documents would.
pub fn full_disk_access(home: &Path) -> Option<bool> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let database =
        home.join("Library/Application Support/com.apple.TCC/TCC.db");
    match std::fs::File::open(database) {
        Ok(_) => Some(true),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Some(false)
        }
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_macos_has_an_answer_and_a_missing_database_is_not_a_refusal() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        assert_eq!(full_disk_access(temp.path()), None);
        if !cfg!(target_os = "macos") {
            let home = std::env::home_dir().expect("a home directory");
            assert_eq!(full_disk_access(&home), None);
        }
    }
}
