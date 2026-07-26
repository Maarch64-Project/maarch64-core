//! Virtual File System (VFS) & Mock Environment Manager
//!
//! Provides a single source of truth for mock system files (such as `/etc/passwd`)
//! and host environment mapping shared across Syscalls and Thunks.

use std::path::PathBuf;

pub struct Vfs;

impl Vfs {
    /// Check whether a given path string refers to `/etc/passwd`.
    pub fn is_passwd_path(path: &str) -> bool {
        path == "/etc/passwd" || path.ends_with("etc/passwd")
    }

    /// Dynamically generate `/etc/passwd` content matching host user identity.
    pub fn get_passwd_content() -> Vec<u8> {
        let host_user = std::env::var("USER").unwrap_or_else(|_| "user".to_string());
        let host_uid = unsafe { libc::getuid() };
        let host_gid = unsafe { libc::getgid() };
        format!(
            "root:x:0:0:root:/root:/bin/sh\n{}:x:{}:{}:{}:/home/{}:/bin/sh\n",
            host_user, host_uid, host_gid, host_user, host_user
        )
        .into_bytes()
    }

    /// Prepare a temporary file containing mock `/etc/passwd` content and return its path.
    pub fn prepare_mock_passwd_file() -> PathBuf {
        let tmp_path = std::env::temp_dir().join("maarch64_passwd");
        let content = Self::get_passwd_content();
        let _ = std::fs::write(&tmp_path, content);
        tmp_path
    }
}
