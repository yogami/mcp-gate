//! Filesystem abstraction port for path resolution and policy evaluation.

use std::io;
use std::path::{Path, PathBuf};

/// The type of filesystem entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    File,
    Dir,
    Symlink,
}

/// Metadata for a filesystem entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub file_type: FileType,
    pub len: u64,
}

impl Meta {
    pub fn file(len: u64) -> Self {
        Self {
            file_type: FileType::File,
            len,
        }
    }

    pub fn dir() -> Self {
        Self {
            file_type: FileType::Dir,
            len: 0,
        }
    }

    pub fn symlink() -> Self {
        Self {
            file_type: FileType::Symlink,
            len: 0,
        }
    }

    pub fn is_dir(&self) -> bool {
        self.file_type == FileType::Dir
    }

    pub fn is_file(&self) -> bool {
        self.file_type == FileType::File
    }

    pub fn is_symlink(&self) -> bool {
        self.file_type == FileType::Symlink
    }
}

/// Port trait providing read-only filesystem observation.
pub trait FsView {
    fn lstat(&self, p: &Path) -> io::Result<Meta>;
    fn readlink(&self, p: &Path) -> io::Result<PathBuf>;
}

/// Standard filesystem implementation backed by std::fs.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdFs;

impl FsView for StdFs {
    fn lstat(&self, p: &Path) -> io::Result<Meta> {
        let meta = std::fs::symlink_metadata(p)?;
        let file_type = if meta.is_symlink() {
            FileType::Symlink
        } else if meta.is_dir() {
            FileType::Dir
        } else {
            FileType::File
        };
        Ok(Meta {
            file_type,
            len: meta.len(),
        })
    }

    fn readlink(&self, p: &Path) -> io::Result<PathBuf> {
        std::fs::read_link(p)
    }
}
