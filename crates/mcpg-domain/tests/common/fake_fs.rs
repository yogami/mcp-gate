//! In-memory filesystem implementation for testing path resolution and policy evaluation.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use mcpg_domain::fs_view::{FsView, Meta};

#[derive(Debug, Clone, PartialEq, Eq)]
enum FakeEntry {
    File(Vec<u8>),
    Dir,
    Symlink(PathBuf),
}

/// An in-memory filesystem that implements `FsView`.
#[derive(Debug, Default, Clone)]
pub struct FakeFs {
    entries: BTreeMap<PathBuf, FakeEntry>,
}

impl FakeFs {
    /// Create a new empty in-memory filesystem.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Add a directory entry at the specified path.
    pub fn add_dir<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        self.entries
            .insert(path.as_ref().to_path_buf(), FakeEntry::Dir);
        self
    }

    /// Add a regular file entry with the given byte contents.
    pub fn add_file<P: AsRef<Path>, B: AsRef<[u8]>>(&mut self, path: P, contents: B) -> &mut Self {
        self.entries.insert(
            path.as_ref().to_path_buf(),
            FakeEntry::File(contents.as_ref().to_vec()),
        );
        self
    }

    /// Add a symbolic link pointing to target.
    pub fn add_symlink<P: AsRef<Path>, T: AsRef<Path>>(&mut self, path: P, target: T) -> &mut Self {
        self.entries.insert(
            path.as_ref().to_path_buf(),
            FakeEntry::Symlink(target.as_ref().to_path_buf()),
        );
        self
    }

    /// Read the bytes of a regular file if it exists.
    pub fn read<P: AsRef<Path>>(&self, path: P) -> io::Result<Vec<u8>> {
        match self.entries.get(path.as_ref()) {
            Some(FakeEntry::File(bytes)) => Ok(bytes.clone()),
            Some(FakeEntry::Dir) | Some(FakeEntry::Symlink(_)) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Is not a regular file",
            )),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No such file or directory",
            )),
        }
    }
}

impl FsView for FakeFs {
    fn lstat(&self, p: &Path) -> io::Result<Meta> {
        match self.entries.get(p) {
            Some(FakeEntry::Dir) => Ok(Meta::dir()),
            Some(FakeEntry::File(bytes)) => Ok(Meta::file(bytes.len() as u64)),
            Some(FakeEntry::Symlink(_)) => Ok(Meta::symlink()),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("No such file or directory: {}", p.display()),
            )),
        }
    }

    fn readlink(&self, p: &Path) -> io::Result<PathBuf> {
        match self.entries.get(p) {
            Some(FakeEntry::Symlink(target)) => Ok(target.clone()),
            Some(FakeEntry::Dir) | Some(FakeEntry::File(_)) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid argument (not a symlink): {}", p.display()),
            )),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("No such file or directory: {}", p.display()),
            )),
        }
    }
}
