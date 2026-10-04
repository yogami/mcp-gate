//! Executable dependency and interpreter discovery for Landlock rule planning.
//!
//! SPEC 3.1.5: Discovers the ELF dynamic interpreter (PT_INTERP) and shebang
//! script interpreters so Landlock can grant execute rights to necessary runtimes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::fs_view::FsView;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const PT_INTERP: u32 = 3;

fn is_elf64_le(bytes: &[u8]) -> bool {
    if bytes.len() < 64 {
        return false;
    }
    bytes[0..4] == ELF_MAGIC && bytes[4] == ELFCLASS64 && bytes[5] == ELFDATA2LSB
}

fn read_ph_table_info(bytes: &[u8]) -> Option<(usize, usize, usize)> {
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().ok()?) as usize;
    let phentsize = u16::from_le_bytes(bytes[54..56].try_into().ok()?) as usize;
    let phnum = u16::from_le_bytes(bytes[56..58].try_into().ok()?) as usize;
    if phentsize < 56 {
        None
    } else {
        Some((phoff, phentsize, phnum))
    }
}

fn interp_from_phdr(bytes: &[u8], phdr: &[u8]) -> Option<PathBuf> {
    let p_type = u32::from_le_bytes(phdr[0..4].try_into().ok()?);
    if p_type != PT_INTERP {
        return None;
    }
    let p_offset = u64::from_le_bytes(phdr[8..16].try_into().ok()?) as usize;
    let p_filesz = u64::from_le_bytes(phdr[32..40].try_into().ok()?) as usize;
    let interp_end = p_offset.checked_add(p_filesz)?;
    if interp_end > bytes.len() {
        return None;
    }
    let interp_bytes = &bytes[p_offset..interp_end];
    let cstr = std::ffi::CStr::from_bytes_until_nul(interp_bytes).ok()?;
    let s = cstr.to_str().ok()?;
    Some(PathBuf::from(s))
}

/// Extract the PT_INTERP path from an ELF64 little-endian binary.
pub fn parse_elf_pt_interp(bytes: &[u8]) -> Option<PathBuf> {
    if !is_elf64_le(bytes) {
        return None;
    }
    let (phoff, phentsize, phnum) = read_ph_table_info(bytes)?;
    for i in 0..phnum {
        let start = phoff.checked_add(i.checked_mul(phentsize)?)?;
        let end = start.checked_add(phentsize)?;
        if end > bytes.len() {
            return None;
        }
        if let Some(interp) = interp_from_phdr(bytes, &bytes[start..end]) {
            return Some(interp);
        }
    }
    None
}

/// Discovered shebang script target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shebang {
    Direct(PathBuf),
    Env { env_path: PathBuf, target: String },
}

fn find_env_target<'a, I>(mut parts: I) -> Option<String>
where
    I: Iterator<Item = &'a str>,
{
    parts.find(|part| !part.starts_with('-')).map(String::from)
}

fn parse_env_shebang(interp: &str, parts: std::str::SplitWhitespace<'_>) -> Shebang {
    if let Some(target) = find_env_target(parts) {
        Shebang::Env {
            env_path: PathBuf::from(interp),
            target,
        }
    } else {
        Shebang::Direct(PathBuf::from(interp))
    }
}

/// Parse a shebang line from script bytes.
pub fn parse_shebang(bytes: &[u8]) -> Option<Shebang> {
    if bytes.len() < 2 || bytes[0] != b'#' || bytes[1] != b'!' {
        return None;
    }
    let line_end = bytes
        .iter()
        .position(|&b| b == b'\n' || b == b'\r')
        .unwrap_or(bytes.len());
    let line = std::str::from_utf8(&bytes[2..line_end]).ok()?;
    let mut parts = line.split_whitespace();
    let interp = parts.next()?;
    if interp.ends_with("/env") || interp == "env" {
        Some(parse_env_shebang(interp, parts))
    } else {
        Some(Shebang::Direct(PathBuf::from(interp)))
    }
}

fn discover_shebang_deps(shebang: Shebang, fs: &dyn FsView, worklist: &mut Vec<PathBuf>) {
    match shebang {
        Shebang::Direct(path) => {
            worklist.push(path);
        }
        Shebang::Env { env_path, target } => {
            worklist.push(env_path);
            let default_path = "/usr/local/bin:/usr/bin:/bin";
            if let Ok(resolved) = crate::policy::resolve::resolve_binary(&target, default_path, fs)
            {
                worklist.push(resolved);
            }
        }
    }
}

fn process_exec_file(
    path: &Path,
    fs: &dyn FsView,
    read: &dyn Fn(&Path) -> std::io::Result<Vec<u8>>,
    worklist: &mut Vec<PathBuf>,
) {
    let bytes = match read(path) {
        Ok(b) => b,
        Err(_) => return,
    };
    if let Some(interp) = parse_elf_pt_interp(&bytes) {
        worklist.push(interp);
    } else if let Some(shebang) = parse_shebang(&bytes) {
        discover_shebang_deps(shebang, fs, worklist);
    }
}

/// Compute the transitive execution closure for a set of root binaries.
pub fn exec_closure(
    roots: &[PathBuf],
    fs: &dyn FsView,
    read: &dyn Fn(&Path) -> std::io::Result<Vec<u8>>,
) -> Vec<PathBuf> {
    let mut visited = BTreeSet::new();
    let mut worklist: Vec<PathBuf> = roots.to_vec();

    while let Some(path) = worklist.pop() {
        if visited.insert(path.clone()) {
            process_exec_file(&path, fs, read, &mut worklist);
        }
    }

    visited.into_iter().collect()
}
