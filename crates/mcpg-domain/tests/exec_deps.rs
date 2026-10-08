use std::path::{Path, PathBuf};

use mcpg_domain::exec_deps::{exec_closure, parse_elf_pt_interp, parse_shebang, Shebang};
use mcpg_domain::testing::FakeFs;

fn make_synthetic_elf64(interp: Option<&str>) -> Vec<u8> {
    let mut bytes = vec![0u8; 64 + 56];
    bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum

    if let Some(interp_str) = interp {
        let interp_bytes = interp_str.as_bytes();
        let interp_offset = 120u64;
        let interp_len = (interp_bytes.len() + 1) as u64;

        bytes[64..68].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
        bytes[72..80].copy_from_slice(&interp_offset.to_le_bytes());
        bytes[96..104].copy_from_slice(&interp_len.to_le_bytes());

        bytes.extend_from_slice(interp_bytes);
        bytes.push(0);
    } else {
        bytes[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    }

    bytes
}

#[test]
fn pt_interp_from_synthetic_elf64() {
    let elf = make_synthetic_elf64(Some("/lib64/ld-linux-x86-64.so.2"));
    let interp = parse_elf_pt_interp(&elf);
    assert_eq!(interp, Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2")));
}

#[test]
fn static_elf_has_no_interp() {
    let elf = make_synthetic_elf64(None);
    let interp = parse_elf_pt_interp(&elf);
    assert_eq!(interp, None);
}

#[test]
fn shebang_absolute_interpreter() {
    let script = b"#!/bin/bash\necho hello\n";
    let shebang = parse_shebang(script);
    assert_eq!(shebang, Some(Shebang::Direct(PathBuf::from("/bin/bash"))));

    let fs = FakeFs::new();
    let roots = vec![PathBuf::from("/script.sh")];
    let read = |p: &Path| -> std::io::Result<Vec<u8>> {
        if p == Path::new("/script.sh") {
            Ok(script.to_vec())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not found",
            ))
        }
    };
    let closure = exec_closure(&roots, &fs, &read);
    assert!(closure.contains(&PathBuf::from("/script.sh")));
    assert!(closure.contains(&PathBuf::from("/bin/bash")));
}

#[test]
fn shebang_env_form_adds_env_and_resolved_target() {
    let mut fs = FakeFs::new();
    fs.add_file("/usr/bin/env", "env binary");
    fs.add_file("/usr/bin/python3", "python binary");

    let script = b"#!/usr/bin/env python3\nprint('hello')\n";
    let roots = vec![PathBuf::from("/app/main.py")];
    let read = |p: &Path| -> std::io::Result<Vec<u8>> {
        if p == Path::new("/app/main.py") {
            Ok(script.to_vec())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not found",
            ))
        }
    };

    let closure = exec_closure(&roots, &fs, &read);
    assert!(closure.contains(&PathBuf::from("/app/main.py")));
    assert!(closure.contains(&PathBuf::from("/usr/bin/env")));
    assert!(closure.contains(&PathBuf::from("/usr/bin/python3")));
}

#[test]
#[cfg(target_os = "linux")]
fn real_bin_true_needs_ld_linux() {
    let fs = FakeFs::new();
    let bin_true = if Path::new("/usr/bin/true").exists() {
        PathBuf::from("/usr/bin/true")
    } else {
        PathBuf::from("/bin/true")
    };

    let roots = vec![bin_true.clone()];
    let read = |p: &Path| std::fs::read(p);
    let closure = exec_closure(&roots, &fs, &read);

    assert!(closure.contains(&bin_true));
    let has_ld_linux = closure.iter().any(|p| {
        let s = p.to_string_lossy();
        s.contains("ld-linux") || s.contains("ld-musl")
    });
    assert!(
        has_ld_linux,
        "closure must contain dynamic linker, got: {closure:?}"
    );
}
