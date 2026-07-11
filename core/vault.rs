// TRV™ Cryptographic Engine (TRVEngine™) — created by Ihentuge Uchechukwu, licensed to TRV™ Labs
// Copyright (c) 2026 Ihentuge Uchechukwu. All rights reserved.
// Licensed under the "TRV™ Cryptographic Engine License (TCEL)".
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path};
use std::convert::TryInto;

/// Rejects any entry name that is absolute or contains a parent-directory
/// (`..`) component, which would otherwise let a crafted or tampered vault
/// stream write files outside the intended target directory (path
/// traversal / "Zip Slip" class vulnerability - the name is generic to the
/// bug pattern, not specific to the ZIP format).
fn is_safe_relative_path(name: &str) -> bool {
    let path = Path::new(name);
    if path.is_absolute() {
        return false;
    }
    !path.components().any(|c| matches!(c, Component::ParentDir | Component::Prefix(_) | Component::RootDir))
}

pub fn trv_stream_pack(dir_path: &Path) -> io::Result<Vec<u8>> {
    let mut stream = Vec::new();
    fn bundle(current_path: &Path, base_path: &Path, buffer: &mut Vec<u8>) -> io::Result<()> {
        let mut entries: Vec<_> = fs::read_dir(current_path)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|e| e.path());
        for entry in entries {
            if entry.file_type()?.is_symlink() {
                continue; // Prevent symlink-following exfiltration
            }
            let path = entry.path();
            if path.is_dir() { bundle(&path, base_path, buffer)?; }
            else {
                let name = path.strip_prefix(base_path).unwrap().to_string_lossy();
                let name_bytes = name.as_bytes();
                let data = fs::read(&path)?;
                let mut fuse = [0u8; 16];
                fuse[0..4].copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
                fuse[4..12].copy_from_slice(&(data.len() as u64).to_le_bytes());
                fuse[12..16].copy_from_slice(&[0x9E, 0x37, 0x79, 0xB9]);
                buffer.extend_from_slice(&fuse);
                buffer.extend_from_slice(name_bytes);
                buffer.extend_from_slice(&data);
            }
        }
        Ok(())
    }
    bundle(dir_path, dir_path, &mut stream)?;
    Ok(stream)
}

pub fn trv_stream_unpack(stream: &[u8], target_dir: &Path) -> io::Result<()> {
    let mut cursor = 0;
    fs::create_dir_all(target_dir)?;
    let canonical_target = target_dir.canonicalize()?;
    
    while cursor < stream.len() {
        if cursor.checked_add(16).map_or(true, |end| end > stream.len()) {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated fuse"));
        }
        let fuse: [u8; 16] = stream[cursor..cursor+16].try_into().unwrap();
        cursor += 16;
        
        if &fuse[12..16] != [0x9E, 0x37, 0x79, 0xB9] {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "corrupted or missing magic bytes"));
        }
        
        let nl = u32::from_le_bytes(fuse[0..4].try_into().unwrap()) as usize;
        let dl = u64::from_le_bytes(fuse[4..12].try_into().unwrap()) as usize;
        
        let end_cursor = cursor
            .checked_add(nl)
            .and_then(|c| c.checked_add(dl));
            
        if end_cursor.map_or(true, |end| end > stream.len()) {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated entry or integer overflow"));
        }
        
        let name = String::from_utf8_lossy(&stream[cursor..cursor+nl]).into_owned();
        cursor += nl;
        let data = &stream[cursor..cursor+dl];
        cursor += dl;
        
        if !is_safe_relative_path(&name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("refusing to unpack unsafe entry name: {:?}", name),
            ));
        }
        
        let out_path = target_dir.join(name);
        if let Some(p) = out_path.parent() { 
            fs::create_dir_all(p)?; 
            let canonical_parent = p.canonicalize()?;
            if !canonical_parent.starts_with(&canonical_target) {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "symlink escape detected"));
            }
        }
        fs::File::create(out_path)?.write_all(data)?;
    }
    Ok(())
}
