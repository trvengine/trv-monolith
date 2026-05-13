// TRV™ Cryptographic Engine (TRVEngine™) — created by Ihentuge Uchechukwu, licensed to TRV™ Labs
// Copyright (c) 2026 Ihentuge Uchechukwu. All rights reserved.
// Licensed under the "TRV™ Cryptographic Engine License (TCEL)".
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::convert::TryInto;

pub fn trv_stream_pack(dir_path: &Path) -> io::Result<Vec<u8>> {
    let mut stream = Vec::new();
    fn bundle(current_path: &Path, base_path: &Path, buffer: &mut Vec<u8>) -> io::Result<()> {
        let mut entries: Vec<_> = fs::read_dir(current_path)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|e| e.path());
        for entry in entries {
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
    while cursor < stream.len() {
        if cursor + 16 > stream.len() { break; }
        let fuse: [u8; 16] = stream[cursor..cursor+16].try_into().unwrap();
        cursor += 16;
        let nl = u32::from_le_bytes(fuse[0..4].try_into().unwrap()) as usize;
        let dl = u64::from_le_bytes(fuse[4..12].try_into().unwrap()) as usize;
        if cursor + nl + dl > stream.len() { break; }
        let name = String::from_utf8_lossy(&stream[cursor..cursor+nl]).into_owned();
        cursor += nl;
        let data = &stream[cursor..cursor+dl];
        cursor += dl;
        let out_path = target_dir.join(name);
        if let Some(p) = out_path.parent() { fs::create_dir_all(p)?; }
        fs::File::create(out_path)?.write_all(data)?;
    }
    Ok(())
}
