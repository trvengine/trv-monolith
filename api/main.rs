// TRV™ Cryptographic Engine (TRVEngine™) — created by Ihentuge Uchechukwu, licensed to TRV™ Labs
// Copyright (c) 2026 Ihentuge Uchechukwu. All rights reserved.
// Licensed under the "TRV™ Cryptographic Engine License (TCEL)".

#[path = "../core/engine.rs"] mod engine;
#[path = "../core/crypto.rs"] mod crypto;
#[path = "../core/kdf.rs"] mod kdf;
#[path = "../core/vault.rs"] mod vault;

use std::{env, fs, io::{self, Write, BufRead}, path::Path, convert::TryInto};
use crypto::{trv_hash, trv_ctr_stream};
use kdf::trv_kdf;
use vault::{trv_stream_pack, trv_stream_unpack};
use engine::{MAGIC, MAGIC_VAULT};

// Libc bindings for terminal control (Dependency-Free)
extern "C" {
    fn tcgetattr(fd: i32, termios_p: *mut u8) -> i32;
    fn tcsetattr(fd: i32, optional_actions: i32, termios_p: *const u8) -> i32;
}
const ECHO: u32 = 0x00000008;
const TCSANOW: i32 = 0;

fn get_password(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut termios = [0u8; 128];
    let fd = 0; // stdin
    let mut pass = String::new();
    unsafe {
        tcgetattr(fd, termios.as_mut_ptr());
        let mut silent_termios = termios;
        let lflag_offset = 12; 
        if lflag_offset < silent_termios.len() {
            let mut lflag = u32::from_le_bytes(silent_termios[lflag_offset..lflag_offset+4].try_into().unwrap());
            lflag &= !ECHO;
            silent_termios[lflag_offset..lflag_offset+4].copy_from_slice(&lflag.to_le_bytes());
        }
        tcsetattr(fd, TCSANOW, silent_termios.as_ptr());
        io::stdin().lock().read_line(&mut pass).unwrap();
        tcsetattr(fd, TCSANOW, termios.as_ptr());
    }
    println!();
    pass.trim().to_string()
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("=====================================================");
        println!("  🚀 TRV™ CRYPTOGRAPHIC ENGINE v1.0 [EVALUATION] 🚀");
        println!("=====================================================");
        println!("Usage:");
        println!("  trv hash    <target>");
        println!("  trv encrypt <target> <pass>");
        println!("  trv decrypt <target> <pass>");
        println!("  trv sign    <target> <pass>");
        println!("  trv verify  <target> <sig> <pass>");
        println!("=====================================================");
        return Ok(());
    }

    let command = args[1].to_lowercase();
    
    match command.as_str() {
        "hash" => {
            let target = Path::new(&args[2]);
            if target.exists() && target.is_file() {
                let h = trv_hash(&fs::read(target)?);
                println!("\n[HASH]: {}", h.iter().map(|b| format!("{:02x}", b)).collect::<String>());
            } else {
                let h = trv_hash(args[2].as_bytes());
                println!("\n[STRING HASH]: {}", h.iter().map(|b| format!("{:02x}", b)).collect::<String>());
            }
        },
        "encrypt" => {
            let target = Path::new(&args[2]);
            let password = if args.len() > 3 { args[3].clone() } else { get_password("Enter Password: ") };
            let key = trv_kdf(&password);
            let data = if target.is_dir() { trv_stream_pack(target)? } else { fs::read(target)? };
            let hash = trv_hash(&data);
            let iv = u128::from_be_bytes(hash[..16].try_into().unwrap());
            let processed = trv_ctr_stream(&data, key, iv);
            let out = if target.is_dir() { format!("{}.vault", args[2]) } else { format!("{}.enc", args[2]) };
            let mut f = fs::File::create(&out)?;
            f.write_all(if target.is_dir() { &MAGIC_VAULT } else { &MAGIC })?;
            f.write_all(&hash[..16])?; f.write_all(&processed)?;
            println!("✅ ENCRYPTED: {}", out);
        },
        "sign" => {
            let target_path = Path::new(&args[2]);
            let password = if args.len() > 3 { args[3].clone() } else { get_password("Enter Password: ") };
            let key = trv_kdf(&password);
            let fingerprint = if target_path.is_dir() {
                let mut all_hashes = Vec::new();
                fn walk_sign(dir: &Path, h: &mut Vec<u8>) -> io::Result<()> {
                    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
                    entries.sort_by_key(|e| e.path());
                    for entry in entries {
                        let p = entry.path();
                        if p.is_dir() { walk_sign(&p, h)?; }
                        else { h.extend_from_slice(&trv_hash(&fs::read(p)?)); }
                    }
                    Ok(())
                }
                walk_sign(target_path, &mut all_hashes)?;
                trv_hash(&all_hashes)
            } else {
                trv_hash(&fs::read(target_path)?)
            };
            let mut combined = Vec::new();
            combined.extend_from_slice(&key.to_be_bytes());
            combined.extend_from_slice(&fingerprint);
            let signature = trv_hash(&combined);
            let sig_path = format!("{}.sig", target_path.display());
            fs::write(&sig_path, &signature)?;
            println!("✅ SIGNED: {}", sig_path);
        },
        "verify" => {
            let target_path = Path::new(&args[2]);
            let sig_path = Path::new(&args[3]);
            let password = if args.len() > 4 { args[4].clone() } else { get_password("Enter Password: ") };
            let key = trv_kdf(&password);
            let sig_data = fs::read(sig_path)?;
            let fingerprint = if target_path.is_dir() {
                let mut all_hashes = Vec::new();
                fn walk_verify(dir: &Path, h: &mut Vec<u8>) -> io::Result<()> {
                    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
                    entries.sort_by_key(|e| e.path());
                    for entry in entries {
                        let p = entry.path();
                        if p.is_dir() { walk_verify(&p, h)?; }
                        else { h.extend_from_slice(&trv_hash(&fs::read(p)?)); }
                    }
                    Ok(())
                }
                walk_verify(target_path, &mut all_hashes)?;
                trv_hash(&all_hashes)
            } else {
                trv_hash(&fs::read(target_path)?)
            };
            let mut combined = Vec::new();
            combined.extend_from_slice(&key.to_be_bytes());
            combined.extend_from_slice(&fingerprint);
            let expected_sig = trv_hash(&combined);
            if sig_data == expected_sig { println!("✅ VALID"); } else { println!("❌ INVALID"); }
        },
        "decrypt" => {
            let target = Path::new(&args[2]);
            let password = if args.len() > 3 { args[3].clone() } else { get_password("Enter Password: ") };
            let key = trv_kdf(&password);
            let data = fs::read(target)?;
            if data.len() < 20 { return Ok(()); }
            let iv = u128::from_be_bytes(data[4..20].try_into().unwrap());
            let processed = trv_ctr_stream(&data[20..], key, iv);
            let verify_hash = trv_hash(&processed);
            let verify_iv = u128::from_be_bytes(verify_hash[..16].try_into().unwrap());
            if iv != verify_iv { println!("❌ ERROR: AUTHENTICATION FAILED"); return Ok(()); }
            
            if data[..4] == MAGIC_VAULT {
                trv_stream_unpack(&processed, Path::new("."))?;
            } else {
                let out_name = format!("{}.dec", target.display());
                fs::write(out_name, &processed)?;
            }
            println!("✅ DECRYPTED");
        },
        _ => println!("Unknown command."),
    }
    Ok(())
}
