// TRV™ Cryptographic Engine (TRVEngine™) — created by Ihentuge Uchechukwu, licensed to TRV™ Labs
// Copyright (c) 2026 Ihentuge Uchechukwu. All rights reserved.
// Licensed under the "TRV™ Cryptographic Engine License (TCEL)".

#[path = "../core/engine.rs"] mod engine;
#[path = "../core/crypto.rs"] mod crypto;
#[path = "../core/kdf.rs"] mod kdf;
#[path = "../core/vault.rs"] mod vault;

use std::{env, fs, io::{self, Write, Read}, path::Path, convert::TryInto, time::Instant};
use crypto::{trv_hash, trv_ctr_stream};
use kdf::{trv_kdf, generate_salt_from_entropy, heap_entropy_source, DEFAULT_MEMHARD_BUF_WORDS};
use vault::{trv_stream_pack, trv_stream_unpack};
use engine::{MAGIC, MAGIC_VAULT};

// Libc bindings for terminal control (Dependency-Free)
extern "C" {
    fn tcgetattr(fd: i32, termios_p: *mut u8) -> i32;
    fn tcsetattr(fd: i32, optional_actions: i32, termios_p: *const u8) -> i32;
}
const ECHO: u64 = 0x00000008;
const ICANON: u64 = 0x00000100;
const TCSANOW: i32 = 0;
const LFLAG_OFFSET: usize = 24;
const CC_OFFSET: usize = 32;
const VMIN: usize = 16;
const VTIME: usize = 17;

fn get_password(prompt: &str) -> (String, Vec<u128>) {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut termios = [0u8; 128];
    let fd = 0; // stdin
    unsafe {
        tcgetattr(fd, termios.as_mut_ptr());
        let mut raw = termios;
        let mut lflag = u64::from_le_bytes(raw[LFLAG_OFFSET..LFLAG_OFFSET + 8].try_into().unwrap());
        lflag &= !ECHO;
        lflag &= !ICANON;
        raw[LFLAG_OFFSET..LFLAG_OFFSET + 8].copy_from_slice(&lflag.to_le_bytes());
        raw[CC_OFFSET + VMIN] = 1;
        raw[CC_OFFSET + VTIME] = 0;
        tcsetattr(fd, TCSANOW, raw.as_ptr());
    }

    let mut password = String::new();
    let mut timestamps = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        let n = io::stdin().lock().read(&mut buf).unwrap();
        if n == 0 { break; }
        let ch = buf[0];
        if ch == b'\n' || ch == b'\r' { break; }
        if ch == 0x7f || ch == 0x08 { // DEL or BS - backspace
            password.pop();
            timestamps.pop();
            continue;
        }
        timestamps.push(Instant::now());
        password.push(ch as char);
    }

    unsafe { tcsetattr(fd, TCSANOW, termios.as_ptr()); }
    println!();

    let mut deltas_ns = Vec::new();
    for w in timestamps.windows(2) {
        deltas_ns.push(w[1].duration_since(w[0]).as_nanos());
    }
    (password, deltas_ns)
}

/// Prompts for a password, then asks again to confirm - used anywhere a
/// NEW password is being set (encrypt/sign), since it's typed invisibly
/// and a typo would otherwise be undetectable until decryption/
/// verification fails later, by which point the original plaintext may
/// already be gone. Not used for decrypt/verify, where a typo just fails
/// the existing authentication check with no data at risk.
fn get_password_confirmed(prompt: &str) -> (String, Vec<u128>) {
    loop {
        let (p1, deltas) = get_password(prompt);
        let (p2, _) = get_password("Confirm Password: ");
        if p1 == p2 {
            return (p1, deltas);
        }
        println!("❌ Passwords did not match, try again.");
    }
}

fn main() -> io::Result<()> {
    let mut args: Vec<String> = env::args().collect();
    let delete_original = if let Some(pos) = args.iter().position(|a| a == "--delete-original") {
        args.remove(pos);
        true
    } else {
        false
    };
    if args.len() < 2 {
        println!("=====================================================");
        println!("  🚀 TRV™ CRYPTOGRAPHIC ENGINE v1.0 [EVALUATION] 🚀");
        println!("=====================================================");
        println!("Usage:");
        println!("  trv hash    <target>");
        println!("  trv encrypt <target> <pass> [--delete-original]");
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
            let (password, deltas) = if args.len() > 3 { (args[3].clone(), Vec::new()) } else { get_password_confirmed("Enter Password: ") };
            let salt = generate_salt_from_entropy(&deltas, heap_entropy_source());
            let key = trv_kdf(&password, salt, DEFAULT_MEMHARD_BUF_WORDS);
            let data = if target.is_dir() { trv_stream_pack(target)? } else { fs::read(target)? };
            let hash = trv_hash(&data);
            let iv = u128::from_be_bytes(hash[..16].try_into().unwrap());
            let processed = trv_ctr_stream(&data, key, iv);
            let out = if target.is_dir() { format!("{}.vault", args[2]) } else { format!("{}.enc", args[2]) };
            let mut f = fs::File::create(&out)?;
            f.write_all(if target.is_dir() { &MAGIC_VAULT } else { &MAGIC })?;
            f.write_all(&salt.to_be_bytes())?;
            f.write_all(&hash[..16])?; f.write_all(&processed)?;
            println!("✅ ENCRYPTED: {}", out);
            if delete_original {
                if target.is_dir() { fs::remove_dir_all(target)?; } else { fs::remove_file(target)?; }
                println!("🗑️  Deleted original: {}", args[2]);
            }
        },
        "sign" => {
            let target_path = Path::new(&args[2]);
            let (password, deltas) = if args.len() > 3 { (args[3].clone(), Vec::new()) } else { get_password_confirmed("Enter Password: ") };
            let salt = generate_salt_from_entropy(&deltas, heap_entropy_source());
            let key = trv_kdf(&password, salt, DEFAULT_MEMHARD_BUF_WORDS);
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
            let mut sig_out = Vec::new();
            sig_out.extend_from_slice(&salt.to_be_bytes());
            sig_out.extend_from_slice(&signature);
            fs::write(&sig_path, &sig_out)?;
            println!("✅ SIGNED: {}", sig_path);
        },
        "verify" => {
            let target_path = Path::new(&args[2]);
            let sig_path = Path::new(&args[3]);
            let (password, _deltas) = if args.len() > 4 { (args[4].clone(), Vec::new()) } else { get_password("Enter Password: ") };
            let sig_data = fs::read(sig_path)?;
            if sig_data.len() < 16 + 32 {
                println!("❌ INVALID (signature file too short)");
                return Ok(());
            }
            let salt = u128::from_be_bytes(sig_data[0..16].try_into().unwrap());
            let stored_signature = &sig_data[16..];
            let key = trv_kdf(&password, salt, DEFAULT_MEMHARD_BUF_WORDS);
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
            if stored_signature == expected_sig { println!("✅ VALID"); } else { println!("❌ INVALID"); }
        },
        "decrypt" => {
            let target = Path::new(&args[2]);
            let (password, _deltas) = if args.len() > 3 { (args[3].clone(), Vec::new()) } else { get_password("Enter Password: ") };
            let data = fs::read(target)?;
            if data.len() < 36 { return Ok(()); } // 4 magic + 16 salt + 16 iv
            let salt = u128::from_be_bytes(data[4..20].try_into().unwrap());
            let key = trv_kdf(&password, salt, DEFAULT_MEMHARD_BUF_WORDS);
            let iv = u128::from_be_bytes(data[20..36].try_into().unwrap());
            let processed = trv_ctr_stream(&data[36..], key, iv);
            let verify_hash = trv_hash(&processed);
            let verify_iv = u128::from_be_bytes(verify_hash[..16].try_into().unwrap());
            if iv != verify_iv { println!("❌ ERROR: AUTHENTICATION FAILED"); return Ok(()); }
            
            if data[..4] == MAGIC_VAULT {
                trv_stream_unpack(&processed, Path::new("."))?;
            } else {
                let base = args[2].strip_suffix(".enc").unwrap_or(&args[2]);
                let out_name = format!("{}.dec", base);
                fs::write(out_name, &processed)?;
            }
            println!("✅ DECRYPTED");
        },
        _ => println!("Unknown command."),
    }
    Ok(())
}
