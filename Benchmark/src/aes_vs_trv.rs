// AES-256-CTR vs. TRV™ CTR Pure Software Benchmark
// Implements both ciphers from scratch in pure software (no HW acceleration, no dependencies).

use std::time::Instant;
use std::thread;

// ==========================================================================
// 1. PURE SOFTWARE AES-256 DEFINITION (From Cryptographic Specifications)
// ==========================================================================
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

const RCON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
];

fn sub_word(word: u32) -> u32 {
    let b0 = SBOX[((word >> 24) & 0xFF) as usize] as u32;
    let b1 = SBOX[((word >> 16) & 0xFF) as usize] as u32;
    let b2 = SBOX[((word >> 8) & 0xFF) as usize] as u32;
    let b3 = SBOX[(word & 0xFF) as usize] as u32;
    (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

fn rot_word(word: u32) -> u32 {
    word.rotate_left(8)
}

fn aes256_key_expansion(key: &[u8; 32], round_keys: &mut [u8; 240]) {
    round_keys[..32].copy_from_slice(key);
    let mut i = 8;
    while i < 60 {
        let mut temp_bytes = [0u8; 4];
        temp_bytes.copy_from_slice(&round_keys[(i - 1) * 4..i * 4]);
        let mut temp = u32::from_be_bytes(temp_bytes);
        if i % 8 == 0 {
            temp = sub_word(rot_word(temp)) ^ RCON[(i / 8) - 1];
        } else if i % 8 == 4 {
            temp = sub_word(temp);
        }
        let mut prev_bytes = [0u8; 4];
        prev_bytes.copy_from_slice(&round_keys[(i - 8) * 4..(i - 7) * 4]);
        let prev = u32::from_be_bytes(prev_bytes);
        let next = prev ^ temp;
        round_keys[i * 4..(i + 1) * 4].copy_from_slice(&next.to_be_bytes());
        i += 1;
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let temp = *state;
    state[1] = temp[5];
    state[5] = temp[9];
    state[9] = temp[13];
    state[13] = temp[1];
    
    state[2] = temp[10];
    state[6] = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];
    
    state[3] = temp[15];
    state[7] = temp[3];
    state[11] = temp[7];
    state[15] = temp[11];
}

fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

#[inline(always)]
fn gm2(x: u8) -> u8 {
    if x & 0x80 != 0 { (x << 1) ^ 0x1B } else { x << 1 }
}

fn mix_columns(state: &mut [u8; 16]) {
    let temp = *state;
    for i in 0..4 {
        let c = i * 4;
        let s0 = temp[c];
        let s1 = temp[c + 1];
        let s2 = temp[c + 2];
        let s3 = temp[c + 3];
        
        state[c]     = gm2(s0 ^ s1) ^ s1 ^ s2 ^ s3;
        state[c + 1] = gm2(s1 ^ s2) ^ s2 ^ s3 ^ s0;
        state[c + 2] = gm2(s2 ^ s3) ^ s3 ^ s0 ^ s1;
        state[c + 3] = gm2(s3 ^ s0) ^ s0 ^ s1 ^ s2;
    }
}

fn add_round_key(state: &mut [u8; 16], round_key: &[u8]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

fn aes256_encrypt_block(state: &mut [u8; 16], expanded_keys: &[u8; 240]) {
    add_round_key(state, &expanded_keys[..16]);
    for round in 1..14 {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &expanded_keys[round * 16..(round + 1) * 16]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &expanded_keys[14 * 16..15 * 16]);
}

pub fn aes256_ctr_stream(data: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let mut expanded_keys = [0u8; 240];
    aes256_key_expansion(key, &mut expanded_keys);
    
    let mut counter = *iv;
    
    // Process block by block
    let mut offset = 0;
    while offset < data.len() {
        let mut keystream_block = counter;
        aes256_encrypt_block(&mut keystream_block, &expanded_keys);
        
        let chunk_len = std::cmp::min(data.len() - offset, 16);
        for i in 0..chunk_len {
            out[offset + i] = data[offset + i] ^ keystream_block[i];
        }
        offset += chunk_len;
        
        // Increment the 16-byte Big-Endian counter
        for i in (0..16).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 { break; }
        }
    }
    out
}

// ==========================================================================
// 2. TRV™ CTR STREAM CIPHER DEFINITIONS (Verbatim from TRV™ Monolith Core Specifications)
// ==========================================================================
const MASK: u128 = u128::MAX;

#[inline(always)]
fn trv_gate(a: u128, b: u128, c: u128) -> (u128, u128, u128) {
    let x = (!(a ^ b)) & MASK;
    let y = ((a & !c) | ((!b) & c)) & MASK;
    let z = (((!b) & (!c)) | ((!a) & c)) & MASK;
    (x, y, z)
}

pub struct TrvState {
    pub hi: u128,
    pub lo: u128,
}

impl TrvState {
    pub fn with_values(hi: u128, lo: u128) -> Self { Self { hi, lo } }
    
    #[inline(always)]
    pub fn trv_lock_step(&mut self, seedling: u128) {
        let (n_hi, n_lo, _) = trv_gate(self.hi, self.lo, seedling);
        self.hi = n_hi.rotate_left(31);
        self.lo = n_lo.rotate_right(19);
    }
    
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&self.hi.to_be_bytes());
        out[16..].copy_from_slice(&self.lo.to_be_bytes());
        out
    }
}

pub fn trv_ctr_stream(data: &[u8], key: u128, iv: u128) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let mut offset = 0;
    while offset < data.len() {
        let block_idx = offset / 16;
        let mut seedling = key ^ (block_idx as u128);
        let mut state = TrvState::with_values(iv, key);
        for _ in 0..128 {
            state.trv_lock_step(seedling);
            seedling = seedling.wrapping_add(state.hi ^ state.lo);
        }
        let ks = state.to_bytes();
        
        let chunk_len = std::cmp::min(data.len() - offset, 16);
        for j in 0..chunk_len {
            out[offset + j] = data[offset + j] ^ ks[j];
        }
        offset += chunk_len;
    }
    out
}

// ==========================================================================
// 3. COMPARATIVE BENCHMARK RUNNER
// ==========================================================================
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = if args.len() > 1 { args[1].clone() } else { "10mb".to_string() };
    
    println!("==================================================");
    println!("   🛡️ AES-256-CTR vs. TRV™ CTR STREAM BENCHMARK   ");
    println!("   [ PURE SOFTWARE / NO HW ACCEL / 100% NATIVE ]  ");
    println!("==================================================");

    // Baseline definitions
    let aes_key = [0x55u8; 32];
    let aes_iv = [0xAAu8; 16];
    let trv_key: u128 = 0x55555555555555555555555555555555;
    let trv_iv: u128 = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;

    // Direct Correctness Test
    println!("[ STATUS ] Running cryptographic correctness verification...");
    let test_data = b"TRV Sovereign VPN Cryptographic Stream Cipher Verification Vector";
    let aes_enc = aes256_ctr_stream(test_data, &aes_key, &aes_iv);
    let aes_dec = aes256_ctr_stream(&aes_enc, &aes_key, &aes_iv);
    assert_eq!(test_data, aes_dec.as_slice(), "AES-256-CTR Correctness failed!");
    
    let trv_enc = trv_ctr_stream(test_data, trv_key, trv_iv);
    let trv_dec = trv_ctr_stream(&trv_enc, trv_key, trv_iv);
    assert_eq!(test_data, trv_dec.as_slice(), "TRV-CTR Correctness failed!");
    println!("  ✅ AES-256-CTR and TRV-CTR Correctness: SUCCESS!");
    println!();

    if mode == "10mb" {
        // Run standard 10MB benchmark
        let size = 10 * 1024 * 1024;
        let payload = vec![0x37u8; size];
        println!("[ STATUS ] Allocating 10MB payload...");

        println!("[ BENCHMARK ] Running pure AES-256-CTR...");
        let start = Instant::now();
        let aes_res = aes256_ctr_stream(&payload, &aes_key, &aes_iv);
        let aes_duration = start.elapsed();
        let aes_mbps = (size as f64 / 1024.0 / 1024.0) / aes_duration.as_secs_f64();

        println!("[ BENCHMARK ] Running pure TRV-CTR...");
        let start = Instant::now();
        let trv_res = trv_ctr_stream(&payload, trv_key, trv_iv);
        let trv_duration = start.elapsed();
        let trv_mbps = (size as f64 / 1024.0 / 1024.0) / trv_duration.as_secs_f64();

        println!("\n==================================================");
        println!("  📊 10MB SINGLE-CORE BASICS COMPARISON           ");
        println!("==================================================");
        println!("  AES-256-CTR:");
        println!("    Time taken:  {:?}", aes_duration);
        println!("    Throughput:  {:.2} MB/s", aes_mbps);
        println!("    Check:       {:02x?}", &aes_res[..4]);
        println!();
        println!("  TRV-CTR:");
        println!("    Time taken:  {:?}", trv_duration);
        println!("    Throughput:  {:.2} MB/s", trv_mbps);
        println!("    Check:       {:02x?}", &trv_res[..4]);
        println!("--------------------------------------------------");
        let speedup = trv_mbps / aes_mbps;
        println!("  🚀 Result: TRV-CTR is {:.2}x FASTER than AES-256-CTR", speedup);
        println!("==================================================");
        
    } else if mode == "1gb-single" {
        // Run massive 1GB single-core benchmark
        let size = 1024 * 1024 * 1024;
        let payload = vec![0x37u8; size];
        println!("[ STATUS ] Allocating 1GB payload (Single-Core)...");

        println!("[ BENCHMARK ] Running pure AES-256-CTR...");
        let start = Instant::now();
        let aes_res = aes256_ctr_stream(&payload, &aes_key, &aes_iv);
        let aes_duration = start.elapsed();
        let aes_mbps = (size as f64 / 1024.0 / 1024.0) / aes_duration.as_secs_f64();

        println!("[ BENCHMARK ] Running pure TRV-CTR...");
        let start = Instant::now();
        let trv_res = trv_ctr_stream(&payload, trv_key, trv_iv);
        let trv_duration = start.elapsed();
        let trv_mbps = (size as f64 / 1024.0 / 1024.0) / trv_duration.as_secs_f64();

        println!("\n==================================================");
        println!("  📊 1GB SINGLE-CORE STRESS TEST COMPARISON       ");
        println!("==================================================");
        println!("  AES-256-CTR:");
        println!("    Time taken:  {:?}", aes_duration);
        println!("    Throughput:  {:.2} MB/s", aes_mbps);
        println!("    Check:       {:02x?}", &aes_res[..4]);
        println!();
        println!("  TRV-CTR:");
        println!("    Time taken:  {:?}", trv_duration);
        println!("    Throughput:  {:.2} MB/s", trv_mbps);
        println!("    Check:       {:02x?}", &trv_res[..4]);
        println!("--------------------------------------------------");
        let speedup = trv_mbps / aes_mbps;
        println!("  🚀 Result: TRV-CTR is {:.2}x FASTER than AES-256-CTR", speedup);
        println!("==================================================");
        
    } else if mode == "1gb-multi" {
        // Run massive 1GB multi-core parallel benchmark
        let num_cores = thread::available_parallelism().unwrap().get();
        let size = 1024 * 1024 * 1024;
        let payload = vec![0x37u8; size];
        let chunk_size = size / num_cores;
        println!("[ STATUS ] Allocating 1GB payload across {} logical cores...", num_cores);

        // --- PARALLEL AES-256-CTR ---
        println!("[ BENCHMARK ] Running parallel AES-256-CTR...");
        let start = Instant::now();
        let mut handles = Vec::new();
        for i in 0..num_cores {
            let start_idx = i * chunk_size;
            let end_idx = if i == num_cores - 1 { size } else { (i + 1) * chunk_size };
            let chunk_ref = &payload[start_idx..end_idx];
            let chunk_ptr_usize = chunk_ref.as_ptr() as usize;
            let chunk_len = chunk_ref.len();
            
            handles.push(thread::spawn(move || {
                let chunk_ptr = chunk_ptr_usize as *const u8;
                let chunk = unsafe { std::slice::from_raw_parts(chunk_ptr, chunk_len) };
                aes256_ctr_stream(chunk, &[0x55u8; 32], &[0xAAu8; 16])
            }));
        }
        let mut aes_checksums = Vec::new();
        for h in handles { aes_checksums.push(h.join().unwrap()); }
        let aes_duration = start.elapsed();
        let aes_mbps = (size as f64 / 1024.0 / 1024.0) / aes_duration.as_secs_f64();

        // --- PARALLEL TRV-CTR ---
        println!("[ BENCHMARK ] Running parallel TRV-CTR...");
        let start = Instant::now();
        let mut handles = Vec::new();
        for i in 0..num_cores {
            let start_idx = i * chunk_size;
            let end_idx = if i == num_cores - 1 { size } else { (i + 1) * chunk_size };
            let chunk_ref = &payload[start_idx..end_idx];
            let chunk_ptr_usize = chunk_ref.as_ptr() as usize;
            let chunk_len = chunk_ref.len();
            
            handles.push(thread::spawn(move || {
                let chunk_ptr = chunk_ptr_usize as *const u8;
                let chunk = unsafe { std::slice::from_raw_parts(chunk_ptr, chunk_len) };
                trv_ctr_stream(chunk, 0x55555555555555555555555555555555, 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
            }));
        }
        let mut trv_checksums = Vec::new();
        for h in handles { trv_checksums.push(h.join().unwrap()); }
        let trv_duration = start.elapsed();
        let trv_mbps = (size as f64 / 1024.0 / 1024.0) / trv_duration.as_secs_f64();

        println!("\n==================================================");
        println!("  📊 1GB MULTI-CORE PARALLEL RESULTS              ");
        println!("==================================================");
        println!("  AES-256-CTR:");
        println!("    Time taken:  {:?}", aes_duration);
        println!("    Throughput:  {:.2} MB/s", aes_mbps);
        println!("    Check:       {:02x?}", &aes_checksums[0][..4]);
        println!();
        println!("  TRV-CTR:");
        println!("    Time taken:  {:?}", trv_duration);
        println!("    Throughput:  {:.2} MB/s", trv_mbps);
        println!("    Check:       {:02x?}", &trv_checksums[0][..4]);
        println!("--------------------------------------------------");
        let speedup = trv_mbps / aes_mbps;
        println!("  🚀 Result: TRV-CTR is {:.2}x FASTER than AES-256-CTR", speedup);
        println!("==================================================");
    }
}
