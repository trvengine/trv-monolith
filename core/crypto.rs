// TRV™ Cryptographic Engine (TRVEngine™) — created by Ihentuge Uchechukwu, licensed to TRV™ Labs
// Copyright (c) 2026 Ihentuge Uchechukwu. All rights reserved.
// Licensed under the "TRV™ Cryptographic Engine License (TCEL)".
use super::engine::{TrvState, trv_gate, GOLDEN};

pub fn trv_get_schedule(master: u128, count: usize) -> Vec<u128> {
    let mut sched = Vec::with_capacity(count);
    let mut current = master;
    for i in 0..count {
        sched.push(current);
        let (n_c, _, _) = trv_gate(current, i as u128, GOLDEN);
        current = n_c;
    }
    sched
}

/// TRV-Hash Configuration
/// Hardened for Length-Sensitivity and Collision Resistance
/// Reference: TRV_GATE_SPEC.md Section 3.2
pub fn trv_hash(data: &[u8]) -> [u8; 32] {
    let mut state = TrvState::new();
    let mut seedling: u128 = GOLDEN;
    let bit_len = (data.len() as u64) * 8;
    
    // Byte-Wise Continuous Absorption
    for &b in data {
        state.lo ^= b as u128;
        state.trv_lock_step(seedling);
        seedling = seedling.wrapping_add(state.hi ^ state.lo);
    }
    
    // Hardened Padding (Sentinel)
    state.lo ^= 0x80u128;
    state.hi ^= bit_len as u128;
    
    // Final block saturation
    for _ in 0..16 { state.trv_lock_step(seedling); }
    seedling = seedling.wrapping_add(state.hi ^ state.lo);

    // Final Expansion Schedule (Saturation Phase)
    let sched = trv_get_schedule(seedling, 128);
    for &k in &sched { state.trv_lock_step(k); }
    state.to_bytes()
}

/// TRV-Stream Configuration (CTR Mode)
pub fn trv_ctr_stream(data: &[u8], key: u128, iv: u128) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    
    // Continuous CTR Stream
    for i in 0..data.len() {
        // We generate a fresh state for every 16 bytes (block boundary)
        if i % 16 == 0 {
            let block_idx = i / 16;
            // High-Entropy Seedling Construction (Key-Counter Fusion)
            let seedling = key ^ (block_idx as u128);
            let mut state = TrvState::with_values(iv, key);
            
            // 128-Round Ultra-Saturation for Stream Opacity
            for _ in 0..128 { state.trv_lock_step(seedling); }
            let ks = state.to_bytes();
            
            // Apply keystream to the next 16 bytes (or remainder)
            for j in 0..16 {
                if i + j < data.len() {
                    out[i + j] = data[i + j] ^ ks[j];
                }
            }
        }
    }
    out
}
