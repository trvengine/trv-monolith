// TRV™ Cryptographic Engine (TRVEngine™) — created by Ihentuge Uchechukwu, licensed to TRV™ Labs
// Copyright (c) 2026 Ihentuge Uchechukwu. All rights reserved.
// Licensed under the "TRV™ Cryptographic Engine License (TCEL)".
use super::engine::{TrvState, GOLDEN};
use std::convert::TryInto;

/// Default memory cost for desktop/server deployments: 655,360 words * 16
/// bytes = 10 MiB, sized to exceed typical shared L3 cache so concurrent
/// brute-force guesses thrash the cache instead of scaling linearly (see
/// examples/kdf_cache_sweep.rs).
pub const DEFAULT_MEMHARD_BUF_WORDS: usize = 655_360;

/// Minimum viable memory cost below which the memory-hard buffer fits
/// inside typical L1/L2 cache and provides little to no real resistance
/// to a cache-resident brute-force attacker. Callers targeting constrained
/// hardware should stay at or above this if the deployment can afford it;
/// below it, `trv_kdf` still works correctly but the memory-hardness
/// property degrades toward a plain iterated hash.
pub const MIN_RECOMMENDED_MEMHARD_BUF_WORDS: usize = 16_384; // 16,384 * 16 bytes = 256 KiB

/// TRV-KDF Configuration (Hardened Key Derivation)
/// Reference: TRV_GATE_SPEC.md Section 3.3
///
/// `mem_words` is the hardware-agnostic memory-cost parameter (in 16-byte
/// words): the size of the scratch buffer the main loop randomly reads
/// from and writes to. Choose it based on the deployment target's
/// available memory and threat model - `DEFAULT_MEMHARD_BUF_WORDS` (10
/// MiB) for desktop/server, something smaller (see
/// `MIN_RECOMMENDED_MEMHARD_BUF_WORDS`) for constrained/embedded targets.
/// This mirrors how Argon2 exposes its own memory-cost parameter rather
/// than hard-coding one value for every deployment.
pub fn trv_kdf(password: &str, salt: u128, mem_words: usize) -> u128 {
    let mem_words = mem_words.max(1);
    let mut state = TrvState::new();
    let mut seedling: u128 = GOLDEN ^ (password.len() as u128).rotate_left(64);

    for &b in password.as_bytes() {
        state.lo ^= b as u128; state.trv_lock_step(seedling);
        seedling = seedling.wrapping_add(state.hi ^ state.lo);
    }

    state.hi ^= salt;
    state.trv_lock_step(seedling ^ salt);
    seedling = seedling.wrapping_add(state.hi ^ state.lo);

    let mut buf = vec![0u128; mem_words];
    let mut filler = seedling ^ state.hi ^ state.lo;
    for slot in buf.iter_mut() {
        filler = filler.wrapping_add(GOLDEN);
        state.trv_lock_step(filler);
        filler = filler.wrapping_add(state.hi ^ state.lo);
        *slot = state.hi ^ state.lo;
    }

    for i in 0..100_000u128 {
        let idx = ((seedling ^ state.hi ^ state.lo) as usize) % mem_words;
        let mem_val = buf[idx];
        state.trv_lock_step(seedling ^ i ^ mem_val);
        buf[idx] = state.hi ^ state.lo;
        if i % 64 == 0 {
            seedling = seedling.wrapping_add(state.hi ^ state.lo);
            state.hi = state.hi.rotate_left(13) ^ GOLDEN;
        }
    }
    u128::from_be_bytes(state.to_bytes()[..16].try_into().unwrap())
}

/// Salt from two non-OS-RNG entropy sources: inter-keystroke timing during
/// password entry, and a heap-allocation address (OS ASLR). Whitened
/// through trv_lock_step, same as password absorption above.
pub fn generate_salt_from_entropy(deltas_ns: &[u128], heap_addr: u64) -> u128 {
    let mut state = TrvState::new();
    let mut seedling: u128 = GOLDEN ^ (deltas_ns.len() as u128).rotate_left(64);
    for &d in deltas_ns {
        state.lo ^= d;
        state.trv_lock_step(seedling);
        seedling = seedling.wrapping_add(state.hi ^ state.lo);
    }
    state.hi ^= heap_addr as u128;
    state.trv_lock_step(seedling ^ (heap_addr as u128));
    seedling = seedling.wrapping_add(state.hi ^ state.lo);
    for i in 0..1000u128 {
        state.trv_lock_step(seedling ^ i);
        seedling = seedling.wrapping_add(state.hi ^ state.lo);
    }
    state.hi ^ state.lo
}

pub fn heap_entropy_source() -> u64 {
    let b = Box::new(0u8);
    &*b as *const u8 as usize as u64
}
