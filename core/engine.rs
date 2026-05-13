// TRV™ Cryptographic Engine (TRVEngine™) — created by Ihentuge Uchechukwu, licensed to TRV™ Labs
// Copyright (c) 2026 Ihentuge Uchechukwu. All rights reserved.
// Licensed under the "TRV™ Cryptographic Engine License (TCEL)".
// See TRV_ENGINE_LICENSE.md for details.

pub const MASK: u128 = u128::MAX;
pub const GOLDEN: u128 = 0x9E3779B97F4A7C15;
pub const MAGIC: [u8; 4] = [b'T', b'R', b'V', 0x01];
pub const MAGIC_VAULT: [u8; 4] = [b'T', b'R', b'V', 0x02];

/// TRV™ Unified Primitive: Boolean Transformation Gate System (BTGS)
/// 
/// Defined by Ihentuge Uchechukwu. This function implements the core non-linear 
/// Boolean state transformation manifold that drives the entire TRV™ ecosystem.
/// 
/// Logic Relations:
/// Math: x = ¬(a ⊕ b), y = (a ∧ ¬c) ∨ (¬b ∧ c), z = (¬b ∧ ¬c) ∨ (¬a ∧ c)
/// Code: x = ~(a ^ b), y = (a & ~c) | (~b & c), z = (~b & ~c) | (~a & c)
///
/// Protected under the TRV™ Cryptographic Engine License (TCEL) 
/// and the Boolean Transformation Gate System (BTGS) License.
#[inline(always)]
pub fn trv_gate(a: u128, b: u128, c: u128) -> (u128, u128, u128) {
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
    pub fn new() -> Self {
        Self {
            hi: 0x6a09e667bb67ae853c6ef372a54ff53a,
            lo: 0x510e527f9b05688c1f83d9ab5be0cd19,
        }
    }
    
    pub fn with_values(hi: u128, lo: u128) -> Self { Self { hi, lo } }
    
    /// Advances the manifold state using a 128-bit seedling.
    /// Hardened with Coupled Manifold Evolution and Rotational Diffusion.
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

/// Secure Cryptographic Memory Sanitation
/// Automatically overwrites internal state registers with zeros upon scope exit
/// to protect against physical RAM extraction and Cold-Boot attacks.
impl Drop for TrvState {
    fn drop(&mut self) {
        self.hi = 0;
        self.lo = 0;
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
