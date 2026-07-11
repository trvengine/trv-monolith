import numpy as np

# Impossible-differential search against the real trv_gate/trv_lock_step
# round pump (miss-in-the-middle style: find an input difference and an
# output difference whose transition probability is EXACTLY zero, not just
# small - which requires exhaustive coverage of the base-state space, not
# sampling, since a sampled test can never certify "never happens").
#
# Reduced to W=12 bits so the full (hi0, lo0) pair space (2^24) can be
# enumerated exhaustively for each candidate input difference, with seed0
# held fixed. For each input difference, run every (hi0, lo0) pair through
# R rounds and record which output differences actually occur. An output
# difference with a hit-count of exactly 0 across the full exhaustive
# (hi0, lo0) space would be a candidate impossible differential - though
# see main()'s coupon-collector baseline for why raw non-coverage isn't
# sufficient evidence by itself.

W = 12
MASK = (1 << W) - 1

def rotl(v, n):
    n = n % W
    if n == 0:
        return v & MASK
    return ((v << n) | (v >> (W - n))) & MASK

def rotr(v, n):
    return rotl(v, W - n)

def coverage_for_diff_fast(dhi, dlo, rounds, seed0):
    # Fully exhaustive over the (hi0, lo0) pair - all 2^12 x 2^12 = 2^24
    # combinations - via vectorized broadcasting (no python-level loop over
    # base states). seed0 fixed (not exhaustive; that dimension is a
    # documented reduction, consistent with the rest of the battery).
    # Trial count (2^24) exactly matches the output-diff space size (2^24),
    # which makes the coupon-collector baseline comparison in main() valid.
    N = 1 << W
    hi_grid, lo_grid = np.meshgrid(np.arange(N, dtype=np.int64), np.arange(N, dtype=np.int64), indexing='ij')
    hiA = hi_grid.ravel()
    loA = lo_grid.ravel()
    seedA = np.full_like(hiA, seed0)
    hiB = (hiA ^ dhi) & MASK
    loB = (loA ^ dlo) & MASK
    seedB = seedA.copy()
    for _ in range(rounds):
        xA = (~(hiA ^ loA)) & MASK
        yA = ((hiA & ~seedA) | ((~loA) & seedA)) & MASK
        hiA, loA = rotl(xA, 5), rotr(yA, 3)
        seedA = (seedA + (hiA ^ loA)) & MASK

        xB = (~(hiB ^ loB)) & MASK
        yB = ((hiB & ~seedB) | ((~loB) & seedB)) & MASK
        hiB, loB = rotl(xB, 5), rotr(yB, 3)
        seedB = (seedB + (hiB ^ loB)) & MASK
    diff_hi = hiA ^ hiB
    diff_lo = loA ^ loB
    combined = (diff_hi << W) | diff_lo
    return set(np.unique(combined).tolist())

def main():
    total_space = 1 << (2 * W)
    trials = 1 << (2 * W)  # exhaustive (hi0,lo0) pairs == same order as output space
    expected_frac_random = 1.0 - np.exp(-trials / total_space)  # coupon-collector baseline for an IDEAL random function

    print(f"=== Impossible-differential search on real trv_gate/trv_lock_step (W={W}) ===")
    print(f"Exhaustive over all {trials:,} (hi0,lo0) pairs, fixed seed0. Output-diff space = {total_space:,}.")
    print(f"Coupon-collector baseline: even an IDEAL random function would only cover ~{expected_frac_random:.4%} of")
    print("output diffs at this trial count (many diffs go unhit by chance alone, not because they're impossible).")
    print("A real finding requires coverage clearly BELOW this random baseline, or an exact-zero count for a diff")
    print("that a random function would essentially always hit given the redundancy at low round counts.\n")

    diffs = [
        ("single bit hi[0]", 1, 0),
        ("single bit hi[11]", 1 << (W - 1), 0),
        ("single bit lo[0]", 0, 1),
        ("both lsb", 1, 1),
    ]
    round_counts = [1, 2, 3, 4, 6, 8]
    seed0 = 0x123

    for name, dhi, dlo in diffs:
        print(f"--- input difference: {name} (dhi=0x{dhi:03x}, dlo=0x{dlo:03x}) ---", flush=True)
        for rounds in round_counts:
            achieved = coverage_for_diff_fast(dhi, dlo, rounds, seed0)
            frac = len(achieved) / total_space
            flag = " <<< BELOW RANDOM BASELINE" if frac < expected_frac_random - 0.02 else ""
            print(f"  rounds={rounds}: distinct_output_diffs_achieved={len(achieved):,}/{total_space:,} ({frac:.4%}, random baseline {expected_frac_random:.4%}){flag}", flush=True)
        print()

if __name__ == "__main__":
    main()
