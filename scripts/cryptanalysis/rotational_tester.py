import numpy as np

# Rotational cryptanalysis of the real trv_gate/trv_lock_step core, using
# the exact per-round seedling feedback trv_ctr_stream/trv_hash use:
#   state.trv_lock_step(seedling); seedling = seedling.wrapping_add(hi ^ lo)
# every round (the literal transcription of crypto.rs's inner loop, not the
# periodic-refresh variant differential_tester.py uses).
#
# Every operation inside trv_gate (NOT, AND, OR, XOR) is bitwise and
# therefore commutes with rotation: rotl(f(a,b,c), r) == f(rotl(a,r),
# rotl(b,r), rotl(c,r)) for any bitwise f. trv_lock_step's own rotl(31)/
# rotr(19) also compose with an extra outer rotation by r. So a round pump
# built only from {NOT,AND,OR,XOR,ROTATE} would rotate every output by r
# whenever every input (hi, lo, seedling) is rotated by r, with probability
# 1, for any number of rounds - a textbook rotational cipher.
#
# The one operation that can break this is seedling.wrapping_add(hi ^ lo):
# addition has carry propagation across bit positions, which rotation does
# not respect (rotl(a,r) + rotl(b,r) != rotl(a+b,r) in general) - the same
# mechanism ARX-cipher designers rely on to defeat rotational cryptanalysis
# (Khovratovich-Nikolic). This measures whether that single wrapping_add
# per round collapses the rotational relationship to noise, or whether it
# survives at an exploitable probability.

W = 32
DT = np.uint32

def trv_gate(a, b, c):
    x = np.bitwise_not(np.bitwise_xor(a, b))
    y = np.bitwise_or(np.bitwise_and(a, np.bitwise_not(c)), np.bitwise_and(np.bitwise_not(b), c))
    return x, y

def rotl(v, n):
    n = n % W
    if n == 0:
        return v.copy()
    return DT((v.astype(np.uint64) << n) | (v.astype(np.uint64) >> (W - n)))

def rotr(v, n):
    return rotl(v, W - n)

def run(hi0, lo0, seed0, rounds):
    hi, lo, seed = hi0.copy(), lo0.copy(), seed0.copy()
    for _ in range(rounds):
        x, y = trv_gate(hi, lo, seed)
        hi, lo = rotl(x, 31), rotr(y, 19)
        seed = DT(seed + np.bitwise_xor(hi, lo))
    return hi, lo, seed

def test_rotation(r, rounds, trials, rng):
    hi0 = rng.integers(0, 1 << W, size=trials, dtype=np.int64).astype(DT)
    lo0 = rng.integers(0, 1 << W, size=trials, dtype=np.int64).astype(DT)
    seed0 = rng.integers(0, 1 << W, size=trials, dtype=np.int64).astype(DT)

    # Trajectory A: plain input
    hiA, loA, _ = run(hi0, lo0, seed0, rounds)

    # Trajectory B: every input (hi, lo, AND seedling) rotated by r
    hi0r, lo0r, seed0r = rotl(hi0, r), rotl(lo0, r), rotl(seed0, r)
    hiB, loB, _ = run(hi0r, lo0r, seed0r, rounds)

    # Prediction under the rotational hypothesis: output should also be
    # rotated by r if the construction were rotation-invariant.
    pred_hi, pred_lo = rotl(hiA, r), rotl(loA, r)

    exact_match = np.mean((pred_hi == hiB) & (pred_lo == loB))

    # Partial correlation: average fraction of matching bits between the
    # predicted-rotated output and the actual rotated-input output, vs the
    # 0.5 expected for two independent random 2W-bit strings.
    xor_hi = np.bitwise_xor(pred_hi, hiB)
    xor_lo = np.bitwise_xor(pred_lo, loB)
    combined = xor_hi.astype(np.uint64) << W | xor_lo.astype(np.uint64)
    popcount = np.zeros(trials, dtype=np.int64)
    tmp = combined.copy()
    for _ in range(2 * W):
        popcount += (tmp & 1).astype(np.int64)
        tmp >>= 1
    mean_matching_bits = (2 * W) - popcount.mean()
    frac_matching = mean_matching_bits / (2 * W)

    return exact_match, frac_matching

def main():
    trials = 500_000
    rng = np.random.default_rng(1337)
    print(f"=== Rotational cryptanalysis of real trv_gate/trv_lock_step (W={W}, {trials:,} trials/config) ===")
    print("Baseline for 'no relationship': exact_match ~ 1/2^64 (~0), frac_matching_bits ~ 0.5\n")

    rotations = [1, 7, 13, 19, 31]
    round_counts = [1, 2, 4, 8, 16, 32, 64, 128]

    for r in rotations:
        print(f"--- rotation amount r={r} ---", flush=True)
        for rounds in round_counts:
            exact, frac = test_rotation(r, rounds, trials, rng)
            flag = " <<< SUSPICIOUS" if frac > 0.55 or exact > 1e-3 else ""
            print(f"  rounds={rounds:3d}: exact_rotational_match={exact:.6f}  mean_matching_bit_frac={frac:.5f}{flag}", flush=True)
        print()

if __name__ == "__main__":
    main()
