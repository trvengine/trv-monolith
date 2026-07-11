import numpy as np

# Integral / Square (zero-sum) attack against the real trv_gate/trv_lock_step
# round pump, exact per-round seedling feedback as crypto.rs's inner loop:
#   state.trv_lock_step(seedling); seedling = seedling.wrapping_add(hi ^ lo)
#
# Method (classical Square/integral attack, Daemen-Knudsen-Rijmen style):
# fix lo0 and seedling0 to a constant, let hi0 range EXHAUSTIVELY over ALL
# 2^W values ("active" word, full/saturated set). After R rounds, XOR-sum
# (integral) the outputs across the whole active set. If the construction
# had insufficient diffusion/degree, the sum would be forced to zero (a
# "balanced" property) - a real distinguisher. This is done EXHAUSTIVELY
# (not sampled) at reduced width W=16 so the full 65536-element active set
# is actually covered, which is what the classical attack requires - a
# sampled/partial set cannot certify a zero-sum.
#
# Repeated over multiple random choices of the fixed (lo0, seedling0) pair
# to check the result isn't a fluke of one particular base state.

W = 16
DT = np.uint32  # use uint32 for arithmetic headroom, mask to W bits

MASK = (1 << W) - 1

def trv_gate(a, b, c):
    x = np.bitwise_and(np.bitwise_not(np.bitwise_xor(a, b)), MASK)
    y = np.bitwise_and(np.bitwise_or(np.bitwise_and(a, np.bitwise_not(c)), np.bitwise_and(np.bitwise_not(b), c)), MASK)
    return x, y

def rotl(v, n):
    n = n % W
    if n == 0:
        return v & MASK
    return ((v << n) | (v >> (W - n))) & MASK

def rotr(v, n):
    return rotl(v, W - n)

def run(hi0, lo0, seed0, rounds):
    hi, lo, seed = hi0.copy(), lo0.copy(), seed0.copy()
    for _ in range(rounds):
        x, y = trv_gate(hi, lo, seed)
        hi, lo = rotl(x, 5), rotr(y, 3)  # rotation amounts scaled down proportionally for W=16 (31/19 out of 128 ~ 24%/15%)
        seed = (seed + np.bitwise_xor(hi, lo)) & MASK
    return hi, lo, seed

def zero_sum_check(lo0_val, seed0_val, rounds):
    hi0 = np.arange(1 << W, dtype=DT)  # exhaustive active set
    lo0 = np.full(1 << W, lo0_val, dtype=DT)
    seed0 = np.full(1 << W, seed0_val, dtype=DT)
    hi, lo, _ = run(hi0, lo0, seed0, rounds)
    sum_hi = np.bitwise_xor.reduce(hi)
    sum_lo = np.bitwise_xor.reduce(lo)
    return int(sum_hi), int(sum_lo)

def main():
    print(f"=== Integral/Square attack on real trv_gate/trv_lock_step (W={W}, EXHAUSTIVE 2^{W}={1<<W:,} active set) ===")
    print("Balanced/zero-sum property (sum_hi==0 and sum_lo==0) across ALL repeats would be a real distinguisher.\n")

    rng = np.random.default_rng(2024)
    round_counts = [1, 2, 4, 8, 16, 32, 64, 128]
    repeats = 10

    for rounds in round_counts:
        zero_count = 0
        examples = []
        for _ in range(repeats):
            lo0_val = int(rng.integers(0, 1 << W))
            seed0_val = int(rng.integers(0, 1 << W))
            sh, sl = zero_sum_check(lo0_val, seed0_val, rounds)
            is_zero = (sh == 0 and sl == 0)
            if is_zero:
                zero_count += 1
            examples.append((sh, sl))
        flag = " <<< SUSPICIOUS (all zero-sum)" if zero_count == repeats else ""
        print(f"  rounds={rounds:3d}: zero_sum_hits={zero_count}/{repeats}  sample_sums(hi,lo)={examples[:3]}{flag}", flush=True)

if __name__ == "__main__":
    main()
