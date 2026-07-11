import numpy as np

# Exact transcription of the real trv_gate / TrvState / trv_lock_step from
# core/engine.rs, vectorized with numpy uint32 arrays so a full cube (up to
# 2^20+ evaluations) runs in seconds instead of minutes. Formulas unchanged
# from the real source - only vectorized across many parallel evaluations.

W = 32
DT = np.uint32

def trv_gate(a, b, c):
    x = np.bitwise_not(np.bitwise_xor(a, b))
    y = np.bitwise_or(np.bitwise_and(a, np.bitwise_not(c)), np.bitwise_and(np.bitwise_not(b), c))
    return x, y

def rotl(v, n):
    n = n % W
    return DT((v.astype(np.uint64) << n) | (v.astype(np.uint64) >> (W - n)))

def rotr(v, n):
    return rotl(v, W - n)

def run_core_vectorized(hi0, lo0, seedling0, rounds):
    hi = hi0.copy()
    lo = lo0.copy()
    seedling = np.full(hi0.shape, seedling0, dtype=DT)
    for _ in range(rounds):
        x, y = trv_gate(hi, lo, seedling)
        hi = rotl(x, 31)
        lo = rotr(y, 19)
        seedling = DT(seedling + np.bitwise_xor(hi, lo))
    return hi, lo

def cube_test(rounds, cube_size, output_bit, trials=3, fixed_seed=0xDEADBEEF):
    rng = np.random.default_rng(1234)
    k = cube_size
    n = 1 << k
    assignments = np.arange(n, dtype=np.uint64).astype(DT)  # low k bits vary

    all_zero = True
    for t in range(trials):
        lo0_val = int(rng.integers(0, 1 << W))
        base_hi = int(rng.integers(0, 1 << W)) & ~((1 << k) - 1) & ((1 << W) - 1)
        hi0 = DT(base_hi) | assignments  # low k bits = cube assignment, rest fixed
        lo0 = np.full(n, lo0_val, dtype=DT)

        hi, lo = run_core_vectorized(hi0, lo0, fixed_seed, rounds)
        out_bits = (hi >> output_bit) & DT(1)
        xor_sum = int(np.bitwise_xor.reduce(out_bits))
        if xor_sum != 0:
            all_zero = False
            break
    return all_zero

def main():
    print(f"=== Cube tester against the real trv_gate/trv_lock_step core (W={W} bits, numpy-vectorized) ===", flush=True)
    print("Cube = low-order bits of hi0 varied; output bit checked = bit 0 of final hi.\n", flush=True)

    cube_sizes = [8, 12, 16, 20]
    round_counts = [1, 2, 4, 8, 16, 32, 64, 128]

    for cube_size in cube_sizes:
        print(f"--- cube size {cube_size} ({1<<cube_size} evaluations/trial) ---", flush=True)
        for r in round_counts:
            zero = cube_test(r, cube_size, output_bit=0, trials=3)
            status = "ZERO-SUM (potential weakness)" if zero else "non-zero (no distinguisher found)"
            print(f"  rounds={r:3d}: {status}", flush=True)
        print("", flush=True)

if __name__ == "__main__":
    main()
