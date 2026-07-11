import numpy as np

# Differential cryptanalysis of the real trv_gate/trv_lock_step core,
# mirroring trv_kdf's actual seedling-feedback construction exactly
# (seedling ^ i each round, seedling += hi^lo and hi = rotl(hi,13)^GOLDEN
# every 64 rounds) - not an idealized fixed round function.
#
# Reduced to W=32 bits (numpy uint32) for speed, vectorized across millions of parallel trials.
#
# Method: fix an input difference (dhi, dlo). For N random base states,
# run the SAME base state and the XOR-perturbed state through R rounds.
# Look at the distribution of the resulting output difference across all
# N trials - any bit of that difference with probability far from 0.5
# (or the full difference collapsing to a fixed value) is a real
# differential characteristic, i.e. a genuine weakness.

W = 32
DT = np.uint32
GOLDEN = DT(0x9E3779B9)

def trv_gate(a, b, c):
    x = np.bitwise_not(np.bitwise_xor(a, b))
    y = np.bitwise_or(np.bitwise_and(a, np.bitwise_not(c)), np.bitwise_and(np.bitwise_not(b), c))
    return x, y

def rotl(v, n):
    n = n % W
    return DT((v.astype(np.uint64) << n) | (v.astype(np.uint64) >> (W - n)))

def rotr(v, n):
    return rotl(v, W - n)

def run_pair(hi0, lo0, dhi, dlo, seedling0, rounds):
    hiA, loA = hi0.copy(), lo0.copy()
    hiB, loB = np.bitwise_xor(hi0, dhi), np.bitwise_xor(lo0, dlo)
    seedA = np.full(hi0.shape, seedling0, dtype=DT)
    seedB = np.full(hi0.shape, seedling0, dtype=DT)
    for i in range(rounds):
        xA, yA = trv_gate(hiA, loA, np.bitwise_xor(seedA, DT(i)))
        hiA, loA = rotl(xA, 31), rotr(yA, 19)  # same constants as the real 128-bit construction
        xB, yB = trv_gate(hiB, loB, np.bitwise_xor(seedB, DT(i)))
        hiB, loB = rotl(xB, 31), rotr(yB, 19)
        if i % 64 == 0:
            seedA = DT(seedA + np.bitwise_xor(hiA, loA))
            seedB = DT(seedB + np.bitwise_xor(hiB, loB))
            hiA = np.bitwise_xor(rotl(hiA, 13), GOLDEN)
            hiB = np.bitwise_xor(rotl(hiB, 13), GOLDEN)
    return hiA, loA, hiB, loB

def bias_report(rounds, dhi, dlo, trials, seedling0=0xDEADBEEF):
    rng = np.random.default_rng(42)
    hi0 = rng.integers(0, 1 << W, size=trials, dtype=np.int64).astype(DT)
    lo0 = rng.integers(0, 1 << W, size=trials, dtype=np.int64).astype(DT)
    hiA, loA, hiB, loB = run_pair(hi0, lo0, DT(dhi), DT(dlo), seedling0, rounds)
    diff_hi = np.bitwise_xor(hiA, hiB)
    diff_lo = np.bitwise_xor(loA, loB)

    max_bias = 0.0
    worst_bit = None
    for word_name, diff in [("hi", diff_hi), ("lo", diff_lo)]:
        for bit in range(W):
            p1 = float(np.mean((diff >> DT(bit)) & DT(1)))
            bias = abs(p1 - 0.5)
            if bias > max_bias:
                max_bias = bias
                worst_bit = (word_name, bit, p1)

    # also check: does the full difference ever collapse to a single
    # constant value across all trials (strongest possible signal)?
    combined = diff_hi.astype(np.uint64) << 32 | diff_lo.astype(np.uint64)
    unique_vals = len(np.unique(combined))

    return max_bias, worst_bit, unique_vals

def main():
    trials = 2_000_000
    print(f"=== Differential cryptanalysis of real trv_gate/trv_lock_step (W={W}, {trials:,} trials/config) ===")
    print("Checking: max |P(output-diff-bit=1) - 0.5| across all 64 output bits, and whether output diff ever collapses to <100 unique values (both would indicate a real weakness)\n")

    diffs_to_test = [
        ("single bit hi[0]", 1, 0),
        ("single bit hi[31]", 1 << 31, 0),
        ("single bit lo[0]", 0, 1),
        ("single bit lo[31]", 0, 1 << 31),
        ("both lsb", 1, 1),
    ]
    round_counts = [1, 2, 4, 8, 16, 32, 64, 128]

    for name, dhi, dlo in diffs_to_test:
        print(f"--- input difference: {name} (dhi=0x{dhi:08x}, dlo=0x{dlo:08x}) ---", flush=True)
        for r in round_counts:
            max_bias, worst_bit, unique_vals = bias_report(r, dhi, dlo, trials)
            flag = " <<< SUSPICIOUS" if max_bias > 0.01 or unique_vals < trials * 0.5 else ""
            print(f"  rounds={r:3d}: max_bit_bias={max_bias:.5f}  worst_bit={worst_bit}  unique_output_diffs={unique_vals:,}/{trials:,}{flag}", flush=True)
        print()

if __name__ == "__main__":
    main()
