"""
Isolates one specific claim: that wrapping_add's carry-chain (as opposed to
a carry-free operation like XOR) is what specifically causes the SAT
solver's difficulty, by swapping ONLY that one operation and comparing
solve time at the same round count. Everything else (trv_gate, rotations,
key/seedling coupling) is identical to sat_audit.py.

If the carry-chain is the special ingredient, the XOR-seedling variant
should solve dramatically faster at the same round count where the real
(addition) version times out. If solve time is similar either way, the
difficulty is coming from the round count / iterated nonlinearity in
general, not specifically from the carry-chain.
"""
import sys
import time
import z3

W = 128
MASK = (1 << W) - 1


def rotl(bv, n, width=W):
    return z3.RotateLeft(bv, n % width)


def rotr(bv, n, width=W):
    return rotl(bv, width - n, width)


def trv_gate(a, b, c):
    x = ~(a ^ b)
    y = (a & ~c) | (~b & c)
    return x, y


def trv_lock_step(hi, lo, seedling):
    x, y = trv_gate(hi, lo, seedling)
    return rotl(x, 31), rotr(y, 19)


def build_and_solve(rounds: int, timeout_ms: int, use_addition: bool):
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)

    key = z3.BitVec("key", W)
    iv = z3.BitVecVal(0xA5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5, W)
    seedling = key
    hi = iv
    lo = key

    for _ in range(rounds):
        hi, lo = trv_lock_step(hi, lo, seedling)
        seedling = (seedling + (hi ^ lo)) if use_addition else (seedling ^ (hi ^ lo))

    real_key = 0x0123456789ABCDEF0123456789ABCDEF
    ref_iv = 0xA5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5
    ref_seedling = real_key
    ref_hi, ref_lo = ref_iv, real_key
    for _ in range(rounds):
        x = (~(ref_hi ^ ref_lo)) & MASK
        y = ((ref_hi & (~ref_seedling & MASK)) | ((~ref_lo & MASK) & ref_seedling)) & MASK
        ref_hi = ((x << 31) | (x >> (W - 31))) & MASK
        ref_lo = ((y >> 19) | (y << (W - 19))) & MASK
        if use_addition:
            ref_seedling = (ref_seedling + (ref_hi ^ ref_lo)) & MASK
        else:
            ref_seedling = (ref_seedling ^ (ref_hi ^ ref_lo)) & MASK

    solver.add(hi == ref_hi, lo == ref_lo)

    start = time.time()
    result = solver.check()
    elapsed = time.time() - start
    label = "wrapping_add (real)" if use_addition else "XOR (carry-free variant)"
    print(f"[{label}] rounds={rounds}  z3_result={result}  elapsed={elapsed:.2f}s")
    return result, elapsed


def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    timeout_s = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    print(f"=== Isolating wrapping_add's carry-chain effect at rounds={rounds}, timeout={timeout_s}s ===\n")
    build_and_solve(rounds, timeout_s * 1000, use_addition=True)
    build_and_solve(rounds, timeout_s * 1000, use_addition=False)


if __name__ == "__main__":
    main()
