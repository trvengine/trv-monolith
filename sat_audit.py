"""
SAT/SMT audit of the real trv_gate/trv_lock_step core, via Z3 bit-blasting.

Usage: python3 sat_audit.py [rounds] [timeout_seconds]
"""
import sys
import time
import z3

W = 128
MASK = (1 << W) - 1


def rotl(bv, n, width=W):
    n = n % width
    return z3.RotateLeft(bv, n)


def rotr(bv, n, width=W):
    return rotl(bv, width - n, width)


def trv_gate(a, b, c):
    x = ~(a ^ b)
    y = (a & ~c) | (~b & c)
    return x, y


def trv_lock_step(hi, lo, seedling):
    x, y = trv_gate(hi, lo, seedling)
    return rotl(x, 31), rotr(y, 19)


def build_and_solve(rounds: int, timeout_ms: int):
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)

    key = z3.BitVec("key", W)          # the single unknown - real attacker's target
    iv = z3.BitVecVal(0xA5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5, W)  # known, public IV
    block_idx = 0

    seedling = key ^ z3.BitVecVal(block_idx, W)
    hi = iv
    lo = key  # TrvState::with_values(iv, key) - lo IS the key, tied to the same unknown as seedling

    for _ in range(rounds):
        hi, lo = trv_lock_step(hi, lo, seedling)
        seedling = seedling + (hi ^ lo)  # matches wrapping_add via BitVec's native wraparound

    # compute the REAL keystream for a fixed, known real_key, then ask the
    # solver to find ANY key consistent with that observed output - this
    # is the actual attack: given output, recover key.
    real_key = 0x0123456789ABCDEF0123456789ABCDEF
    ref_iv = 0xA5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5
    ref_seedling = real_key ^ block_idx
    ref_hi, ref_lo = ref_iv, real_key
    for _ in range(rounds):
        # NOTE: this python-native reference reimplements the gate purely
        # to compute a ground-truth target keystream without needing z3
        # for that half - kept deliberately simple/direct so a reader can
        # verify it against core/engine.rs by eye. a=hi, b=lo, c=seedling.
        x = (~(ref_hi ^ ref_lo)) & MASK
        y = ((ref_hi & (~ref_seedling & MASK)) | ((~ref_lo & MASK) & ref_seedling)) & MASK
        ref_hi = ((x << 31) | (x >> (W - 31))) & MASK
        ref_lo = ((y >> 19) | (y << (W - 19))) & MASK
        ref_seedling = (ref_seedling + (ref_hi ^ ref_lo)) & MASK

    solver.add(hi == ref_hi, lo == ref_lo)

    start = time.time()
    result = solver.check()
    elapsed = time.time() - start

    print(f"rounds={rounds}  timeout={timeout_ms}ms  z3_result={result}  elapsed={elapsed:.2f}s")
    if result == z3.sat:
        model = solver.model()
        found_key = model[key].as_long()
        print(f"  Z3 FOUND a key: 0x{found_key:032x}  (real key was 0x{real_key:032x})")
    return result


def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    timeout_s = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    print(f"=== SAT audit of real trv_gate/trv_lock_step ({W}-bit, {rounds} rounds, {timeout_s}s timeout) ===")
    build_and_solve(rounds, timeout_s * 1000)


if __name__ == "__main__":
    main()
