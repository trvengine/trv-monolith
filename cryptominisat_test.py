"""
Runs REAL CryptoMiniSat (native Gaussian elimination for XOR structure)
on two instances: the trivial random-linear control (sanity check: should
be near-instant), then the real 16-round trv_gate/trv_lock_step
key-recovery instance (the actual question).
"""
import random
import time
import sys
from pycryptosat import Solver as CMSSolver
import z3

W = 32
MASK = (1 << W) - 1


def rotl(bv, n, width=W):
    return z3.RotateLeft(bv, n % width)


def rotr(bv, n, width=W):
    return rotl(bv, width - n, width)


def trv_gate(a, b, c):
    x = ~(a ^ b)
    y = (a & ~c) | (~b & c)
    return x, y


def trv_gate_int(a, b, c):
    return (~(a ^ b)) & MASK, ((a & ~c) | (~b & c)) & MASK


def rotl_int(v, n):
    n = n % W
    return ((v << n) | (v >> (W - n))) & MASK


def rotr_int(v, n):
    return rotl_int(v, W - n)


def build_real_trv_cnf(rounds):
    key = z3.BitVec("key", W)
    iv = z3.BitVecVal(0xA5A5A5A5, W)
    seedling = key
    hi = iv
    lo = key
    for _ in range(rounds):
        x, y = trv_gate(hi, lo, seedling)
        hi, lo = rotl(x, 31), rotr(y, 19)
        seedling = seedling + (hi ^ lo)

    real_key = 0x12345678
    real_hi, real_lo, real_seedling = 0xA5A5A5A5, real_key, real_key
    for _ in range(rounds):
        x, y = trv_gate_int(real_hi, real_lo, real_seedling)
        real_hi, real_lo = rotl_int(x, 31), rotr_int(y, 19)
        real_seedling = (real_seedling + (real_hi ^ real_lo)) & MASK

    constraint = z3.And(hi == real_hi, lo == real_lo)
    goal = z3.Goal()
    goal.add(constraint)
    tactic = z3.Then(z3.Tactic("simplify"), z3.Tactic("bit-blast"), z3.Tactic("tseitin-cnf"))
    cnf_goal = tactic(goal)[0]
    dimacs = cnf_goal.dimacs()
    return dimacs, real_key


def dimacs_to_clauses(dimacs):
    clauses = []
    for line in dimacs.splitlines():
        line = line.strip()
        if not line or line.startswith("p") or line.startswith("c"):
            continue
        lits = [int(x) for x in line.split() if x != "0"]
        if lits:
            clauses.append(lits)
    return clauses


def build_xor_control(n_vars, n_eqs, seed=42):
    rng = random.Random(seed)
    truth = [rng.randint(0, 1) for _ in range(n_vars)]
    bits = [z3.Bool(f"x{i}") for i in range(n_vars)]
    equations = []
    for _ in range(n_eqs):
        subset_size = rng.randint(3, 8)
        subset = rng.sample(range(n_vars), subset_size)
        rhs = 0
        for idx in subset:
            rhs ^= truth[idx]
        expr = bits[subset[0]]
        for idx in subset[1:]:
            expr = z3.Xor(expr, bits[idx])
        equations.append(expr == bool(rhs))
    goal = z3.Goal()
    for eq in equations:
        goal.add(eq)
    cnf_goal = z3.Tactic("tseitin-cnf")(goal)[0]
    return cnf_goal.dimacs()


def run_cms(dimacs, label, timeout_s=120):
    clauses = dimacs_to_clauses(dimacs)
    num_vars = max(abs(l) for c in clauses for l in c)
    print(f"--- CryptoMiniSat on {label}: {num_vars} vars, {len(clauses)} clauses ---")
    s = CMSSolver()
    for c in clauses:
        s.add_clause(c)
    t0 = time.time()
    sat, solution = s.solve()
    elapsed = time.time() - t0
    print(f"Result: {'SAT' if sat else 'UNSAT'}, time={elapsed:.2f}s")
    return elapsed, sat


def main():
    print("=== Sanity check: CryptoMiniSat on the trivial random-linear control (should be near-instant) ===")
    xor_dimacs = build_xor_control(3900, 3200)
    run_cms(xor_dimacs, "random XOR control")

    print("\n=== Real question: CryptoMiniSat on the real 16-round trv_gate/trv_lock_step key-recovery instance ===")
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 16
    dimacs, real_key = build_real_trv_cnf(rounds)
    print(f"(real key = {hex(real_key)}, rounds={rounds})")
    run_cms(dimacs, f"real TRV, {rounds} rounds", timeout_s=180)


if __name__ == "__main__":
    main()
