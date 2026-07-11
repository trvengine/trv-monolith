"""
Tests whether a specialized, competition-grade CDCL SAT solver
(CaDiCaL/Glucose4/MapleSAT, via python-sat) does meaningfully better than
Z3 on the EXACT SAME trv_gate/trv_lock_step key-recovery instance where
Z3 stalls - distinguishing "generic tool limitation" from "the same
difficulty shows up regardless of which solver you throw at it."

Method: build the identical formula Z3 uses (same as sat_audit.py),
bit-blast it to raw CNF via Z3's own tactics (so the encoding is
identical, not a different/unfair encoding), export to DIMACS, then feed
that DIMACS file to real, modern SAT solvers directly.
"""
import sys
import time
import z3

W = 32  # reduced width so this is tractable to actually run to completion
MASK = (1 << W) - 1


def rotl(bv, n, width=W):
    return z3.RotateLeft(bv, n % width)


def rotr(bv, n, width=W):
    return rotl(bv, width - n, width)


def trv_gate(a, b, c):
    x = ~(a ^ b)
    y = (a & ~c) | (~b & c)
    return x, y


def build_formula(rounds):
    key = z3.BitVec("key", W)
    iv = z3.BitVecVal(0xA5A5A5A5, W)
    seedling = key ^ z3.BitVecVal(0, W)
    hi = iv
    lo = key

    for _ in range(rounds):
        x, y = trv_gate(hi, lo, seedling)
        hi, lo = rotl(x, 31), rotr(y, 19)
        seedling = seedling + (hi ^ lo)

    # Real target: run the same construction forward with a known real key
    # to get a real output, then ask the solver to find ANY key consistent
    # with it (the actual attack framing), using plain python ints so the
    # forward computation is trivially correct to check by hand.
    real_key = 0x12345678

    def trv_gate_int(a, b, c):
        return (~(a ^ b)) & MASK, ((a & ~c) | (~b & c)) & MASK
    def rotl_int(v, n):
        n = n % W
        return ((v << n) | (v >> (W - n))) & MASK
    def rotr_int(v, n):
        return rotl_int(v, W - n)
    real_hi, real_lo, real_seedling = 0xA5A5A5A5, real_key, real_key
    for _ in range(rounds):
        x, y = trv_gate_int(real_hi, real_lo, real_seedling)
        real_hi, real_lo = rotl_int(x, 31), rotr_int(y, 19)
        real_seedling = (real_seedling + (real_hi ^ real_lo)) & MASK

    constraint = z3.And(hi == real_hi, lo == real_lo)
    return constraint, real_key


def to_dimacs(constraint, path):
    goal = z3.Goal()
    goal.add(constraint)
    tactic = z3.Then(z3.Tactic("simplify"), z3.Tactic("bit-blast"), z3.Tactic("tseitin-cnf"))
    result = tactic(goal)
    subgoal = result[0]
    with open(path, "w") as f:
        f.write(subgoal.dimacs())


def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 16
    print(f"=== Building and CNF-exporting the real trv_gate/trv_lock_step key-recovery instance, rounds={rounds}, W={W} ===")
    constraint, real_key = build_formula(rounds)

    t0 = time.time()
    dimacs_path = "/tmp/trv_sat_instance.cnf"
    to_dimacs(constraint, dimacs_path)
    print(f"CNF export took {time.time()-t0:.2f}s, real key={hex(real_key)}")

    with open(dimacs_path) as f:
        header = f.readline()
    print(f"CNF size: {header.strip()}")

    print("\n--- Z3 (same formula, direct, native solving) ---")
    t0 = time.time()
    solver = z3.Solver()
    solver.set("timeout", 60000)
    solver.add(constraint)
    result = solver.check()
    print(f"Z3 result: {result}, time={time.time()-t0:.2f}s")

    from pysat.formula import CNF
    from pysat.solvers import Solver as SatSolver

    cnf = CNF(from_file=dimacs_path)
    for name in ["cadical195", "glucose4", "maplesat"]:
        print(f"\n--- {name} (identical CNF instance) ---")
        t0 = time.time()
        s = SatSolver(name=name, bootstrap_with=cnf.clauses)
        sat_result = s.solve()
        elapsed = time.time() - t0
        print(f"{name} result: {'SAT' if sat_result else 'UNSAT'}, time={elapsed:.2f}s")
        s.delete()


if __name__ == "__main__":
    main()
