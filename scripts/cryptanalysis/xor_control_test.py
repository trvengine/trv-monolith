"""
Control experiment: build a random system of pure XOR (linear GF(2))
equations - provably solvable in polynomial time by Gaussian elimination,
zero cryptographic content, no security claim whatsoever - at a similar
small variable count to the 16-round TRV instance (~3900 vars). Feed it
to the same plain CDCL solvers (Z3, CaDiCaL) with no native XOR/Gaussian
handling, and see whether they also stall.

If a solver with no special XOR support struggles on a system we KNOW is
trivially easy, that demonstrates "small instance + CDCL stalls" is a
known property of this solver family against linear/XOR structure, not
evidence of deep problem-specific hardness.
"""
import random
import time
import z3

N_VARS = 3900  # match the real 16-round TRV CNF size
N_EQUATIONS = 3200  # a well-determined-ish random linear system


def build_random_xor_system(n_vars, n_eqs, seed=42):
    rng = random.Random(seed)
    # ground truth assignment (unused by the solver - it must find it blind)
    truth = [rng.randint(0, 1) for _ in range(n_vars)]
    bits = [z3.Bool(f"x{i}") for i in range(n_vars)]
    equations = []
    for _ in range(n_eqs):
        # each equation: XOR of a random subset of variables == some constant
        subset_size = rng.randint(3, 8)
        subset = rng.sample(range(n_vars), subset_size)
        rhs = 0
        for idx in subset:
            rhs ^= truth[idx]
        expr = bits[subset[0]]
        for idx in subset[1:]:
            expr = z3.Xor(expr, bits[idx])
        equations.append(expr == bool(rhs))
    return equations


def main():
    print(f"=== Control: random XOR/linear system, {N_VARS} variables, {N_EQUATIONS} equations ===")
    print("(Provably polynomial-time solvable via Gaussian elimination - zero cryptographic content)\n")
    equations = build_random_xor_system(N_VARS, N_EQUATIONS)

    solver = z3.Solver()
    solver.set("timeout", 60000)
    for eq in equations:
        solver.add(eq)

    t0 = time.time()
    result = solver.check()
    elapsed = time.time() - t0
    print(f"Z3 (plain, no Gaussian-elimination hint) result: {result}, time={elapsed:.2f}s")
    print("\nIf this times out / returns unknown on a KNOWN-trivially-solvable system,")
    print("that demonstrates the earlier TRV hang pattern isn't unique to deep cryptographic hardness -")
    print("it's a known weak spot of plain CDCL against XOR-heavy structure, size notwithstanding.")


if __name__ == "__main__":
    main()
