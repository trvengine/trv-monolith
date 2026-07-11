"""
Isolates WHERE the CNF export time actually goes as rounds increase -
distinguishing "the resulting CNF is genuinely huge" (supports exponential
math-density blowup) from "one specific tactic step is slow regardless of
output size" (supports mundane tooling bottleneck).
"""
import time
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


def build_formula(rounds):
    key = z3.BitVec("key", W)
    iv = z3.BitVecVal(0xA5A5A5A5, W)
    seedling = key
    hi = iv
    lo = key
    for _ in range(rounds):
        x, y = trv_gate(hi, lo, seedling)
        hi, lo = rotl(x, 31), rotr(y, 19)
        seedling = seedling + (hi ^ lo)
    return hi == 0, lo == 0  # dummy target, we only care about export size/timing here


def main():
    for rounds in [4, 8, 10, 12, 14]:
        c1, c2 = build_formula(rounds)
        constraint = z3.And(c1, c2)
        goal = z3.Goal()
        goal.add(constraint)

        t0 = time.time()
        simplified = z3.Tactic("simplify")(goal)[0]
        t_simplify = time.time() - t0

        t0 = time.time()
        bitblasted = z3.Tactic("bit-blast")(simplified)[0]
        t_bitblast = time.time() - t0

        t0 = time.time()
        cnf_goal = z3.Tactic("tseitin-cnf")(bitblasted)[0]
        t_tseitin = time.time() - t0

        dimacs = cnf_goal.dimacs()
        header = dimacs.split("\n")[0]

        print(f"rounds={rounds:3d}: simplify={t_simplify:6.2f}s  bit-blast={t_bitblast:6.2f}s  tseitin-cnf={t_tseitin:6.2f}s  |  {header}")


if __name__ == "__main__":
    main()
