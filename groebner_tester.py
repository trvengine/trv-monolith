import time
from sympy import symbols, groebner

# Algebraic (Groebner-basis) attack against the real trv_gate/trv_lock_step
# round pump, distinct from the SAT/Z3 bit-blasting attack in sat_audit.py:
# instead of a CNF-SAT solver, this builds the exact GF(2) ANF (algebraic
# normal form) polynomial system for R rounds symbolically in the unknown
# seedling/key bits, then asks a Groebner-basis engine (Buchberger's
# algorithm, lex order) to eliminate down to the key bits directly. If the
# ideal reduces to {k_i - constant_i}, the key is fully and directly solved
# algebraically. If Buchberger's algorithm blows up in degree/time, that is
# the honest negative result.
#
# W is intentionally tiny (6 bits) so the *width* isn't the bottleneck -
# this isolates whether the round structure itself is easy for a Groebner
# basis to crack open, independent of brute-forceability at this scale.
#
# Uses sympy's GF(2) Groebner-basis support rather than a full computer
# algebra system.

W = 6
MASK = (1 << W) - 1


def XOR(a, b):
    return [(x + y) for x, y in zip(a, b)]


def AND(a, b):
    return [(x * y) for x, y in zip(a, b)]


def OR(a, b):
    return [(x + y + x * y) for x, y in zip(a, b)]


def NOT(a):
    return [(1 + x) for x in a]


def trv_gate_sym(a, b, c):
    x = NOT(XOR(a, b))
    y = OR(AND(a, NOT(c)), AND(NOT(b), c))
    return x, y


def rotl(bits, n):
    n = n % W
    return bits[-n:] + bits[:-n] if n else bits[:]


def rotr(bits, n):
    return rotl(bits, W - n)


def ripple_add(a, b):
    # Symbolic GF(2) ripple-carry adder: a,b little-endian bit lists.
    out = []
    carry = 0
    for ai, bi in zip(a, b):
        s = ai + bi + carry
        t1 = ai * bi
        t2 = carry * (ai + bi)
        carry = t1 + t2 + t1 * t2
        out.append(s)
    return out


def int_to_bits(v, w=W):
    return [ (v >> i) & 1 for i in range(w) ]


def bits_to_int(bits):
    v = 0
    for i, b in enumerate(bits):
        v |= (int(b) & 1) << i
    return v


def run_reference(hi0, lo0, seed0, rounds):
    hi, lo, seed = hi0, lo0, seed0
    for _ in range(rounds):
        x = (~(hi ^ lo)) & MASK
        y = ((hi & ~seed) | ((~lo) & seed)) & MASK
        hi, lo = ((x << 2) | (x >> (W - 2))) & MASK, ((y >> 1) | (y << (W - 1))) & MASK
        seed = (seed + (hi ^ lo)) & MASK
    return hi, lo


def build_symbolic(hi0, lo0, key_bits, rounds):
    hi = int_to_bits(hi0)
    lo = int_to_bits(lo0)
    seed = key_bits
    for _ in range(rounds):
        x, y = trv_gate_sym(hi, lo, seed)
        hi, lo = rotl(x, 2), rotr(y, 1)
        seed = ripple_add(seed, XOR(hi, lo))
    return hi, lo


def attempt_round(rounds, real_key):
    # hi0/lo0 must not be bitwise complements of each other: trv_gate's
    # y=(a&~c)|(~b&c) degenerates to a key-independent constant at any bit
    # position where a==~b, since both mux branches become equal regardless
    # of the selector c. hi0^lo0 = 0b110011 here (mixed, not all-ones).
    hi0, lo0 = 0b010110, 0b100101  # fixed known "IV" / plaintext-equivalent
    target_hi, target_lo = run_reference(hi0, lo0, real_key, rounds)

    ks = symbols(f'k0:{W}')
    key_bits = list(ks)
    sym_hi, sym_lo = build_symbolic(hi0, lo0, key_bits, rounds)
    target_hi_bits = int_to_bits(target_hi)
    target_lo_bits = int_to_bits(target_lo)

    equations = []
    for i in range(W):
        equations.append(sym_hi[i] - target_hi_bits[i])
        equations.append(sym_lo[i] - target_lo_bits[i])
    # field equations k_i^2 - k_i = 0 enforce Boolean-valued variables (GF(2) ideal membership)
    for k in key_bits:
        equations.append(k**2 - k)

    t0 = time.time()
    try:
        gb = groebner(equations, *key_bits, order='lex', modulus=2)
    except Exception as e:
        return None, time.time() - t0, str(e)
    elapsed = time.time() - t0

    # Brute-force check (trivial at W=6, 64 candidates) of how many key
    # values in {0,1}^W actually satisfy every basis polynomial mod 2 -
    # this tells us whether the ideal has been narrowed to exactly one
    # solution (the real key - a genuine break) or leaves ambiguity.
    solutions = []
    for cand in range(1 << W):
        cand_bits = int_to_bits(cand)
        subs = dict(zip(key_bits, cand_bits))
        if all(int(g.as_expr().subs(subs)) % 2 == 0 for g in gb.polys):
            solutions.append(cand)
    return gb, elapsed, solutions


def main():
    print(f"=== Groebner-basis algebraic attack on real trv_gate/trv_lock_step (W={W}, key-recovery framing) ===")
    print("Tool: sympy groebner() over GF(2), lex order, Buchberger's algorithm - a genuinely distinct")
    print("technique from the earlier Z3/SAT bit-blasting attack (algebraic elimination, not clause search).\n")

    real_key = 0b011010
    for rounds in [1, 2, 3, 4]:
        print(f"--- rounds={rounds} (real key={real_key:0{W}b}) ---", flush=True)
        gb, elapsed, result = attempt_round(rounds, real_key)
        if gb is None:
            print(f"  FAILED after {elapsed:.2f}s: {result}")
            continue
        print(f"  Groebner basis computed in {elapsed:.3f}s, {len(gb.polys)} basis polynomials")
        n_sol = len(result)
        if n_sol == 1 and result[0] == real_key:
            print(f"  Ideal has EXACTLY 1 solution over {{0,1}}^{W}, and it is the real key ({real_key:0{W}b}) - key fully recovered algebraically")
        else:
            print(f"  Ideal has {n_sol} solution(s) over {{0,1}}^{W} consistent with the equations: {[f'{s:0{W}b}' for s in result]} (real key: {real_key:0{W}b})")
        print()

if __name__ == "__main__":
    main()
