#!/usr/bin/env python3
"""Keccak-256 of lib/keccak/keccak.cho against pycryptodome, bit for bit (docs/design.md section 4).

    CHAIN=build/chain python3 scripts/check_keccak.py [--mutants]       # --mutants needs CANCHO=the compiler

Every length 0..420 (the rate is 136, so this crosses the 135/136/137, 271/272/273 and 407/408/409 edges), a few long inputs, and
random bytes. --mutants rebuilds the program with one deliberate fault at a time; every mutant must be killed by this same check.
"""
import os, random, shutil, subprocess, sys, tempfile
from Crypto.Hash import keccak

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "lib/keccak/keccak.cho")


def oracle(m):
    return keccak.new(digest_bits=256, data=m).hexdigest()


def cases():
    rng = random.Random(20261106)
    for n in range(0, 421):
        yield bytes(rng.randrange(256) for _ in range(n))
    yield bytes(1000)
    yield bytes([0xff]) * 1000
    for n in (4096, 65537):
        yield bytes(rng.randrange(256) for _ in range(n))


def run(exe):
    bad = total = 0
    for m in cases():
        total += 1
        got = subprocess.run([exe], input=m, capture_output=True, timeout=60).stdout.decode().strip()
        if got != oracle(m):
            bad += 1
            if bad <= 3:
                print(f"  MISMATCH len={len(m)} got={got} want={oracle(m)}")
    return bad, total


MUTANTS = [
    ("SHA-3 padding 0x06 instead of Keccak 0x01", "xor_byte(st, rest, 0x01);", "xor_byte(st, rest, 0x06);"),
    ("no final 0x80 bit", "xor_byte(st, rate - 1, 0x80);", "xor_byte(st, rate - 1, 0x00);"),
    ("rate 135", "let rate = 136;", "let rate = 135;"),
    ("rho offset of lane 1 changed", "t[0] = 0; t[1] = 1;", "t[0] = 0; t[1] = 2;"),
    ("round constant 1 changed", "t[1] = 0x00008082;", "t[1] = 0x00008083;"),
    ("round constant 2 high word", "t[2] = 0x80000000; t[3] = 0x80000000;", "t[2] = 0x00000000; t[3] = 0x80000000;"),
    ("theta rotates by 2", "st[101 + 2 * right], st[100 + 2 * right], 1);\n            let dhi", "st[101 + 2 * right], st[100 + 2 * right], 2);\n            let dhi"),
    ("chi without the complement", "(st[50 + 2 * b] ^ 0xffffffff)", "(st[50 + 2 * b])"),
    ("iota skipped", "st[0] = st[0] ^ round_lo[round];", "st[0] = st[0];"),
    ("23 rounds", "while round < 24 {", "while round < 23 {"),
    ("pi uses 2x+2y", "(2 * x + 3 * y) % 5", "(2 * x + 2 * y) % 5"),
    ("odd lanes land in lo", "if within < 4 {\n        st[2 * lane] = st[2 * lane] ^ v", "if within < 5 {\n        st[2 * lane] = st[2 * lane] ^ v"),
]


def mutants():
    cancho = os.environ.get("CANCHO", "cancho")
    text = open(SRC).read()
    survived = 0
    for name, old, new in MUTANTS:
        assert text.count(old) == 1, f"mutant pattern not unique: {name}"
        d = tempfile.mkdtemp()
        try:
            os.makedirs(f"{d}/lib/keccak"); os.makedirs(f"{d}/tools")
            open(f"{d}/lib/keccak/keccak.cho", "w").write(text.replace(old, new))
            shutil.copytree(f"{ROOT}/tools/chain", f"{d}/tools/chain")
            shutil.copy(f"{ROOT}/cancho.toml", d)
            r = subprocess.run([cancho, "build", "--bin", "chain"], cwd=d, capture_output=True, text=True)
            if r.returncode != 0:
                print(f"mutant '{name}': did not build\n{r.stderr}")
                survived += 1
                continue
            bad, total = run(f"{d}/build/chain")
            print(f"mutant '{name}': {'KILLED' if bad else 'SURVIVED'} ({bad}/{total} mismatches)")
            survived += 0 if bad else 1
        finally:
            shutil.rmtree(d)
    return survived


def main():
    exe = os.environ.get("CHAIN", os.path.join(ROOT, "build/chain"))
    bad, total = run(exe)
    print(f"keccak256: {total - bad}/{total} agree with pycryptodome")
    if bad:
        sys.exit(1)
    if "--mutants" in sys.argv:
        s = mutants()
        print(f"mutants: {len(MUTANTS) - s}/{len(MUTANTS)} killed")
        if s:
            sys.exit(1)


main()
