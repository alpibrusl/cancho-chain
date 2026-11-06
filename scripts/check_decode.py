#!/usr/bin/env python3
"""The strict RLP decoder and the final-transaction validator against rlp (strict mode) and eth-account (docs/design.md section 9.3).

    CANCHO=the-compiler CANCHO_PACKAGES=../cancho/packages python3 -I scripts/check_decode.py [--mutants] [--cases N]
    needs: pip install eth-account

(1) accept/reject agreement with `rlp.decode(strict=True)` on random bytes, on every kind of one-byte damage to valid encodings and on the length boundaries;
(2) every valid ERC-20 transfer eth-account signs validates, unsigned and signed; (3) for each reason code, a transaction tampered in exactly that field is refused with exactly that code;
(4) malformed encodings are `tx-format` / `tx-type`. --mutants: one deliberate fault at a time in lib/eth/rlp.cho and lib/eth/txcheck.cho; every one must be killed.
"""
import glob, os, random, shutil, subprocess, sys, tempfile
import rlp
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_utils import function_signature_to_4byte_selector, to_checksum_address

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKGS = os.environ.get("CANCHO_PACKAGES", os.path.join(ROOT, "../cancho/packages"))
SEL = function_signature_to_4byte_selector("transfer(address,uint256)")


def srcs(libdir):
    return ([os.path.join(ROOT, "tools/ethdrv/main.cho"), os.path.join(ROOT, "lib/keccak/keccak.cho")] + sorted(glob.glob(os.path.join(libdir, "eth/*.cho")))
            + [os.path.join(PKGS, "secp256k1", f) for f in ("secp256k1.cho", "comb.cho", "field.cho", "scalar.cho")])


def build(cancho, libdir, out):
    r = subprocess.run([cancho, "build", "--std", *srcs(libdir), "-o", out], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("build failed:\n" + r.stderr)


def call(exe, line):
    out = subprocess.run([exe], input=line.encode(), capture_output=True, timeout=60).stdout.decode().split()
    return out[0] if out else "CRASH"  # a trap prints nothing: a mutant that makes the program trap is caught


def be(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def hx(b):
    return b.hex() if b else "_"


class Tx:
    """An authorised ERC-20 transfer, and the expectation that matches it."""

    def __init__(self, rng):
        self.chain = rng.choice((1, 11155111, 137, rng.getrandbits(40) + 1))
        self.nonce = rng.choice((0, 1, 127, 128, rng.getrandbits(32)))
        self.prio = rng.getrandbits(rng.choice((0, 8, 34, 64)))
        self.fee = self.prio + rng.getrandbits(rng.choice((0, 8, 36, 64)))
        self.gas = rng.choice((21000, 65000, rng.getrandbits(32) + 1))
        self.token = bytes(rng.randrange(256) for _ in range(20))
        self.recipient = bytes(rng.randrange(256) for _ in range(20))
        self.amount = rng.getrandbits(rng.choice((0, 8, 64, 128, 255, 256)))
        self.value = 0
        self.data = SEL + abi_encode(["address", "uint256"], [to_checksum_address(self.recipient), self.amount])
        self.to = self.token
        self.access = []
        self.fee_cap = self.fee + rng.getrandbits(8)
        self.gas_cap = self.gas + rng.getrandbits(8)

    def fields(self):
        return [self.chain, self.nonce, self.prio, self.fee, self.gas, self.to, self.value, self.data, self.access]

    def unsigned(self):
        return b"\x02" + rlp.encode(self.fields())

    def signed(self, key):
        d = {"type": 2, "chainId": self.chain, "nonce": self.nonce, "maxPriorityFeePerGas": self.prio, "maxFeePerGas": self.fee, "gas": self.gas,
             "to": to_checksum_address(self.to), "value": self.value, "data": self.data,
             "accessList": [{"address": to_checksum_address(a), "storageKeys": []} for a, _ in self.access]}
        return bytes(Account.from_key(key).sign_transaction(d).raw_transaction)

    def expect(self, amount_bytes=None):
        amount = be(self.amount) if amount_bytes is None else amount_bytes
        return f"{hx(be(self.chain))} {hx(be(self.nonce))} {self.token.hex()} {self.recipient.hex()} {hx(amount)} {hx(be(self.fee_cap))} {hx(be(self.gas_cap))}"


def validate(exe, raw, exp, signed=False):
    return call(exe, f"{'W' if signed else 'V'} {raw.hex() if raw else '_'} {exp}")


def random_item(rng, depth=0):
    if depth < 3 and rng.random() < 0.3:
        return [random_item(rng, depth + 1) for _ in range(rng.randrange(0, 5))]
    return bytes(rng.randrange(256) for _ in range(rng.choice((0, 1, 1, 2, 3, 20, 55, 56, 57, 100, 300))))


def agrees(exe, data):
    rc = call(exe, f"D {data.hex() if data else '_'}")
    if rc == "CRASH":
        return None, True  # the program trapped: never agreement, whatever rlp says
    ours = rc == "0"
    try:
        rlp.decode(data, strict=True)
        theirs = True
    except Exception:
        theirs = False
    return ours, theirs


def run(exe, cases):
    bad = total = 0

    def check(name, got, want):
        nonlocal bad, total
        total += 1
        if got != want:
            bad += 1
            if bad <= 8:
                print(f"  MISMATCH {name}: got {got} want {want}")

    rng = random.Random(20261106)
    # ---- (1) decoder agreement
    pool = [rlp.encode(random_item(rng)) for _ in range(cases)]
    for i, enc in enumerate(pool):
        o, t = agrees(exe, enc)
        check(f"valid encoding #{i}", o, True)
        mutations = [enc[:-1] if enc else enc, enc + b"\x00", enc + enc[:1]]
        if enc:
            k = rng.randrange(len(enc))
            mutations.append(enc[:k] + bytes([rng.randrange(256)]) + enc[k + 1:])
            mutations.append(enc[:k] + enc[k + 1:])
            mutations.append(enc[:k] + bytes([rng.randrange(256)]) + enc[k:])
        for m in mutations:
            o, t = agrees(exe, m)
            check(f"damaged encoding {m[:12].hex()}", o, t)
    for _ in range(cases * 2):
        b = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 12)))
        o, t = agrees(exe, b)
        check(f"random bytes {b.hex()}", o, t)
    for enc in ("", "00", "7f", "80", "8100", "817f", "8180", "81ff", "b800", "b80136", "b8380000", "b838" + "11" * 56, "b8" + "38" + "11" * 55, "b837" + "11" * 55, "f837" + "c0" * 55, "b836" + "11" * 54, "b839" + "11" * 57, "b90038" + "11" * 56, "b9003811", "c0", "c100", "c180", "f800",
                "f83800", "f838" + "c0" * 56, "f90038" + "c0" * 56, "bf" + "00" * 8, "bf" + "01" + "00" * 7, "bfffffffffffffffff", "f8ff" + "00" * 3, "c2c0c0", "c3c0c0", "c1c0", "c2c0"):
        b = bytes.fromhex(enc)
        o, t = agrees(exe, b)
        check(f"boundary {enc[:20]}", o, t)

    # the reason of a refusal, which `rlp` cannot give (each is the code the decoder is documented to answer)
    for enc, want in (("", "E152"), ("80", "0"), ("81", "E152"), ("8200", "E152"), ("c1", "E152"), ("b8", "E152"), ("b838" + "11" * 55, "E152"), ("f8", "E152"), ("f800", "E153"), ("8101", "E153"),
                      ("b800", "E153"), ("b90001", "E153"), ("b837" + "11" * 55, "E153"), ("bf0100000000000000", "E154"), ("bf0000000000000001", "E154"), ("ff0100000000000000", "E154"),
                      ("c0c0", "E155"), ("8000", "E155"), ("c2c0", "E152"), ("c3c0c0", "E152")):
        check(f"decode reason of {enc[:24]}", call(exe, f"D {enc if enc else '_'}"), want)

    # ---- (2) and (3) the validator
    key = rng.getrandbits(255).to_bytes(32, "big")
    for i in range(cases):
        tx = Tx(rng)
        exp = tx.expect()
        check("valid unsigned", validate(exe, tx.unsigned(), exp), "0")
        check("valid signed", validate(exe, tx.signed(key), exp, True), "0")
        # our own encoder and signer's output, through our own validator
        out = subprocess.run([exe], input=f"T {hx(be(tx.chain))} {hx(be(tx.nonce))} {hx(be(tx.prio))} {hx(be(tx.fee))} {hx(be(tx.gas))} {tx.to.hex()} _ {tx.data.hex()} {key.hex()}".encode(), capture_output=True).stdout.decode().split()
        if len(out) == 5:
            check("our unsigned message validates", validate(exe, bytes.fromhex(out[1]), exp), "0")
            check("our signed transaction validates", validate(exe, bytes.fromhex(out[3]), exp, True), "0")
        else:
            check("our encoder produced a transaction", out, "five fields")
        # a leading-zero amount in the expectation is the same number
        check("amount padded to 32 bytes with leading zeros", validate(exe, tx.unsigned(), tx.expect(be(tx.amount).rjust(32, b"\0"))), "0")
        base = Tx(rng)
        def tampered(mut, signed=False, **over):
            t = Tx(rng)
            t.__dict__.update(base.__dict__)
            t.data = SEL + abi_encode(["address", "uint256"], [to_checksum_address(t.recipient), t.amount])
            t.__dict__.update(over)
            if mut:
                mut(t)
            return t.signed(key) if signed else t.unsigned()
        e = base.expect()
        cases_ = [
            ("chain id", lambda t: setattr(t, "chain", t.chain + 1), "E182"),
            ("nonce", lambda t: setattr(t, "nonce", t.nonce + 1), "E183"),
            ("to", lambda t: setattr(t, "to", bytes([t.to[0] ^ 1]) + t.to[1:]), "E184"),
            ("to empty", lambda t: setattr(t, "to", b""), "E184"),
            ("value", lambda t: setattr(t, "value", 1), "E185"),
            ("data short", lambda t: setattr(t, "data", t.data[:-1]), "E186"),
            ("data long", lambda t: setattr(t, "data", t.data + b"\0"), "E186"),
            ("selector", lambda t: setattr(t, "data", b"\x09" + t.data[1:]), "E187"),
            ("padding", lambda t: setattr(t, "data", t.data[:10] + b"\x01" + t.data[11:]), "E188"),
            ("recipient", lambda t: setattr(t, "data", t.data[:35] + bytes([t.data[35] ^ 1]) + t.data[36:]), "E189"),
            ("amount", lambda t: setattr(t, "data", t.data[:67] + bytes([t.data[67] ^ 1])), "E190"),
            ("amount high byte", lambda t: setattr(t, "data", t.data[:36] + bytes([t.data[36] ^ 0x80]) + t.data[37:]), "E190"),
            ("access list", lambda t: setattr(t, "access", [[b"\x11" * 20, []]]), "E191"),
        ]
        for name, mut, want in cases_:
            check(f"tampered {name} (unsigned)", validate(exe, tampered(mut), e), want)
            if name not in ("to empty",):
                check(f"tampered {name} (signed)", validate(exe, tampered(mut, True), e, True), want)
        # caps and ordering
        check("fee above the cap", validate(exe, tampered(None), e.rsplit(" ", 2)[0] + f" {hx(be(max(base.fee - 1, 0)))} {hx(be(base.gas_cap))}") if base.fee > 0 else "E192", "E192")
        check("gas above the cap", validate(exe, tampered(None), e.rsplit(" ", 1)[0] + f" {hx(be(max(base.gas - 1, 0)))}"), "E193")
        check("priority above max fee", validate(exe, tampered(lambda t: setattr(t, "prio", t.fee + 1)), e), "E194")
        # the first failure answers: chain id before nonce before to
        check("two faults: the first in the table", validate(exe, tampered(lambda t: (setattr(t, "chain", t.chain + 1), setattr(t, "nonce", t.nonce + 1))), e), "E182")
        check("two faults: nonce then value", validate(exe, tampered(lambda t: (setattr(t, "nonce", t.nonce + 1), setattr(t, "value", 5))), e), "E183")
    # caps are inclusive; a token that starts with a zero byte; padding at its first and last byte; many items; an outer string
    t2 = Tx(rng)
    t2.fee_cap, t2.gas_cap = t2.fee, t2.gas
    check("fee equal to its cap and gas equal to its cap", validate(exe, t2.unsigned(), t2.expect()), "0")
    t3 = Tx(rng)
    t3.token = b"\0" + t3.token[1:]
    t3.to = t3.token
    check("a token starting with a zero byte", validate(exe, t3.unsigned(), t3.expect()), "0")
    short = Tx(rng)
    short.__dict__.update(t3.__dict__)
    short.to = t3.token[1:]
    check("a 19-byte `to` equal to the token without its zero byte", validate(exe, short.unsigned(), t3.expect()), "E184")
    for at in (4, 15):
        tp = Tx(rng)
        tp.data = tp.data[:at] + b"\x01" + tp.data[at + 1:]
        check(f"recipient padding nonzero at byte {at}", validate(exe, tp.unsigned(), tp.expect()), "E188")
    tr = Tx(rng)
    tr.data = tr.data[:16] + bytes([tr.data[16] ^ 1]) + tr.data[17:]
    check("recipient differs in its first byte", validate(exe, tr.unsigned(), tr.expect()), "E189")
    tr.data = tr.data[:16] + bytes([tr.data[16] ^ 1]) + tr.data[17:35] + bytes([tr.data[35] ^ 1]) + tr.data[36:]
    check("recipient differs in its last byte", validate(exe, tr.unsigned(), tr.expect()), "E189")
    tf = Tx(rng)
    ff = tf.fields()
    check("20 items", validate(exe, b"\x02" + rlp.encode(ff + [1] * 11), tf.expect()), "E180")
    check("an outer string holding the nine items", validate(exe, b"\x02" + rlp.encode(b"".join(rlp.encode(x) for x in ff)), tf.expect()), "E180")
    check("an outer string holding twelve items, signed", validate(exe, b"\x02" + rlp.encode(b"".join(rlp.encode(x) for x in ff + [1, 5, 6])), tf.expect(), True), "E180")
    # field widths and the 2^63 edge
    t = Tx(rng)
    e = t.expect()
    big = 2**63 + 5
    for name, over, want in (("chain id of 2^63 + 5", {"chain": big}, "E182"), ("nonce of 2^63 + 5", {"nonce": big}, "E183"), ("gas of 2^63 + 5", {"gas": big}, "E193"),
                             ("chain id of 9 bytes", {"chain": 2**64}, "E180"), ("nonce of 9 bytes", {"nonce": 2**64}, "E180"), ("gas of 9 bytes", {"gas": 2**64}, "E180")):
        tt = Tx(rng)
        tt.__dict__.update(t.__dict__)
        tt.__dict__.update(over)
        check(name, validate(exe, tt.unsigned(), e), want)
    # signature fields
    f = t.fields()
    for name, tail, want in (("y parity 2", [2, 1, 1], "E195"), ("y parity 255", [255, 1, 1], "E195"), ("r zero", [0, 0, 1], "E195"), ("s zero", [0, 1, 0], "E195"), ("r of 33 bytes", [0, 2**256, 1], "E195"),
                             ("s of 33 bytes", [0, 1, 2**256], "E195"), ("valid", [1, 2**255 + 7, 2**254 + 9], "0"), ("r with a leading zero", [0, b"\x00\x05", 1], "E195"),
                             ("y parity as a list", [[], 1, 1], "E195")):
        check(f"signature: {name}", validate(exe, b"\x02" + rlp.encode(f + tail), e, True), want)
    # malformed encodings
    ok = t.unsigned()
    okf = b"\x02" + rlp.encode(f + [1, 5, 6])
    mal = [("empty", b"", "E180", False), ("one byte", b"\x02", "E180", False), ("type 1", b"\x01" + ok[1:], "E181", False), ("type 3", b"\x03" + ok[1:], "E181", False),
           ("type 0x7f", b"\x7f" + ok[1:], "E181", False), ("legacy list", rlp.encode(f), "E181", False), ("truncated", ok[:-1], "E180", False), ("trailing byte", ok + b"\0", "E180", False),
           ("8 items", b"\x02" + rlp.encode(f[:8]), "E180", False), ("10 items", b"\x02" + rlp.encode(f + [1]), "E180", False), ("signed expected, unsigned given", ok, "E180", True),
           ("unsigned expected, signed given", okf, "E180", False), ("13 items", b"\x02" + rlp.encode(f + [1, 5, 6, 7]), "E180", True), ("to as a list", b"\x02" + rlp.encode(f[:5] + [[]] + f[6:]), "E180", False),
           ("data as a list", b"\x02" + rlp.encode(f[:7] + [[]] + f[8:]), "E180", False), ("access list as a string", b"\x02" + rlp.encode(f[:8] + [b""]), "E180", False),
           ("chain id as a list", b"\x02" + rlp.encode([[]] + f[1:]), "E180", False), ("nonce with a leading zero", b"\x02" + rlp.encode(f[:1] + [b"\x00\x01"] + f[2:]), "E180", False),
           ("fee with a leading zero", b"\x02" + rlp.encode(f[:3] + [b"\x00" + be(t.fee)] + f[4:]), "E180", False), ("value of 33 bytes", b"\x02" + rlp.encode(f[:6] + [b"\x01" * 33] + f[7:]), "E180", False),
           ("payload shorter than its header", b"\x02\xf8\x05" + ok[3:], "E180", False), ("list inside a list header lie", b"\x02" + bytes([0xC0 + 3]) + ok[2:], "E180", False)]
    for name, raw, want, signed in mal:
        check(f"malformed: {name}", validate(exe, raw, e, signed), want)
    # a bad expectation is the caller's fault, not the transaction's
    check("expectation: token of 19 bytes", call(exe, f"V {ok.hex()} {hx(be(t.chain))} {hx(be(t.nonce))} {t.token.hex()[:-2]} {t.recipient.hex()} _ _ _"), "E196")
    check("expectation: recipient of 21 bytes", call(exe, f"V {ok.hex()} {hx(be(t.chain))} {hx(be(t.nonce))} {t.token.hex()} {t.recipient.hex()}00 _ _ _"), "E196")
    return bad, total


# (name, file, old, new)
MUTANTS = [
    ("decode: short string limit 184 -> 185", "rlp.cho", "if b < 184 || b >= 192 && b < 248 {", "if b < 185 || b >= 192 && b < 248 {"),
    ("decode: short list limit 248 -> 249", "rlp.cho", "b >= 192 && b < 248 {", "b >= 192 && b < 249 {"),
    ("decode: one byte below 0x80 with a header accepted", "rlp.cho", "int_of(data[start]) < 128 && b < 184 {", "int_of(data[start]) < 127 && b < 184 {"),
    ("decode: leading zero in a length accepted", "rlp.cho", "if int_of(data[pos + 1]) == 0 {\n            return -153;", "if int_of(data[pos + 1]) == 99 {\n            return -153;"),
    ("decode: long form for a length under 56 accepted", "rlp.cho", "if n < 56 {\n            return -153;", "if n < 55 {\n            return -153;"),
    ("decode: lengths of 8 bytes accepted", "rlp.cho", "if w > 7 {", "if w > 8 {"),
    ("decode: truncation check off by one", "rlp.cho", "if n > end - start {", "if n > end - start + 1 {"),
    ("decode: length bytes past the end", "rlp.cho", "if pos + 1 + w > end {", "if pos + 1 + w > end + 1 {"),
    ("decode: trailing bytes accepted", "rlp.cho", "if next != len(data) {\n        return -155;", "if next > len(data) {\n        return -155;"),
    ("decode: empty input accepted", "rlp.cho", "    if pos >= end {\n        return -152;\n    }", "    if pos > end {\n        return -152;\n    }"),
    ("txcheck: type byte", "txcheck.cho", "if int_of(raw[0]) != 2 {", "if int_of(raw[0]) != 3 {"),
    ("txcheck: trailing bytes after the list", "txcheck.cho", "if next < 0 || m[0] != 1 || next != len(raw) {", "if next < 0 || m[0] != 1 {"),
    ("txcheck: the outer item need not be a list", "txcheck.cho", "if next < 0 || m[0] != 1 || next != len(raw) {", "if next < 0 || next != len(raw) {"),
    ("txcheck: 13 items accepted", "txcheck.cho", "if count >= 12 {", "if count >= 13 {"),
    ("txcheck: item count not checked", "txcheck.cho", "} else if n != want {", "} else if n < 0 {"),
    ("txcheck: chain id width 8 -> 9", "txcheck.cho", "!is_uint(raw, f, 0, 8)", "!is_uint(raw, f, 0, 9)"),
    ("txcheck: nonce width 8 -> 9", "txcheck.cho", "!is_uint(raw, f, 1, 8)", "!is_uint(raw, f, 1, 9)"),
    ("txcheck: gas width 8 -> 9", "txcheck.cho", "!is_uint(raw, f, 4, 8)", "!is_uint(raw, f, 4, 9)"),
    ("txcheck: value width 32 -> 33", "txcheck.cho", "!is_uint(raw, f, 6, 32)", "!is_uint(raw, f, 6, 33)"),
    ("txcheck: leading zeros in integers accepted", "txcheck.cho", "if n > 0 && int_of(raw[f[3 * k + 1]]) == 0 {", "if n > 0 && int_of(raw[f[3 * k + 1]]) == 99 {"),
    ("txcheck: integers may be lists", "txcheck.cho", "    if f[3 * k] != 0 {\n        return false;\n    }\n    let n =", "    if f[3 * k] != 7 {\n        return false;\n    }\n    let n ="),
    ("txcheck: to may be a list", "txcheck.cho", "if f[15] != 0 || f[21] != 0 || f[24] != 1 {", "if f[21] != 0 || f[24] != 1 {"),
    ("txcheck: data may be a list", "txcheck.cho", "if f[15] != 0 || f[21] != 0 || f[24] != 1 {", "if f[15] != 0 || f[24] != 1 {"),
    ("txcheck: the access list may be a string", "txcheck.cho", "if f[15] != 0 || f[21] != 0 || f[24] != 1 {", "if f[15] != 0 || f[21] != 0 {"),
    ("txcheck: equals_int ignores the 2^63 edge", "txcheck.cho", "    if len(p) == 8 && int_of(p[0]) >= 128 {\n        return false;\n    }", "    if len(p) == 8 && int_of(p[0]) >= 255 {\n        return false;\n    }"),
    ("txcheck: above_int ignores the 2^63 edge", "txcheck.cho", "    if len(p) == 8 && int_of(p[0]) >= 128 {\n        return true;\n    }", "    if len(p) == 8 && int_of(p[0]) >= 255 {\n        return true;\n    }"),
    ("txcheck: chain id not compared", "txcheck.cho", "if equals_int(raw, f, 0, chain_id) == false {", "if false {"),
    ("txcheck: nonce not compared", "txcheck.cho", "if equals_int(raw, f, 1, nonce) == false {", "if false {"),
    ("txcheck: to compared with a prefix", "txcheck.cho", "if cmp_uint(to, token) != 0 || len(to) != 20 {", "if cmp_uint(to, token) != 0 {"),
    ("txcheck: to not compared", "txcheck.cho", "if cmp_uint(to, token) != 0 || len(to) != 20 {", "if len(to) != 20 {"),
    ("txcheck: value ignored", "txcheck.cho", "if len(payload(raw, f, 6)) != 0 {", "if len(payload(raw, f, 6)) > 33 {"),
    ("txcheck: data length 68 -> 100", "txcheck.cho", "if len(data) != 68 {", "if len(data) < 68 {"),
    ("txcheck: selector byte 0", "txcheck.cho", "if int_of(data[0]) != 0xa9 ||", "if int_of(data[0]) != 0xa8 ||"),
    ("txcheck: selector byte 3", "txcheck.cho", "int_of(data[3]) != 0xbb {", "int_of(data[3]) != 0xba {"),
    ("txcheck: padding checked to 15 only", "txcheck.cho", "while i < 16 {\n        if int_of(data[i]) != 0 {", "while i < 15 {\n        if int_of(data[i]) != 0 {"),
    ("txcheck: padding from byte 5", "txcheck.cho", "var i = 4;\n    while i < 16 {", "var i = 5;\n    while i < 16 {"),
    ("txcheck: last recipient byte unchecked", "txcheck.cho", "i = 0;\n    while i < 20 {\n        if int_of(data[16 + i]) != int_of(recipient[i]) {", "i = 0;\n    while i < 19 {\n        if int_of(data[16 + i]) != int_of(recipient[i]) {"),
    ("txcheck: amount not compared", "txcheck.cho", "if cmp_uint(data[36..68], amount) != 0 {", "if cmp_uint(data[36..68], amount) > 1 {"),
    ("txcheck: amount only 'not below'", "txcheck.cho", "if cmp_uint(data[36..68], amount) != 0 {", "if cmp_uint(data[36..68], amount) < 0 {"),
    ("txcheck: access list may be non-empty", "txcheck.cho", "if f[3 * 8 + 2] != f[3 * 8 + 1] {", "if f[3 * 8 + 2] < f[3 * 8 + 1] {"),
    ("txcheck: fee cap is exclusive", "txcheck.cho", "if cmp_uint(payload(raw, f, 3), fee_cap) > 0 {", "if cmp_uint(payload(raw, f, 3), fee_cap) >= 0 {"),
    ("txcheck: fee cap ignored", "txcheck.cho", "if cmp_uint(payload(raw, f, 3), fee_cap) > 0 {", "if cmp_uint(payload(raw, f, 3), fee_cap) > 5 {"),
    ("txcheck: gas cap ignored", "txcheck.cho", "if above_int(raw, f, 4, gas_cap) {", "if above_int(raw, f, 4, gas_cap + 100000) {"),
    ("txcheck: fee order not checked", "txcheck.cho", "if cmp_uint(payload(raw, f, 2), payload(raw, f, 3)) > 0 {", "if cmp_uint(payload(raw, f, 2), payload(raw, f, 3)) > 5 {"),
    ("txcheck: y parity unchecked", "txcheck.cho", "if len(payload(raw, f, 9)) == 1 && int_of(payload(raw, f, 9)[0]) > 1 {", "if len(payload(raw, f, 9)) == 1 && int_of(payload(raw, f, 9)[0]) > 200 {"),
    ("txcheck: r may be zero", "txcheck.cho", "if len(payload(raw, f, 10)) == 0 || len(payload(raw, f, 11)) == 0 {", "if len(payload(raw, f, 11)) == 0 {"),
    ("txcheck: s may be zero", "txcheck.cho", "if len(payload(raw, f, 10)) == 0 || len(payload(raw, f, 11)) == 0 {", "if len(payload(raw, f, 10)) == 0 {"),
    ("txcheck: r width 32 -> 33", "txcheck.cho", "!is_uint(raw, f, 10, 32)", "!is_uint(raw, f, 10, 33)"),
    ("txcheck: cmp_uint keeps leading zeros", "txcheck.cho", "while i < len(a) && int_of(a[i]) == 0 {", "while i < 0 && int_of(a[i]) == 0 {"),
    ("txcheck: cmp_uint compares lengths wrongly", "txcheck.cho", "if la < lb {\n        return -1;\n    }\n    if la > lb {\n        return 1;\n    }", "if la < lb {\n        return 1;\n    }\n    if la > lb {\n        return -1;\n    }"),
    ("txcheck: expectation sizes unchecked", "txcheck.cho", "if len(token) != 20 || len(recipient) != 20 ||", "if len(token) != 21 || len(recipient) != 21 ||"),
]


# Mutants no input can kill, with the reason. Reported, not failed: a survivor outside this list fails the run.
EXPECTED_SURVIVORS = {
    "txcheck: 13 items accepted": "equivalent: the bound only keeps the 48-word field table in range, the item count is compared afterwards, so a 13th item is stored and then refused as tx-format all the same",
}


def mutants(cancho, cases):
    survived = 0
    for name, fname, old, new in MUTANTS:
        d = tempfile.mkdtemp()
        try:
            os.makedirs(f"{d}/lib")
            shutil.copytree(os.path.join(ROOT, "lib/eth"), f"{d}/lib/eth")
            p = f"{d}/lib/eth/{fname}"
            text = open(p).read()
            if text.count(old) != 1:
                raise SystemExit(f"mutant pattern not unique ({text.count(old)}): {name}")
            open(p, "w").write(text.replace(old, new))
            exe = f"{d}/eth"
            r = subprocess.run([cancho, "build", "--std", *srcs(f"{d}/lib"), "-o", exe], capture_output=True, text=True)
            if r.returncode != 0:
                print(f"mutant '{name}': did not build\n{r.stderr[:300]}")
                survived += 1
                continue
            bad, total = run(exe, cases)
            if not bad and name in EXPECTED_SURVIVORS:
                print(f"mutant '{name}': SURVIVED, expected: {EXPECTED_SURVIVORS[name]}")
                continue
            print(f"mutant '{name}': {'KILLED' if bad else 'SURVIVED'} ({bad}/{total})")
            survived += 0 if bad else 1
        finally:
            shutil.rmtree(d)
    return survived


def main():
    cancho = os.environ.get("CANCHO", "cancho")
    cases = int(sys.argv[sys.argv.index("--cases") + 1]) if "--cases" in sys.argv else 30
    d = tempfile.mkdtemp()
    try:
        exe = os.path.join(d, "eth")
        build(cancho, os.path.join(ROOT, "lib"), exe)
        bad, total = run(exe, cases)
        print(f"decode: {total - bad}/{total} checks agree with rlp (strict) and eth-account")
        if bad:
            sys.exit(1)
        if "--mutants" in sys.argv:
            s = mutants(cancho, max(6, cases // 4))
            print(f"mutants: {len(MUTANTS) - s - len(EXPECTED_SURVIVORS)}/{len(MUTANTS)} killed, {len(EXPECTED_SURVIVORS)} equivalent (above), {s} unexpected survivors")
            if s:
                sys.exit(1)
    finally:
        shutil.rmtree(d)


main()
