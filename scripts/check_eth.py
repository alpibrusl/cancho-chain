#!/usr/bin/env python3
"""lib/eth (addresses, RLP, ERC-20 calldata, type-2 transactions) against eth-account, eth-abi and rlp (docs/design.md section 8.2).

    CANCHO=the-compiler CANCHO_PACKAGES=../cancho/packages python3 -I scripts/check_eth.py [--mutants] [--cases N]
    needs: pip install eth-account coincurve

Builds tools/ethdrv/main.cho with lib/ and secp256k1 from the cancho repository's packages/ (the interim dependency of design.md section 8.1).
--mutants rebuilds with one deliberate fault at a time; every mutant must be killed by the same checks.
"""
import glob, os, random, shutil, subprocess, sys, tempfile
import coincurve, rlp
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.typed_transactions import TypedTransaction
from eth_utils import function_signature_to_4byte_selector, keccak, to_checksum_address

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKGS = os.environ.get("CANCHO_PACKAGES", os.path.join(ROOT, "../cancho/packages"))
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def sources(libdir):
    return (
        [os.path.join(ROOT, "tools/ethdrv/main.cho"), os.path.join(ROOT, "lib/keccak/keccak.cho")]
        + sorted(glob.glob(os.path.join(libdir, "eth/*.cho")))
        + [os.path.join(PKGS, "secp256k1", f) for f in ("secp256k1.cho", "comb.cho", "field.cho", "scalar.cho")]
    )


def build(cancho, libdir, out):
    r = subprocess.run([cancho, "build", "--std", *sources(libdir), "-o", out], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("build failed:\n" + r.stderr)


def call(exe, line):
    out = subprocess.run([exe], input=line.encode(), capture_output=True, timeout=60).stdout.decode().strip()
    parts = out.split()
    return parts[0], parts[1:]


def hexs(b):
    return b.hex() if b else "_"


def be(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


class Checker:
    def __init__(self, exe):
        self.exe, self.bad, self.total = exe, 0, 0

    def check(self, name, got, want):
        self.total += 1
        if got != want:
            self.bad += 1
            if self.bad <= 6:
                print(f"  MISMATCH {name}: got {got} want {want}")


def run(exe, cases):
    c = Checker(exe)
    rng = random.Random(20261106)
    rb = lambda n: bytes(rng.randrange(256) for _ in range(n))

    # ---- addresses
    for spec in ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
                 "0x52908400098527886E0F7030069857D2E4169EE7", "0x8617E340B3D01FA5F11F306F4090FD50E238070D", "0xde709f2102306220921060314715629080e2fb77", "0x27b1fdb04752bbc536007a920d24acb045561c26"):
        rc, out = call(exe, f"P {spec}")
        if spec[2:].isupper() or spec[2:].replace("0", "").isdigit():
            pass
        want = bytes.fromhex(spec[2:]).hex()
        # the EIP-55 test set includes all-caps and all-lower strings: all-caps is refused by design (section 8.1), lower and mixed accepted
        letters = [ch for ch in spec[2:] if ch.isalpha()]
        expect_refused = bool(letters) and all(ch.isupper() for ch in letters)
        c.check(f"parse {spec}", (rc, out), ("E142", []) if expect_refused else ("0", [want]))
        rc, out = call(exe, f"C {spec[2:].lower()}")
        c.check(f"checksum {spec}", (rc, out), ("0", [to_checksum_address(spec)]))
    for _ in range(cases):
        k = rng.randrange(1, N)
        pub = coincurve.PrivateKey(be(k).rjust(32, b"\0")).public_key.format(compressed=False)
        want = Account.from_key(be(k).rjust(32, b"\0")).address
        rc, out = call(exe, f"A {pub.hex()}")
        c.check("address of key", (rc, out), ("0", [want[2:].lower(), want]))
        rc, out = call(exe, f"P {want}")
        c.check("parse checksummed", (rc, out), ("0", [want[2:].lower()]))
        rc, out = call(exe, f"P 0x{want[2:].lower()}")
        c.check("parse lowercase", (rc, out), ("0", [want[2:].lower()]))
        letters = [i for i, ch in enumerate(want) if i >= 2 and ch.isalpha()]
        if letters:
            i = rng.choice(letters)
            flipped = want[:i] + want[i].swapcase() + want[i + 1:]
            mixed = any(ch.isupper() for ch in flipped[2:] if ch.isalpha()) and any(ch.islower() for ch in flipped[2:] if ch.isalpha())
            rc, out = call(exe, f"P {flipped}")
            c.check("parse with one letter's case flipped", rc, "E142" if mixed else "0")
    for name, text, want in (("no prefix", "7E5F4552091A69125d5DfCb7b8C2659029395Bdf", "E140"), ("0X", "0X7E5F4552091A69125d5DfCb7b8C2659029395Bdf", "E140"),
                             ("short", "0x7E5F4552091A69125d5DfCb7b8C2659029395Bd", "E140"), ("long", "0x7E5F4552091A69125d5DfCb7b8C2659029395BdfA", "E140"),
                             ("non-hex", "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdg", "E141"), ("all upper", "0x7E5F4552091A69125D5DFCB7B8C2659029395BDF", "E142"),
                             ("digits only", "0x" + "1" * 40, "0")):
        rc, _ = call(exe, f"P {text}")
        c.check(f"parse refuses {name}", rc, want)
    rc, _ = call(exe, "A 05" + "00" * 64)
    c.check("address refuses a compressed-prefix key", rc, "E144")
    rc, _ = call(exe, "A 04" + "00" * 63)
    c.check("address refuses a short key", rc, "E144")

    # ---- RLP: every length boundary, strings and lists
    for n in (0, 1, 2, 54, 55, 56, 57, 255, 256, 257, 1000):
        item = rb(n)
        if n == 1:
            for b in (0, 1, 0x7F, 0x80, 0xFF):
                item = bytes([b])
                rc, out = call(exe, f"R {hexs(item)}")
                c.check(f"rlp list of one byte {b:02x}", (rc, out), ("0", [rlp.encode([item]).hex()]))
            continue
        rc, out = call(exe, f"R {hexs(item)}")
        c.check(f"rlp list of a {n}-byte string", (rc, out), ("0", [rlp.encode([item]).hex()]))
    for _ in range(cases):
        items = [rb(rng.choice((0, 1, 1, 2, 7, 31, 32, 33, 55, 56, 60))) for _ in range(rng.randrange(1, 9))]
        rc, out = call(exe, "R " + " ".join(hexs(i) for i in items))
        c.check(f"rlp list of {len(items)} strings", (rc, out), ("0", [rlp.encode(items).hex()]))
        v = rng.getrandbits(rng.choice((0, 1, 7, 8, 9, 31, 32, 63, 64, 255, 256)))
        raw = b"\0" * rng.randrange(3) + be(v)
        rc, out = call(exe, f"U {hexs(raw)}")
        c.check(f"rlp uint {v}", (rc, out), ("0", [rlp.encode(v).hex()]))
    rc, out = call(exe, "R " + " ".join(["aa" * 56] * 2))  # a list payload of 114 bytes: long list header
    c.check("rlp long list header", (rc, out), ("0", [rlp.encode([bytes([0xAA] * 56)] * 2).hex()]))
    rc, out = call(exe, "R " + " ".join(["bb" * 255] * 2))  # payload over 255: two-byte length
    c.check("rlp two-byte list length", (rc, out), ("0", [rlp.encode([bytes([0xBB] * 255)] * 2).hex()]))

    # ---- ERC-20 transfer calldata
    sel = function_signature_to_4byte_selector("transfer(address,uint256)")
    for _ in range(cases):
        to = rb(20)
        amount = rng.getrandbits(rng.choice((0, 8, 64, 128, 255, 256)))
        want = sel + abi_encode(["address", "uint256"], [to_checksum_address(to), amount])
        rc, out = call(exe, f"E {to.hex()} {hexs(be(amount))}")
        c.check("erc20 calldata", (rc, out), ("0", [want.hex()]))
    rc, _ = call(exe, f"E {'11' * 19} 01")
    c.check("erc20 refuses a 19-byte recipient", rc, "E161")
    rc, _ = call(exe, f"E {'11' * 20} {'ff' * 33}")
    c.check("erc20 refuses a 33-byte amount", rc, "E160")

    # ---- whole type-2 transactions against eth-account
    for i in range(cases):
        key = rb(32)
        if int.from_bytes(key, "big") % N == 0:
            continue
        chain = rng.choice((1, 11155111, 137, rng.getrandbits(40) + 1))
        nonce = rng.choice((0, 1, 127, 128, rng.getrandbits(32)))
        prio = rng.getrandbits(rng.choice((0, 8, 34, 64, 128)))
        fee = prio + rng.getrandbits(rng.choice((0, 8, 36, 64)))
        gas = rng.choice((21000, 100000, rng.getrandbits(32) + 1))
        to = rb(20)
        value = rng.getrandbits(rng.choice((0, 8, 64, 200, 256)))
        data = rb(rng.choice((0, 4, 68, 68, 100, 200)))
        tx = {"type": 2, "chainId": chain, "nonce": nonce, "maxPriorityFeePerGas": prio, "maxFeePerGas": fee, "gas": gas, "to": to_checksum_address(to), "value": value, "data": data, "accessList": []}
        acct = Account.from_key(key)
        signed = acct.sign_transaction(tx)
        sighash = TypedTransaction.from_dict(tx).hash()
        rc, out = call(exe, f"T {hexs(be(chain))} {hexs(be(nonce))} {hexs(be(prio))} {hexs(be(fee))} {hexs(be(gas))} {to.hex()} {hexs(be(value))} {hexs(data)} {key.hex()}")
        want = ["0", None, sighash.hex(), signed.raw_transaction.hex(), signed.hash.hex()]
        got_ok = rc == "0" and len(out) == 4
        c.check("tx: signing hash", out[1] if got_ok else out, want[2] if got_ok else "four fields")
        if got_ok:
            c.check("tx: signed raw transaction", out[2], want[3])
            c.check("tx: transaction hash", out[3], want[4])
            c.check("tx: unsigned message hashes to the signing hash", keccak(bytes.fromhex(out[0])).hex(), sighash.hex())
            try:
                signer = Account.recover_transaction("0x" + out[2])
            except Exception as e:  # a malformed encoding the oracle cannot even decode
                signer = f"undecodable: {type(e).__name__}"
            c.check("tx: the signer is recovered", signer, acct.address)
    # refusals
    base = f"{hexs(be(1))} {hexs(be(0))} _ _ {hexs(be(21000))}"
    for name, to, value, want in (("19-byte to", "11" * 19, "_", "E170"), ("33-byte value", "11" * 20, "ff" * 33, "E171")):
        rc, _ = call(exe, f"T {base} {to} {value} _")
        c.check(f"tx refuses {name}", rc, want)
    # the signed-message encoder alone, with signatures a signer would not produce
    body = rb(60).hex()
    sig = rb(64)
    for recid, want in ((0, "0"), (1, "0"), (2, "E172"), (255, "E172")):
        rc, _ = call(exe, f"M {body} {(sig + bytes([recid])).hex()}")
        c.check(f"signed message with recovery id {recid}", rc, want)
    rc, _ = call(exe, f"M {body} {sig.hex()}")
    c.check("signed message refuses a 64-byte signature", rc, "E172")
    return c.bad, c.total


MUTANTS = [
    # (name, file, old, new)
    ("rlp: short-header limit 55", "rlp.cho", "if n < 56 {\n        return put(out, pos, base + n);", "if n < 55 {\n        return put(out, pos, base + n);"),
    ("rlp: single byte below 0x80 -> 0x81", "rlp.cho", "int_of(data[0]) < 128 {", "int_of(data[0]) < 129 {"),
    ("rlp: list base 0xc1", "rlp.cho", "return put_header(out, pos, 192, payload_len);", "return put_header(out, pos, 193, payload_len);"),
    ("rlp: long header 0xb8 + w", "rlp.cho", "base + 55 + w", "base + 56 + w"),
    ("rlp: length bytes little-endian", "rlp.cho", "p = put(out, p, n >> (8 * i) & 255);", "p = put(out, p, n >> (8 * (w - 1 - i)) & 255);"),
    ("rlp: leading zeros kept", "rlp.cho", "while at < len(be) && int_of(be[at]) == 0 {", "while at < 0 && int_of(be[at]) == 0 {"),
    ("rlp: put_int single-byte rule", "rlp.cho", "if v > 0 && v < 128 {", "if v > 0 && v < 127 {"),
    ("rlp: integer bytes little-endian", "rlp.cho", "p = put(out, p, v >> (8 * i) & 255);", "p = put(out, p, v >> (8 * (w - 1 - i)) & 255);"),
    ("address: checksum threshold 8 -> 9", "address.cho", "nib >= 8", "nib >= 9"),
    ("address: checksum nibble order", "address.cho", "(4 - 4 * (i % 2))", "(4 * (i % 2))"),
    ("address: last 20 bytes off by one", "address.cho", "out[i] = h[12 + i];", "out[i] = h[11 + i];"),
    ("address: hashes the 0x04 prefix too", "address.cho", "keccak.hash256(st, pubkey[1..65], h)", "keccak.hash256(st, pubkey[0..64], h)"),
    ("address: mixed case not verified", "address.cho", "if upper == 1 && lower == 1 {", "if upper == 1 && lower == 2 {"),
    ("address: all-uppercase accepted", "address.cho", "if upper == 1 && lower == 0 {", "if upper == 2 && lower == 0 {"),
    ("address: 0X accepted", "address.cho", "int_of(text[1]) != 120", "int_of(text[1]) != 120 && int_of(text[1]) != 88"),
    ("address: non-hex accepted", "address.cho", "if code != 0 {\n        return -141;", "if code != 7 {\n        return -141;"),
    ("erc20: selector byte", "erc20.cho", "out[3] = byte_of(0xbb);", "out[3] = byte_of(0xba);"),
    ("erc20: recipient offset", "erc20.cho", "out[16 + i] = to[i];", "out[15 + i] = to[i];"),
    ("erc20: amount not right-aligned", "erc20.cho", "out[68 - len(amount) + i] = amount[i];", "out[36 + i] = amount[i];"),
    ("tx: type byte 1", "tx1559.cho", "out[0] = byte_of(2);\n    var p = rlp.put_list_header(out, 1, len(body_bytes));", "out[0] = byte_of(1);\n    var p = rlp.put_list_header(out, 1, len(body_bytes));"),
    ("tx: access list missing", "tx1559.cho", "p = rlp.put_list_header(out, p, 0);", "p = p + 0;"),
    ("tx: nonce and chain id swapped", "tx1559.cho", "var p = rlp.put_int(out, 0, chain_id);\n    if p >= 0 {\n        p = rlp.put_int(out, p, nonce);", "var p = rlp.put_int(out, 0, nonce);\n    if p >= 0 {\n        p = rlp.put_int(out, p, chain_id);"),
    ("tx: fees swapped", "tx1559.cho", "p = rlp.put_uint(out, p, max_priority);\n    }\n    if p >= 0 {\n        p = rlp.put_uint(out, p, max_fee);", "p = rlp.put_uint(out, p, max_fee);\n    }\n    if p >= 0 {\n        p = rlp.put_uint(out, p, max_priority);"),
    ("tx: value and data swapped", "tx1559.cho", "p = rlp.put_uint(out, p, value);\n    }\n    if p >= 0 {\n        p = rlp.put_bytes(out, p, data);", "p = rlp.put_bytes(out, p, data);\n    }\n    if p >= 0 {\n        p = rlp.put_uint(out, p, value);"),
    ("tx: y parity from the wrong byte", "tx1559.cho", "var t = rlp.put_int(tail, 0, int_of(sig[64]));", "var t = rlp.put_int(tail, 0, 1 - int_of(sig[64]));"),
    ("tx: r and s swapped", "tx1559.cho", "t = rlp.put_uint(tail, t, sig[0..32]);\n        }\n        if t >= 0 {\n            t = rlp.put_uint(tail, t, sig[32..64]);", "t = rlp.put_uint(tail, t, sig[32..64]);\n        }\n        if t >= 0 {\n            t = rlp.put_uint(tail, t, sig[0..32]);"),
    ("tx: recovery id 2 accepted", "tx1559.cho", "int_of(sig[64]) > 1", "int_of(sig[64]) > 2"),
    ("tx: 33-byte value accepted", "tx1559.cho", "len(value) > 32", "len(value) > 33"),
    ("hex: digits uppercase", "hex.cho", "return 87 + v;", "return 55 + v;"),
]


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
            subprocess.run  # build with the mutated lib/eth and the real keccak
            r = subprocess.run([cancho, "build", "--std", os.path.join(ROOT, "tools/ethdrv/main.cho"), os.path.join(ROOT, "lib/keccak/keccak.cho"), *sorted(glob.glob(f"{d}/lib/eth/*.cho")),
                                *[os.path.join(PKGS, "secp256k1", f) for f in ("secp256k1.cho", "comb.cho", "field.cho", "scalar.cho")], "-o", exe], capture_output=True, text=True)
            if r.returncode != 0:
                print(f"mutant '{name}': did not build\n{r.stderr[:300]}")
                survived += 1
                continue
            bad, total = run(exe, cases)
            print(f"mutant '{name}': {'KILLED' if bad else 'SURVIVED'} ({bad}/{total})")
            survived += 0 if bad else 1
        finally:
            shutil.rmtree(d)
    return survived


def main():
    cancho = os.environ.get("CANCHO", "cancho")
    cases = int(sys.argv[sys.argv.index("--cases") + 1]) if "--cases" in sys.argv else 40
    d = tempfile.mkdtemp()
    try:
        exe = os.path.join(d, "eth")
        build(cancho, os.path.join(ROOT, "lib"), exe)
        bad, total = run(exe, cases)
        print(f"eth: {total - bad}/{total} checks agree with eth-account, eth-abi and rlp")
        if bad:
            sys.exit(1)
        if "--mutants" in sys.argv:
            s = mutants(cancho, max(6, cases // 5))
            print(f"mutants: {len(MUTANTS) - s}/{len(MUTANTS)} killed")
            if s:
                sys.exit(1)
    finally:
        shutil.rmtree(d)


main()
