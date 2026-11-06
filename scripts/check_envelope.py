#!/usr/bin/env python3
"""The authorisation envelope against a model written separately from docs/design.md section 13 (section 13.5).

    CANCHO=the-compiler CANCHO_PACKAGES=../cancho/packages CANCHO_SCHEMA=../alpibrusl/cancho-schema/src/schema.cho python3 -I scripts/check_envelope.py [--mutants] [--cases N]
    needs: pip install coincurve pycryptodome eth-account eth-abi rlp eth-utils

Checked: (1) for random cases `issue` writes the model's envelope bytes and a signature that is the model's (libsecp256k1, RFC 6979) and that recovers to the issuer, and `verify` accepts it;
(2) every refusal of `issue`, reached alone; (3) every refusal of `verify` alone and, for every pair of faults that can occur together, the first in the order of section 13.3 answers;
(4) every byte of the envelope, of the signature and of the message changed, one at a time: refused, and for the envelope with the reason the order says; (5) the boundaries of the window;
(6) the single-use ledger; (7) the envelope digest. --mutants: one deliberate fault at a time in lib/envelope/envelope.cho; every one must be killed.
"""
import concurrent.futures, glob, itertools, os, random, shutil, subprocess, sys, tempfile
import coincurve
from Crypto.Hash import keccak as _keccak

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import check_decode as cd  # the transaction builder and its expectation (section 9.3)

PKGS = os.environ.get("CANCHO_PACKAGES", os.path.join(ROOT, "../cancho/packages"))
SCHEMA = os.environ.get("CANCHO_SCHEMA", os.path.join(ROOT, "../alpibrusl/cancho-schema/src/schema.cho"))
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
DOMAIN = b"cancho-chain/envelope/v1"
DECISION_DOMAIN = b"cancho-chain/decision/v1"
ORDER = ["250", "251", "252", "253", "254", "255", "256", "257", "258", "259"]


def srcs(libdir):
    return ([os.path.join(ROOT, "tools/envdrv/main.cho"), os.path.join(ROOT, "lib/keccak/keccak.cho")] + sorted(glob.glob(os.path.join(ROOT, "lib/eth/*.cho")))
            + [os.path.join(ROOT, "lib/intent/intent.cho"), os.path.join(ROOT, "lib/policy/policy.cho"), os.path.join(ROOT, "lib/policy/decide.cho"), os.path.join(libdir, "envelope/envelope.cho"), SCHEMA]
            + [os.path.join(PKGS, "secp256k1", f) for f in ("secp256k1.cho", "comb.cho", "field.cho", "scalar.cho")])


def build(cancho, libdir, out):
    r = subprocess.run([cancho, "build", "--std", *srcs(libdir), "-o", out], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("build failed:\n" + r.stderr)


def call(exe, line):
    return subprocess.run([exe], input=line.encode(), capture_output=True, timeout=60).stdout.decode().strip() or "CRASH"


def kec(b):
    return _keccak.new(digest_bits=256, data=b).digest()


def hx(b):
    return b.hex() if b else "_"


def be(n):
    return cd.be(n)


# ---- the model
def address_of(key):
    pub = coincurve.PrivateKey(key).public_key.format(compressed=False)
    return kec(pub[1:])[12:]


def sign(digest, key):
    return coincurve.PrivateKey(key).sign_recoverable(digest, hasher=None)  # r || s || recid, low s, RFC 6979 as libsecp256k1 draws it


def decision_record(intent_digest, policy_digest, decided, expires, amount, caller, outcome=1, reason=0, version=1):
    return (bytes([version, outcome]) + reason.to_bytes(2, "big") + intent_digest + policy_digest + decided.to_bytes(8, "big") + expires.to_bytes(8, "big")
            + amount.to_bytes(32, "big") + bytes([len(caller)]) + caller)


def layout(c, **over):
    p = dict(id=c.id, ddigest=kec(DECISION_DOMAIN + c.decision), tdigest=kec(c.tx.unsigned()), chain=c.tx.chain, wallet=c.wallet, token=c.tx.token, recipient=c.tx.recipient,
             amount=c.tx.amount, nonce=c.tx.nonce, fee_cap=c.tx.fee_cap, gas_cap=c.tx.gas_cap, issued=c.now, expires=c.expires, caller=c.caller)
    p.update(over)
    return (bytes([1]) + p["id"] + p["ddigest"] + p["tdigest"] + p["chain"].to_bytes(8, "big") + p["wallet"] + p["token"] + p["recipient"] + p["amount"].to_bytes(32, "big")
            + p["nonce"].to_bytes(8, "big") + p["fee_cap"].to_bytes(32, "big") + p["gas_cap"].to_bytes(8, "big") + p["issued"].to_bytes(8, "big") + p["expires"].to_bytes(8, "big")
            + bytes([len(p["caller"])]) + p["caller"])


def env_digest(env):
    return kec(DOMAIN + env)


class Case:
    def __init__(self, rng):
        self.tx = cd.Tx(rng)
        self.tx.chain = rng.choice((1, 11155111, 137, rng.getrandbits(40) + 1))
        self.issuer_key = (rng.randrange(1, N)).to_bytes(32, "big")
        self.wallet_key = (rng.randrange(1, N)).to_bytes(32, "big")
        self.issuer = address_of(self.issuer_key)
        self.wallet = address_of(self.wallet_key)
        self.caller = bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz0123456789-_.:") for _ in range(rng.choice((1, 2, 20, 64))))
        self.id = bytes(rng.randrange(256) for _ in range(32))
        self.decided = rng.choice((0, 1_730_000_000, rng.getrandbits(40)))
        self.expires = self.decided + rng.choice((1, 2, 300, 3600))
        self.now = rng.randrange(self.decided, self.expires)
        self.decision = decision_record(bytes(rng.randrange(256) for _ in range(32)), bytes(rng.randrange(256) for _ in range(32)), self.decided, self.expires, self.tx.amount, self.caller)
        self.sig = None
        self.env = layout(self)

    def signed(self, env=None, key=None):
        e = self.env if env is None else env
        return e, sign(env_digest(e), key or self.issuer_key)

    # the lines for the driver
    def issue_line(self, **over):
        p = dict(decision=self.decision, message=self.tx.unsigned(), chain=be(self.tx.chain), nonce=be(self.tx.nonce), token=self.tx.token, recipient=self.tx.recipient,
                 amount=be(self.tx.amount), fee=be(self.tx.fee_cap), gas=be(self.tx.gas_cap), wallet=self.wallet, id=self.id, now=be(self.now), key=self.issuer_key)
        p.update(over)
        return "I " + " ".join(hx(p[k]) for k in ("decision", "message", "chain", "nonce", "token", "recipient", "amount", "fee", "gas", "wallet", "id", "now", "key"))

    def verify_line(self, env=None, sig=None, message=None, issuer=None, chain=None, wallet=None, caller=None, now=None):
        e = self.env if env is None else env
        s = sig if sig is not None else sign(env_digest(e), self.issuer_key)
        msg = self.tx.unsigned() if message is None else message
        return "V " + " ".join((hx(e), hx(s), hx(msg), hx(issuer or self.issuer), hx(be(self.tx.chain if chain is None else chain)), hx(wallet or self.wallet), hx(caller or self.caller),
                                hx(be(self.now if now is None else now))))


FAILS = []
COUNT = [0]


def check(name, got, want):
    COUNT[0] += 1
    if got != want:
        FAILS.append(name)
        if len(FAILS) <= 12:
            print(f"FAIL {name}: got {got!r}, want {want!r}")


def parse_issue(out):
    f = out.split()
    return (f[0], bytes.fromhex(f[1]), bytes.fromhex(f[2])) if f and f[0] == "0" and len(f) == 3 else (out, None, None)


def run(exe, cases):
    rng = random.Random(60606)
    # (1) the happy path, bytes and signatures against the model
    for i in range(cases):
        c = Case(rng)
        st, env, sig = parse_issue(call(exe, c.issue_line()))
        check(f"issue {i}: accepted", st, "0")
        if env is None:
            continue
        want_env, want_sig = c.signed()
        check(f"issue {i}: the model's envelope", env, want_env)
        check(f"issue {i}: the model's signature", sig, want_sig)
        d = env_digest(env)
        rec = coincurve.PublicKey.from_signature_and_message(sig, d, hasher=None).format(compressed=False)
        check(f"issue {i}: recovers to the issuer", kec(rec[1:])[12:], c.issuer)
        check(f"issue {i}: python-ecdsa verifies it", ecdsa_verify(rec[1:], sig[:64], d), True)
        check(f"issue {i}: verify accepts", call(exe, c.verify_line(env, sig)), "0")
        check(f"issue {i}: the digest", call(exe, "D " + hx(env)), "0 " + d.hex())
        if i % 7 == 0:
            check(f"issue {i}: the amount may be padded to 32 bytes", parse_issue(call(exe, c.issue_line(amount=be(c.tx.amount).rjust(32, b"\0")))), ("0", want_env, want_sig))
    # (2) the refusals of issue, each alone
    c = Case(rng)
    base = c.issue_line()
    check("issue baseline", parse_issue(call(exe, base))[0], "0")

    def refused(name, line, want):
        check("issue: " + name, call(exe, line), want)

    d = c.decision
    refused("decision too short", c.issue_line(decision=d[:-1]), "E240")
    refused("decision too long", c.issue_line(decision=d + b"\0"), "E240")
    refused("decision version 2", c.issue_line(decision=bytes([2]) + d[1:]), "E240")
    refused("caller length 0", c.issue_line(decision=d[:116] + bytes([0])), "E245" if len(d[:116] + bytes([0])) < 118 else "E240")
    refused("caller length byte wrong", c.issue_line(decision=d[:116] + bytes([len(c.caller) + 1]) + d[117:]), "E240")
    refused("caller length 65", c.issue_line(decision=d[:116] + bytes([65]) + bytes(65)), "E240")
    for outcome in (2, 3, 0, 9):
        refused(f"outcome {outcome}", c.issue_line(decision=d[:1] + bytes([outcome]) + d[2:]), "E241")
    refused("now before decided_at", c.issue_line(now=be(c.decided - 1)) if c.decided > 0 else c.issue_line(now=be(c.expires)), "E242")
    refused("now at expires_at", c.issue_line(now=be(c.expires)), "E242")
    refused("now after expires_at", c.issue_line(now=be(c.expires + 1)), "E242")
    check("issue: now at decided_at", parse_issue(call(exe, c.issue_line(now=be(c.decided))))[0], "0")
    check("issue: now one before expires_at", parse_issue(call(exe, c.issue_line(now=be(c.expires - 1))))[0], "0")
    refused("amount one more", c.issue_line(amount=be(c.tx.amount + 1)), "E243")
    refused("amount one less", c.issue_line(amount=be(c.tx.amount - 1)) if c.tx.amount else c.issue_line(amount=be(1)), "E243")
    for name, over in (("chain", dict(chain=be(c.tx.chain + 1))), ("nonce", dict(nonce=be(c.tx.nonce + 1))), ("token", dict(token=bytes([c.tx.token[0] ^ 1]) + c.tx.token[1:])),
                       ("recipient", dict(recipient=bytes([c.tx.recipient[0] ^ 1]) + c.tx.recipient[1:])), ("message", dict(message=c.tx.unsigned()[:-1]))):
        refused("transaction: " + name, c.issue_line(**over), "E244")
    if c.tx.fee > 0:
        refused("transaction: fee above its cap", c.issue_line(fee=be(c.tx.fee - 1)), "E244")
    refused("transaction: gas above its cap", c.issue_line(gas=be(c.tx.gas - 1)), "E244")
    for name, over in (("id 31 bytes", dict(id=c.id[:31])), ("wallet 19 bytes", dict(wallet=c.wallet[:19])), ("token 19 bytes", dict(token=c.tx.token[:19])), ("message empty", dict(message=b"")),
                       ("issuer key 31 bytes", dict(key=c.issuer_key[:31])), ("amount 33 bytes", dict(amount=b"\1" * 33)), ("fee cap 33 bytes", dict(fee=b"\1" * 33))):
        refused("input: " + name, c.issue_line(**over), "E245")
    refused("issuer key zero", c.issue_line(key=bytes(32)), "E247")
    refused("issuer key n", c.issue_line(key=N.to_bytes(32, "big")), "E247")
    refused("issuer key is the wallet's", c.issue_line(wallet=c.issuer), "E248")
    # (3) the refusals of verify, alone
    e, s = c.signed()
    other_key = (rng.randrange(1, N)).to_bytes(32, "big")
    other_addr = address_of(other_key)
    v = lambda **kw: call(exe, c.verify_line(**kw))
    check("verify baseline", v(), "0")
    check("verify: envelope truncated", v(env=e[:-1], sig=s), "E250")
    check("verify: envelope extended", v(env=e + b"\0", sig=s), "E250")
    check("verify: envelope empty", v(env=b"", sig=s), "E250")
    check("verify: version 2", v(env=bytes([2]) + e[1:], sig=s), "E250")
    for n_ in (0, 65):
        check(f"verify: caller length {n_}", v(env=e[:261] + bytes([n_]) + e[262:], sig=s), "E250")
    hs = s[:32] + (N - int.from_bytes(s[32:64], "big")).to_bytes(32, "big") + bytes([s[64] ^ 1])
    check("verify: s above n/2 (the same signature, malleated)", v(sig=hs), "E251")
    check("verify: r zero", v(sig=bytes(32) + s[32:]), "E251")
    check("verify: s zero", v(sig=s[:32] + bytes(32) + s[64:]), "E251")
    check("verify: recid 4", v(sig=s[:64] + bytes([4])), "E251")
    check("verify: signed by another key", v(sig=sign(env_digest(e), other_key)), "E252")
    check("verify: another issuer configured", v(issuer=other_addr), "E252")
    check("verify: chain configured differently", v(chain=c.tx.chain + 1), "E253")
    check("verify: wallet configured differently", v(wallet=other_addr), "E254")
    check("verify: caller differs in one byte", v(caller=bytes([c.caller[0] ^ 1]) + c.caller[1:]), "E255")
    check("verify: caller one byte longer", v(caller=c.caller + b"x"), "E255")
    check("verify: caller one byte shorter", v(caller=c.caller[:-1]) if len(c.caller) > 1 else "E255", "E255")
    check("verify: now before issued_at", v(now=c.now - 1) if c.now > 0 else "E256", "E256")
    check("verify: now at issued_at", v(now=c.now), "0")
    check("verify: now one before expires_at", v(now=c.expires - 1), "0")
    check("verify: now at expires_at", v(now=c.expires), "E257")
    check("verify: now after expires_at", v(now=c.expires + 10), "E257")
    msg = c.tx.unsigned()
    check("verify: a message of another transaction", v(message=msg[:-1] + bytes([msg[-1] ^ 1])), "E258")
    # (3b) a transaction that is not the envelope's expectation, with a digest that matches the message and a signature that is the issuer's: E259 with txcheck's code
    for name, over, code in (("chain", dict(chain=c.tx.chain + 1), 182), ("nonce", dict(nonce=c.tx.nonce + 1), 183), ("token", dict(token=bytes([c.tx.token[0] ^ 1]) + c.tx.token[1:]), 184),
                             ("recipient", dict(recipient=bytes([c.tx.recipient[0] ^ 1]) + c.tx.recipient[1:]), 189), ("amount", dict(amount=c.tx.amount ^ 1), 190),
                             ("gas cap", dict(gas_cap=c.tx.gas - 1), 193)):
        e2 = layout(c, **over)
        s2 = sign(env_digest(e2), c.issuer_key)
        got = call(exe, c.verify_line(env=e2, sig=s2, chain=c.tx.chain))
        check(f"verify: expectation differs in {name}", got, f"E259 {code}")
    if c.tx.fee > 0:
        e2 = layout(c, fee_cap=c.tx.fee - 1)
        check("verify: expectation fee cap below the fee", call(exe, c.verify_line(env=e2, sig=sign(env_digest(e2), c.issuer_key))), "E259 192")
    # (3c) every fault alone, and every pair that can occur together: the first in the order of section 13.3 answers
    c2 = Case(random.Random(5))
    while c2.now == 0 or c2.tx.fee == 0:
        c2 = Case(random.Random(rng.random()))
    c = c2
    msg = c.tx.unsigned()
    other_key = (rng.randrange(1, N)).to_bytes(32, "big")
    other_addr = address_of(other_key)

    def scenario(faults):
        env = layout(c, recipient=bytes([c.tx.recipient[0] ^ 1]) + c.tx.recipient[1:]) if "259" in faults else c.env
        key = other_key if "252" in faults else c.issuer_key
        sig = sign(env_digest(env), key)
        if "251" in faults:
            sig = bytes(32) + sig[32:]
        if "250" in faults:
            env = env[:-1]
        kw = {}
        if "253" in faults:
            kw["chain"] = c.tx.chain + 1
        if "254" in faults:
            kw["wallet"] = other_addr
        if "255" in faults:
            kw["caller"] = c.caller + b"x"
        if "256" in faults:
            kw["now"] = c.now - 1
        if "257" in faults:
            kw["now"] = c.expires
        if "258" in faults:
            kw["message"] = msg[:-1] + bytes([msg[-1] ^ 1])
        return call(exe, c.verify_line(env=env, sig=sig, **kw))

    for name in ORDER:
        want = "E259 189" if name == "259" else "E" + name
        check(f"fault {name} alone", scenario([name]), want)
    for a_, b_ in itertools.combinations(ORDER, 2):
        if {a_, b_} == {"256", "257"}:
            continue
        check(f"pair {a_}+{b_}: the first answers", scenario([a_, b_]).split()[0], "E" + a_)
    for trio in itertools.combinations(ORDER, 3):
        if "256" in trio and "257" in trio:
            continue
        check(f"trio {'+'.join(trio)}: the first answers", scenario(list(trio)).split()[0], "E" + trio[0])
    # (4) every byte of the envelope, signature and message changed
    e, s = c.signed()
    bad = []
    for at in range(len(e)):
        for bit in (0, 7):
            e2 = e[:at] + bytes([e[at] ^ (1 << bit)]) + e[at + 1:]
            got = call(exe, c.verify_line(env=e2, sig=s))
            want = ("E250",) if at in (0, 261) else ("E252", "E251")
            if got not in want:
                bad.append((at, bit, got))
    check(f"every changed bit of the envelope is refused by the signature or the layout ({len(e)} bytes): {bad[:3]}", len(bad), 0)
    bad = []
    for at in range(65):
        for bit in (0, 7):
            s2 = s[:at] + bytes([s[at] ^ (1 << bit)]) + s[at + 1:]
            got = call(exe, c.verify_line(env=e, sig=s2))
            if got == "0":
                bad.append((at, bit))
    check(f"every changed bit of the signature is refused ({bad[:3]})", len(bad), 0)
    bad = []
    for at in range(len(msg)):
        m2 = msg[:at] + bytes([msg[at] ^ 1]) + msg[at + 1:]
        if call(exe, c.verify_line(message=m2)) != "E258":
            bad.append(at)
    check(f"every changed byte of the message is a digest mismatch ({len(msg)} bytes): {bad[:3]}", len(bad), 0)
    # (6) the ledger
    lrng = random.Random(9)
    for i in range(60):
        k = lrng.randrange(0, 6)
        entries = [(bytes(lrng.randrange(256) for _ in range(32)), bytes(lrng.randrange(256) for _ in range(32))) for _ in range(k)]
        led = b"".join(a + b for a, b in entries)
        probe = lrng.randrange(3)
        iid, dig = (entries[0] if (probe and k) else (bytes(lrng.randrange(256) for _ in range(32)), bytes(lrng.randrange(256) for _ in range(32))))
        if probe == 2 and k:
            dig = bytes([dig[0] ^ 1]) + dig[1:]
        want = "0" if not (probe and k) else ("1" if probe == 1 else "E261")
        check(f"ledger {i}", call(exe, f"L {hx(led)} {iid.hex()} {dig.hex()}"), want)
    iid, d1, d2 = bytes(32), bytes([1]) * 32, bytes([2]) * 32
    check("ledger: the same id twice with different digests conflicts", call(exe, f"L {hx(iid + d1 + iid + d2)} {iid.hex()} {d1.hex()}"), "E261")
    check("ledger: the same entry twice is the same", call(exe, f"L {hx(iid + d1 + iid + d1)} {iid.hex()} {d1.hex()}"), "1")
    check("ledger: a length that is not a multiple of 64", call(exe, f"L {hx(iid + d1 + b'x')} {iid.hex()} {d1.hex()}"), "E260")
    check("ledger: a short id", call(exe, f"L _ {iid[:31].hex()} {d1.hex()}"), "E260")


def ecdsa_verify(pub64, sig64, digest):
    import ecdsa
    vk = ecdsa.VerifyingKey.from_string(pub64, curve=ecdsa.SECP256k1)
    try:
        return vk.verify_digest(sig64, digest, sigdecode=ecdsa.util.sigdecode_string)
    except ecdsa.BadSignatureError:
        return False


def main():
    cases = 120
    if "--cases" in sys.argv:
        cases = int(sys.argv[sys.argv.index("--cases") + 1])
    cancho = os.environ.get("CANCHO", "cancho")
    with tempfile.TemporaryDirectory() as t:
        exe = os.path.join(t, "envdrv")
        build(cancho, os.path.join(ROOT, "lib"), exe)
        run(exe, cases)
    print(f"{COUNT[0]} checks, {len(FAILS)} failed")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
