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
    out = subprocess.run([exe], input=line.encode(), capture_output=True, timeout=60).stdout.decode().strip() or "CRASH"
    return out[:-2] if line.startswith("V ") and out.startswith("E") and out.endswith(" 0") else out  # "E<code> 0": no txcheck detail


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
    while c.tx.amount == 0 or c.tx.fee == 0 or c.now == 0:
        c = Case(rng)  # a case in which "one less" and "one before" exist
    base = c.issue_line()
    check("issue baseline", parse_issue(call(exe, base))[0], "0")

    def refused(name, line, want):
        check("issue: " + name, call(exe, line), want)

    d = c.decision
    refused("decision too short", c.issue_line(decision=d[:-1]), "E240")
    refused("decision above the 181-byte bound", c.issue_line(decision=d + bytes(182 - len(d))), "E245")
    refused("decision whose caller length does not match", c.issue_line(decision=d + b"\0"), "E245" if len(d) + 1 > 181 else "E240")
    refused("decision version 2", c.issue_line(decision=bytes([2]) + d[1:]), "E240")
    refused("caller length 0", c.issue_line(decision=d[:116] + bytes([0])), "E245" if len(d[:116] + bytes([0])) < 118 else "E240")
    refused("caller length byte wrong", c.issue_line(decision=d[:116] + bytes([len(c.caller) + 1]) + d[117:]), "E240")
    refused("caller length 65", c.issue_line(decision=d[:116] + bytes([65]) + bytes(65)), "E245")
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
    check("verify: envelope of 261 bytes (the length byte is out of range)", v(env=e[:261], sig=s), "E250")
    check("verify: envelope of 262 bytes", v(env=e[:262], sig=s), "E250")
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
    check("verify: caller one byte longer", v(caller=c.caller + b"x") if len(c.caller) < 64 else v(caller=c.caller[:-1]), "E255")
    check("verify: caller one byte shorter", v(caller=c.caller[:-1]) if len(c.caller) > 1 else "E255", "E255")
    check("verify: now before issued_at", v(now=c.now - 1) if c.now > 0 else "E256", "E256")
    check("verify: now at issued_at", v(now=c.now), "0")
    check("verify: now one before expires_at", v(now=c.expires - 1), "0")
    check("verify: now at expires_at", v(now=c.expires), "E257")
    check("verify: now after expires_at", v(now=c.expires + 10), "E257")
    msg = c.tx.unsigned()
    check("verify: a message of another transaction", v(message=msg[:-1] + bytes([msg[-1] ^ 1])), "E258")
    # (3b) a transaction that is not the envelope's expectation, with a digest that matches the message and a signature that is the issuer's: E259 with txcheck's code
    e2 = layout(c, chain=c.tx.chain + 1)
    check("verify: expectation chain differs from the message's (the configuration agrees with the envelope)", call(exe, c.verify_line(env=e2, sig=sign(env_digest(e2), c.issuer_key), chain=c.tx.chain + 1)), "E259 182")
    for name, over, code in (("nonce", dict(nonce=c.tx.nonce + 1), 183), ("token", dict(token=bytes([c.tx.token[0] ^ 1]) + c.tx.token[1:]), 184),
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
            kw["caller"] = bytes([c.caller[0] ^ 1]) + c.caller[1:]
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
    # (5) the window's edges and the signature's low-s edge, and the configuration's lengths
    half_n = bytes.fromhex("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0")
    rr = 1
    while True:
        cand = rr.to_bytes(32, "big") + half_n + bytes([0])
        try:
            coincurve.PublicKey.from_signature_and_message(cand, env_digest(e), hasher=None)
            break
        except Exception:
            rr += 1
    check("verify: s exactly n/2 is low (the signature is not the issuer's, so E252, not E251)", v(sig=cand), "E252")
    above = rr.to_bytes(32, "big") + (int.from_bytes(half_n, "big") + 1).to_bytes(32, "big") + bytes([0])
    check("verify: s one above n/2 is not low", v(sig=above), "E251")
    check("verify: s n - 1 is not low", v(sig=rr.to_bytes(32, "big") + (N - 1).to_bytes(32, "big") + bytes([0])), "E251")
    line = c.verify_line().split()
    for name, idx, val, want in (("issuer 19 bytes", 4, hx(c.issuer[:19]), "E245"), ("issuer 21 bytes", 4, hx(c.issuer + b"\0"), "E245"), ("wallet 19 bytes", 6, hx(c.wallet[:19]), "E245"),
                                 ("wallet 21 bytes", 6, hx(c.wallet + b"\0"), "E245"), ("caller empty", 7, "_", "E245"), ("caller 65 bytes", 7, hx(bytes(65)), "E245"),
                                 ("message empty", 3, "_", "E245"), ("signature 64 bytes", 2, hx(s[:64]), "E245"), ("signature 66 bytes", 2, hx(s + b"\0"), "E245")):
        l2 = list(line)
        l2[idx] = val
        check("verify: " + name, call(exe, " ".join(l2)), want)
    longest = Case(random.Random(77))
    while len(longest.caller) != 64:
        longest = Case(random.Random(rng.random()))
    le_, ls_ = longest.signed()
    check("verify: a 64-byte caller is accepted (the longest envelope, 326 bytes)", (len(le_), call(exe, longest.verify_line(le_, ls_))), (326, "0"))
    shortest = Case(random.Random(78))
    while len(shortest.caller) != 1:
        shortest = Case(random.Random(rng.random()))
    se_, ss_ = shortest.signed()
    check("verify: a 1-byte caller is accepted (the shortest envelope, 263 bytes)", (len(se_), call(exe, shortest.verify_line(se_, ss_))), (263, "0"))
    check("digest: 262 bytes is refused", call(exe, "D " + hx(bytes(262))), "E246")
    check("digest: 327 bytes is refused", call(exe, "D " + hx(bytes(327))), "E246")
    check("digest: 263 bytes is accepted", call(exe, "D " + hx(bytes(263))).split()[0], "0")
    check("digest: 326 bytes is accepted", call(exe, "D " + hx(bytes(326))).split()[0], "0")
    check("ledger entry", call(exe, f"Y {bytes(range(32)).hex()} {bytes(range(32, 64)).hex()}"), "0 " + bytes(range(64)).hex())
    check("ledger entry: a short digest", call(exe, f"Y {bytes(32).hex()} {bytes(31).hex()}"), "E260")
    for name, over, want in (("recipient 19 bytes", dict(recipient=c.tx.recipient[:19]), "E245"), ("id 33 bytes", dict(id=c.id + b"\0"), "E245"), ("issuer key 33 bytes", dict(key=c.issuer_key + b"\0"), "E245"),
                             ("wallet 21 bytes", dict(wallet=c.wallet + b"\0"), "E245"), ("token 21 bytes", dict(token=c.tx.token + b"\0"), "E245"), ("fee cap 32 bytes is allowed", dict(fee=be(c.tx.fee_cap).rjust(32, b"\0")), None)):
        got = call(exe, c.issue_line(**over))
        check("issue: " + name, got if want else parse_issue(got)[0], want or "0")
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
    check("ledger: a short digest", call(exe, f"L _ {iid.hex()} {d1[:31].hex()}"), "E260")
    check("ledger: a short id", call(exe, f"L _ {iid[:31].hex()} {d1.hex()}"), "E260")


def ecdsa_verify(pub64, sig64, digest):
    import ecdsa
    vk = ecdsa.VerifyingKey.from_string(pub64, curve=ecdsa.SECP256k1)
    try:
        return vk.verify_digest(sig64, digest, sigdecode=ecdsa.util.sigdecode_string)
    except ecdsa.BadSignatureError:
        return False


# (name, old, new): `old` must occur exactly once in lib/envelope/envelope.cho
MUTANTS = [
    ("put_be8 shift", "v >> 8 * (7 - i) & 255", "v >> 8 * i & 255"),
    ("be8 base", "v = v * 256 + int_of(c[at + i]);", "v = v * 255 + int_of(c[at + i]);"),
    ("put_padded offset", "out[at + 32 - len(src) + i] = src[i];", "out[at + 31 - len(src) + i] = src[i];"),
    ("cmp32 direction", "if x < y {\n                return -1;", "if x > y {\n                return -1;"),
    ("digest min length", "if len(env) < 263 || len(env) > 326 || len(out) != 32 {", "if len(env) < 262 || len(env) > 326 || len(out) != 32 {"),
    ("digest max length", "if len(env) < 263 || len(env) > 326 || len(out) != 32 {", "if len(env) < 263 || len(env) > 327 || len(out) != 32 {"),
    ("digest domain length", "alloc_slice[r](24 + len(env), byte_of(0));", "alloc_slice[r](23 + len(env), byte_of(0));"),
    ("digest domain offset", "copy_to(m, 24, env);", "copy_to(m, 23, env);"),
    ("issue: message may be empty", "len(message) < 1 || len(token) != 20", "len(message) < 0 || len(token) != 20"),
    ("issue: token length", "len(token) != 20 || len(recipient) != 20 || len(amount) > 32", "len(token) > 20 || len(recipient) != 20 || len(amount) > 32"),
    ("issue: recipient length", "len(recipient) != 20 || len(amount) > 32", "len(recipient) > 20 || len(amount) > 32"),
    ("issue: amount length", "len(amount) > 32 || len(fee_cap) > 32", "len(amount) > 33 || len(fee_cap) > 32"),
    ("issue: fee cap length", "len(fee_cap) > 32 || len(wallet) != 20", "len(fee_cap) > 33 || len(wallet) != 20"),
    ("issue: wallet length", "len(wallet) != 20 || len(id) != 32", "len(wallet) > 20 || len(id) != 32"),
    ("issue: id length", "len(id) != 32 || len(issuer_key) != 32", "len(id) > 32 || len(issuer_key) != 32"),
    ("issue: key length", "len(issuer_key) != 32 || len(sig) != 65", "len(issuer_key) > 32 || len(sig) != 65"),
    ("issue: decision min length", "if len(decision) < 118 || len(decision) > 181", "if len(decision) < 117 || len(decision) > 181"),
    ("issue: decision max length", "if len(decision) < 118 || len(decision) > 181", "if len(decision) < 118 || len(decision) > 182"),
    ("issue: decision version", "int_of(decision[0]) != 1 || calln < 1", "int_of(decision[0]) != 2 || calln < 1"),
    ("issue: caller length 0", "|| calln < 1 || calln > 64 ||", "|| calln < 0 || calln > 64 ||"),
    ("issue: caller length 65", "|| calln < 1 || calln > 64 ||", "|| calln < 1 || calln > 65 ||"),
    ("issue: caller length matches", "len(decision) != 117 + calln", "len(decision) != 116 + calln"),
    ("issue: outcome", "if int_of(decision[1]) != 1 {", "if int_of(decision[1]) > 1 {"),
    ("issue: window start", "if now < be8(decision, 68) ||", "if now <= be8(decision, 68) ||"),
    ("issue: window end", "|| now >= be8(decision, 76) {", "|| now > be8(decision, 76) {"),
    ("issue: amount compared", "if cmp32(decision[84..116], want) != 0 {", "if cmp32(decision[84..116], want) < 0 {"),
    ("issue: amount offset", "cmp32(decision[84..116], want)", "cmp32(decision[85..117], want)"),
    ("issue: transaction checked", "validate_unsigned(message, chain_id, nonce, token, recipient, amount, fee_cap, gas_cap) != 0 {\n            code = -244;", "validate_unsigned(message, chain_id, nonce, token, recipient, amount, fee_cap, gas_cap) < -300 {\n            code = -244;"),
    ("issue: issuer is the wallet", "} else if bytes.equal(who, wallet) {", "} else if false {"),
    ("issue: issuer address from the key", "code = secp256k1.public_key(issuer_key, pk, work);", "code = secp256k1.public_key(id, pk, work);"),
    ("layout: id", "copy_to(env, 1, id);", "copy_to(env, 1, tdigest);"),
    ("layout: decision digest", "copy_to(env, 33, ddigest);", "copy_to(env, 33, tdigest);"),
    ("layout: transaction digest", "copy_to(env, 65, tdigest);", "copy_to(env, 65, ddigest);"),
    ("layout: chain", "put_be8(env, 97, chain_id);", "put_be8(env, 97, nonce);"),
    ("layout: wallet", "copy_to(env, 105, wallet);", "copy_to(env, 105, token);"),
    ("layout: token", "copy_to(env, 125, token);", "copy_to(env, 125, recipient);"),
    ("layout: recipient", "copy_to(env, 145, recipient);", "copy_to(env, 145, token);"),
    ("layout: amount", "put_padded(env, 165, amount);", "put_padded(env, 165, fee_cap);"),
    ("layout: nonce", "put_be8(env, 197, nonce);", "put_be8(env, 197, chain_id);"),
    ("layout: fee cap", "put_padded(env, 205, fee_cap);", "put_padded(env, 205, amount);"),
    ("layout: gas cap", "put_be8(env, 237, gas_cap);", "put_be8(env, 237, nonce);"),
    ("layout: issued_at", "put_be8(env, 245, now);", "put_be8(env, 245, be8(decision, 68));"),
    ("layout: expires_at", "put_be8(env, 253, be8(decision, 76));", "put_be8(env, 253, now + 300);"),
    ("layout: caller length", "env[261] = byte_of(calln);", "env[261] = byte_of(calln + 1);"),
    ("layout: caller", "copy_to(env, 262, decision[117..117 + calln]);", "copy_to(env, 262, decision[116..116 + calln]);"),
    ("issue: signed as hedged", "secp256k1.sign(edigest, issuer_key, id[0..0], sig, work)", "secp256k1.sign(edigest, issuer_key, id, sig, work)"),
    ("issue: signed over the layout", "code = digest(st, env[0..262 + calln], edigest);", "code = digest(st, env[0..261 + calln], edigest);"),
    ("issue: length answered", "return 262 + calln;", "return 261 + calln;"),
    ("verify: issuer length", "if len(issuer) != 20 || len(wallet) != 20 ||", "if len(issuer) > 20 || len(wallet) != 20 ||"),
    ("verify: wallet length", "|| len(wallet) != 20 || len(caller) < 1", "|| len(wallet) > 20 || len(caller) < 1"),
    ("verify: caller empty", "len(caller) < 1 || len(caller) > 64 || len(detail)", "len(caller) < 0 || len(caller) > 64 || len(detail)"),
    ("verify: caller 65", "len(caller) < 1 || len(caller) > 64 || len(detail)", "len(caller) < 1 || len(caller) > 65 || len(detail)"),
    ("verify: message empty", "|| len(message) < 1 || chain_id < 0 || now < 0 || len(sig) != 65 {", "|| len(message) < 0 || chain_id < 0 || now < 0 || len(sig) != 65 {"),
    ("verify: signature length", "|| len(sig) != 65 {\n        return -245;\n    }\n    detail[0] = 0;", "|| len(sig) > 65 {\n        return -245;\n    }\n    detail[0] = 0;"),
    ("verify: min envelope", "if len(env) < 263 || len(env) > 326 || int_of(env[0]) != 1 {", "if len(env) < 262 || len(env) > 326 || int_of(env[0]) != 1 {"),
    ("verify: max envelope", "if len(env) < 263 || len(env) > 326 || int_of(env[0]) != 1 {", "if len(env) < 263 || len(env) > 327 || int_of(env[0]) != 1 {"),
    ("verify: version", "|| int_of(env[0]) != 1 {\n        return -250;", "|| int_of(env[0]) > 1 {\n        return -250;"),
    ("verify: caller length 0", "if n < 1 || n > 64 || len(env) != 262 + n {", "if n < 0 || n > 64 || len(env) != 262 + n {"),
    ("verify: caller length 65", "if n < 1 || n > 64 || len(env) != 262 + n {", "if n < 1 || n > 65 || len(env) != 262 + n {"),
    ("verify: length matches", "len(env) != 262 + n {", "len(env) != 263 + n {"),
    ("verify: low s", "} else if cmp32(sig[32..64], half_n) > 0 {", "} else if cmp32(sig[32..64], half_n) >= 0 {"),
    ("verify: low s checked", "} else if cmp32(sig[32..64], half_n) > 0 {", "} else if cmp32(sig[32..64], half_n) > 1 {"),
    ("verify: half n", "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1"),
    ("verify: half n, high end", "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", "7ffffffffffffffffffffffffffffffe5d576e7357a4501ddfe92f46681b20a0"),
    ("verify: recovered over the digest", "code = secp256k1.recover(edigest, sig, pk, work);", "code = secp256k1.recover(env[0..32], sig, pk, work);"),
    ("verify: issuer compared", "} else if !bytes.equal(who, issuer) {", "} else if false {"),
    ("verify: chain", "if be8(env, 97) != chain_id {", "if be8(env, 97) == chain_id {"),
    ("verify: wallet", "} else if !bytes.equal(env[105..125], wallet) {", "} else if !bytes.equal(env[106..126], wallet) {"),
    ("verify: caller", "} else if !bytes.equal(env[262..262 + n], caller) {", "} else if !bytes.equal(env[262..261 + n], caller) {"),
    ("verify: not yet valid", "} else if now < be8(env, 245) {", "} else if now <= be8(env, 245) {"),
    ("verify: expired", "} else if now >= be8(env, 253) {", "} else if now > be8(env, 253) {"),
    ("verify: transaction digest", "} else if !bytes.equal(tdigest, env[65..97]) {", "} else if false {"),
    ("verify: transaction digest offset", "} else if !bytes.equal(tdigest, env[65..97]) {", "} else if !bytes.equal(tdigest, env[64..96]) {"),
    ("verify: expectation nonce", "be8(env, 197), env[125..145]", "be8(env, 205), env[125..145]"),
    ("verify: expectation token", "env[125..145], env[145..165], env[165..197]", "env[145..165], env[145..165], env[165..197]"),
    ("verify: expectation recipient", "env[145..165], env[165..197], env[205..237]", "env[125..145], env[165..197], env[205..237]"),
    ("verify: expectation amount", "env[165..197], env[205..237], be8(env, 237)", "env[205..237], env[205..237], be8(env, 237)"),
    ("verify: expectation fee cap", "env[205..237], be8(env, 237));", "env[165..197], be8(env, 237));"),
    ("verify: expectation gas cap", "env[205..237], be8(env, 237));", "env[205..237], be8(env, 197));"),
    ("verify: the detail", "detail[0] = tx;", "detail[0] = 0;"),
    ("verify: transaction invalid", "if tx != 0 {\n                    detail[0] = tx;", "if tx < -300 {\n                    detail[0] = tx;"),
    ("ledger: length", "if len(ledger) % 64 != 0 || len(id) != 32 || len(tx_digest) != 32 {", "if len(ledger) % 64 > 63 || len(id) != 32 || len(tx_digest) != 32 {"),
    ("ledger: id length", "len(id) != 32 || len(tx_digest) != 32 {\n        return -260;", "len(id) > 32 || len(tx_digest) != 32 {\n        return -260;"),
    ("ledger: digest length", "len(tx_digest) != 32 {\n        return -260;\n    }\n    var seen", "len(tx_digest) > 32 {\n        return -260;\n    }\n    var seen"),
    ("ledger: id offset", "bytes.equal(ledger[64 * k..64 * k + 32], id)", "bytes.equal(ledger[64 * k + 1..64 * k + 33], id)"),
    ("ledger: digest offset", "bytes.equal(ledger[64 * k + 32..64 * k + 64], tx_digest)", "bytes.equal(ledger[64 * k + 31..64 * k + 63], tx_digest)"),
    ("ledger: same", "if bytes.equal(ledger[64 * k + 32..64 * k + 64], tx_digest) {\n                seen = 1;", "if bytes.equal(ledger[64 * k + 32..64 * k + 64], tx_digest) {\n                seen = 0;"),
    ("ledger: conflict", "if conflict == 1 {\n        return -261;", "if conflict == 2 {\n        return -261;"),
    ("ledger: conflict set", "} else {\n                conflict = 1;", "} else {\n                conflict = 0;"),
    ("ledger entry: digest offset", "copy_to(out, 32, tx_digest);", "copy_to(out, 31, tx_digest);"),
    ("ledger entry: id", "copy_to(out, 0, id);", "copy_to(out, 0, tx_digest);"),
    ("ledger entry: length", "len(out) != 64 {", "len(out) > 64 {"),
]

# Mutants that no input of the driver can tell from the original, each with the reason.
EQUIVALENT = {
    "issue: caller length 0": "a decision with caller length 0 is 117 bytes, and the 118-byte minimum of the input check refuses it first (-245)",
    "issue: caller length 65": "a decision with caller length 65 is 182 bytes, and the 181-byte bound of the input check refuses it first (-245)",
    "verify: min envelope": "an envelope of 262 bytes reaches its caller-length byte (byte 261, in range), which is then 0 (`n < 1`) or makes the length differ from 262 + n: -250 either way",
    "verify: max envelope": "the next check, `len(env) != 262 + n` with n at most 64, refuses every length above 326 as well (-250), so the bound is defence in depth",
    "verify: caller length 0": "an envelope with caller length 0 is 262 bytes, below the 263-byte minimum that is checked first (-250)",
    "verify: caller length 65": "an envelope with caller length 65 is 327 bytes, above the 326-byte maximum that is checked first (-250)",
    "ledger entry: length": "the driver's output buffer is exactly 64 bytes, so a longer one cannot be given (the check is for callers that pass their own)",
}


def mutants(cancho, cases):
    text = open(os.path.join(ROOT, "lib/envelope/envelope.cho")).read()
    work = []
    for name, old, new in MUTANTS:
        if text.count(old) != 1:
            sys.exit(f"mutant {name!r}: the pattern occurs {text.count(old)} times")
        work.append((name, text.replace(old, new)))

    def one(item):
        name, body = item
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "envelope"))
            open(os.path.join(d, "envelope/envelope.cho"), "w").write(body)
            exe = os.path.join(d, "envdrv")
            r = subprocess.run([cancho, "build", "--std", *srcs(d), "-o", exe], capture_output=True, text=True)
            if r.returncode != 0:
                return name, "did not build: " + r.stderr[:200]
            r = subprocess.run([sys.executable, "-I", os.path.abspath(__file__), "--exe", exe, "--cases", str(cases)], capture_output=True, text=True, timeout=1800)
            return name, ("killed" if r.returncode != 0 else "SURVIVED")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    survivors, broken = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=int(os.environ.get("JOBS", "6"))) as pool:
        for name, verdict in pool.map(one, work):
            if verdict == "SURVIVED":
                survivors.append(name)
                print("SURVIVED:", name, flush=True)
            elif verdict != "killed":
                broken.append(name)
                print(f"INVALID: {name}: {verdict}", flush=True)
    unexplained = [n for n in survivors if n not in EQUIVALENT]
    print(f"mutants: {len(work) - len(survivors) - len(broken)}/{len(work)} killed, {len(survivors) - len(unexplained)} explained, {len(unexplained)} unexplained survivors, {len(broken)} invalid")
    sys.exit(1 if unexplained or broken else 0)


def main():
    cases = 120
    if "--cases" in sys.argv:
        cases = int(sys.argv[sys.argv.index("--cases") + 1])
    if "--mutants" in sys.argv:
        mutants(os.environ.get("CANCHO", "cancho"), min(cases, 20))
    if "--exe" in sys.argv:
        run(sys.argv[sys.argv.index("--exe") + 1], cases)
        print(f"{COUNT[0]} checks, {len(FAILS)} failed")
        sys.exit(1 if FAILS else 0)
    cancho = os.environ.get("CANCHO", "cancho")
    with tempfile.TemporaryDirectory() as t:
        exe = os.path.join(t, "envdrv")
        build(cancho, os.path.join(ROOT, "lib"), exe)
        run(exe, cases)
    print(f"{COUNT[0]} checks, {len(FAILS)} failed")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
