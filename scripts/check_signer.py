#!/usr/bin/env python3
"""The signer, as a real process (docs/design.md section 14.6).

    CANCHO=the-compiler CANCHO_PACKAGES=../cancho/packages CANCHO_SCHEMA=../alpibrusl/cancho-schema/src/schema.cho CANCHO_LOG=../cancho-log/src \
        python3 -I scripts/check_signer.py [--mutants] [--slow]
    needs: pip install coincurve ecdsa pycryptodome eth-account eth-abi rlp eth-utils

The binary is built with a temporary directory in place of its compile-time one. Envelopes are made by the model of `check_envelope.py` (section 13), the signature is checked against libsecp256k1's,
against python-ecdsa and against what `eth-account` signs for the same transaction, and the ledger is read back by a reader written here (record layout and lex-trail's event id, from their
specifications) and by cancho-log's own `trailtool`. Refusals are the rule tags of the design; no refusal may print a signature, and none may change the ledger except to cut a torn tail.
"""
import concurrent.futures, glob, hashlib, json, os, random, shutil, struct, subprocess, sys, tempfile, time
import coincurve
import rlp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import check_envelope as ce  # the model of the envelope and its cases

PKGS = os.environ.get("CANCHO_PACKAGES", os.path.join(ROOT, "../cancho/packages"))
SCHEMA = os.environ.get("CANCHO_SCHEMA", os.path.join(ROOT, "../alpibrusl/cancho-schema/src/schema.cho"))
LOGSRC = os.environ.get("CANCHO_LOG", os.path.join(ROOT, "../cancho-log/src"))
CONST = "/var/lib/cancho-signer"
ANCH = "/var/lib/cancho-anchor"   # the anchor's directory; a copy of the binary is built with <state>-anchor in its place


def sources(libdir):
    lib = lambda *p: os.path.join(libdir, *p)
    eth = [os.path.join(ROOT, "lib/eth", f) for f in ("hex.cho", "address.cho", "rlp.cho", "txcheck.cho")]
    return ([lib("signer/signer.cho"), os.path.join(ROOT, "lib/keccak/keccak.cho")] + eth + [lib("envelope/envelope.cho"), os.path.join(ROOT, "lib/policy/policy.cho"), os.path.join(ROOT, "lib/policy/decide.cho"),
            os.path.join(ROOT, "lib/intent/intent.cho"), SCHEMA] + [os.path.join(PKGS, "secp256k1", f) for f in ("secp256k1.cho", "comb.cho", "field.cho", "scalar.cho")]
            + [os.path.join(LOGSRC, f) for f in ("crc.cho", "record.cho", "segment.cho", "log.cho", "trail.cho")])


def build(cancho, libdir, main_text, state_dir, out):
    with tempfile.TemporaryDirectory() as t:
        main = os.path.join(t, "main.cho")
        open(main, "w").write(main_text.replace(CONST, state_dir).replace(ANCH, state_dir + "-anchor"))
        os.makedirs(state_dir + "-anchor", exist_ok=True)
        r = subprocess.run([cancho, "build", "--std", main, *sources(libdir), "-o", out], capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("build failed:\n" + r.stderr[:1500])


FAILS = []
COUNT = [0]


def check(name, got, want=True):
    COUNT[0] += 1
    if got != want:
        FAILS.append(name)
        if len(FAILS) <= 15:
            print(f"FAIL {name}: got {got!r}, want {want!r}")


# ---- the state directory
class State:
    def __init__(self, path, exe):
        self.dir, self.exe = path, exe
        self.adir = path + "-anchor"
        os.makedirs(self.adir, exist_ok=True)
        self.extra = []   # other directories a harness keeps with this one (the front's), cleared with it
        self.wit = None   # what a front that keeps the last answered anchor would send: "<count> <head>", or None for "-" (design section 20)

    def anchor(self):
        return os.path.join(self.adir, "anchor")

    def anchor_text(self):
        return open(self.anchor(), "rb").read() if os.path.isfile(self.anchor()) else None

    def adopt(self, count=None, head=None):
        """What an operator does for a ledger that exists: write the anchor from its count and head, as the independent reader gives them."""
        ev = read_events(self.ledger())
        n = len(ev) if count is None else count
        h = read_events.ids[n - 1] if head is None else head
        open(self.anchor(), "wb").write(f"{n} ".encode() + h + b"\n")
        self.wit = f"{n} {h.decode()}"

    def reset(self, c=None, conf=True, key=True):
        self.wit = None
        for d in (self.dir, self.adir, *self.extra):
            for f in os.listdir(d):
                p = os.path.join(d, f)
                if os.path.islink(p) or os.path.isfile(p):
                    os.unlink(p)
                else:
                    shutil.rmtree(p)
        if c is not None:
            if conf:
                open(os.path.join(self.dir, "signer.conf"), "w").write(f"issuer={c.issuer.hex()}\nchain={c.tx.chain}\n")
            if key:
                open(os.path.join(self.dir, "wallet.key"), "w").write(c.wallet_key.hex() + "\n")

    def ledger(self):
        return os.path.join(self.dir, "ledger.seg")

    def run(self, c, env=None, sig=None, msg=None, caller=None, line=None, pre=None, witness=None):
        e = c.env if env is None else env
        s = sig if sig is not None else ce.sign(ce.env_digest(e), c.issuer_key)
        m = c.tx.unsigned() if msg is None else msg
        w = witness if witness is not None else (self.wit or "-")
        text = line if line is not None else f"{e.hex()} {s.hex()} {m.hex()} {(c.caller if caller is None else caller).hex()} {w}"
        p = subprocess.run([self.exe], input=(text + "\n").encode(), capture_output=True, timeout=120)
        out = p.stdout.decode().strip()
        try:
            j = json.loads(out)
        except ValueError:
            j = None
        if witness is None and line is None and j and j.get("ok") and "anchor" in j:
            self.wit = f"{j['anchor']['count']} {j['anchor']['head']}"
        return p.returncode, j, out


def live_case(rng, ttl=300, issued=-5, decided=-10):
    c = ce.Case(rng)
    T = int(time.time())
    c.decided, c.now, c.expires = T + decided, T + issued, T + ttl
    c.decision = ce.decision_record(c.decision[4:36], c.decision[36:68], c.decided, c.expires, c.tx.amount, c.caller)
    c.env = ce.layout(c)
    return c


def with_nonce(c, nonce):
    """The same case for another transaction under the same envelope id."""
    import copy
    d = copy.copy(c)
    d.tx = copy.copy(c.tx)
    d.tx.nonce = nonce
    d.env = ce.layout(d)
    return d


# ---- the independent reader of the ledger: the record layout (cancho-log design section 4) and lex-trail's event id (its SPEC section 1)
def crc32c(data):
    c = 0xFFFFFFFF
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
    return c ^ 0xFFFFFFFF


def read_events(path):
    data = open(path, "rb").read()
    at, events, parent, ids = 0, [], b"", []
    while at < len(data):
        (length,) = struct.unpack_from("<I", data, at)
        body = data[at + 8:at + 4 + length]
        assert len(body) == length - 4 and struct.unpack_from("<I", data, at + 4)[0] == crc32c(body), "bad record"
        ms, seq, fields = struct.unpack_from("<QQI", body, 0)
        p, pairs = 20, []
        for _ in range(fields):
            (kl,) = struct.unpack_from("<I", body, p)
            k = body[p + 4:p + 4 + kl]
            p += 4 + kl
            (vl,) = struct.unpack_from("<I", body, p)
            pairs.append((k, body[p + 4:p + 4 + vl]))
            p += 4 + vl
        d = dict(pairs)
        eid = hashlib.sha256(b"\0".join([d[b"kind"], d[b"parent"], d[b"payload"], d[b"ts_ms"]])).hexdigest().encode()
        assert d[b"id"] == eid and d[b"parent"] == parent, "bad event"
        try:
            payload = json.loads(d[b"payload"])
        except ValueError:
            payload = None   # an event that is not a ledger entry still has an id
        events.append((d[b"kind"], payload, int(d[b"ts_ms"])))
        parent = eid
        ids.append(eid)
        at += 4 + length
    read_events.ids = ids
    return events


def write_chain(path, events):
    """A ledger file written here: [(kind, payload bytes, ts)], each event's parent the one before (the model of cancho-log's `trail_sweep.py`)."""
    out, parent, pms, pseq = b"", b"", -1, -1
    for kind, payload, ts in events:
        eid = hashlib.sha256(b"\0".join([kind, parent, payload, str(ts).encode()])).hexdigest().encode()
        ms = max(ts, pms)
        seq = pseq + 1 if ms == pms else 0
        body = struct.pack("<QQI", ms, seq, 5)
        for k, v in ((b"id", eid), (b"kind", kind), (b"parent", parent), (b"payload", payload), (b"ts_ms", str(ts).encode())):
            body += struct.pack("<I", len(k)) + k + struct.pack("<I", len(v)) + v
        out += struct.pack("<II", len(body) + 4, crc32c(body)) + body
        parent, pms, pseq = eid, ms, seq
    open(path, "wb").write(out)
    return out


def ledger_record_offsets(path):
    data = open(path, "rb").read()
    at, offs = 0, []
    while at < len(data):
        offs.append(at)
        at += 4 + struct.unpack_from("<I", data, at)[0]
    return offs


def expect_refusal(name, res, tag, state=None, ledger_before=None):
    rc, j, out = res
    check(f"{name}: exit status 2", rc, 2)
    check(f"{name}: the rule tag is chain.{tag}", (j or {}).get("rule"), "chain." + tag)
    check(f"{name}: a repair and no signature", ("repair" in (j or {})) and ('"signature":' not in out), True)
    check(f"{name}: ok is false", (j or {}).get("ok"), False)
    if state is not None and ledger_before is not None:
        now = open(state.ledger(), "rb").read() if os.path.exists(state.ledger()) else b""
        check(f"{name}: the ledger is as it was", now, ledger_before)


def run_checks(st, trailtool, cancho, rng, slow):
    # (1) a valid request: the signature is the model's, libsecp256k1's, python-ecdsa's and eth-account's
    for i in range(6):
        c = live_case(rng)
        st.reset(c)
        t0 = time.time()
        rc, j, out = st.run(c)
        t1 = time.time()
        check(f"valid {i}: exit 0 and ok", (rc, (j or {}).get("ok"), (j or {}).get("entry")), (0, True, "fresh"))
        if not j or not j.get("ok"):
            continue
        sig = bytes.fromhex(j["signature"])
        tdigest = ce.kec(c.tx.unsigned())
        check(f"valid {i}: the model's signature (libsecp256k1, RFC 6979)", sig, ce.sign(tdigest, c.wallet_key))
        pub = coincurve.PublicKey.from_signature_and_message(sig, tdigest, hasher=None).format(compressed=False)
        check(f"valid {i}: it recovers to the wallet", ce.kec(pub[1:])[12:], c.wallet)
        check(f"valid {i}: python-ecdsa verifies it", ce.ecdsa_verify(pub[1:], sig[:64], tdigest), True)
        raw = bytes(c.tx.signed(c.wallet_key))
        items = rlp.decode(raw[1:])
        yp, r, s = items[-3], items[-2], items[-1]
        check(f"valid {i}: eth-account signs the same transaction with the same r, s and parity", (int.from_bytes(r, "big").to_bytes(32, "big") + int.from_bytes(s, "big").to_bytes(32, "big"), int.from_bytes(yp, "big") if yp else 0), (sig[:64], sig[64]))
        ev = read_events(st.ledger())
        check(f"valid {i}: one ledger event: {c.env[1:33].hex()}", [(k, p) for k, p, t in ev], [(b"envelope.consumed", {"id": c.env[1:33].hex(), "digest": tdigest.hex()})])
        check(f"valid {i}: the event time is the signer's clock, in milliseconds", t0 - 0.01 <= ev[0][2] / 1000 <= t1 + 0.01, True)
        # (2) the same envelope again is the same transaction: the same bytes, no second entry
        rc2, j2, _ = st.run(c)
        check(f"valid {i}: a retry gets the same signature and says so", (rc2, (j2 or {}).get("signature"), (j2 or {}).get("entry")), (0, j["signature"], "same"))
        check(f"valid {i}: and writes nothing", len(read_events(st.ledger())), 1)
    # the ledger as cancho-log's own tool reads it
    c = live_case(rng)
    st.reset(c)
    st.run(c)
    with tempfile.TemporaryDirectory() as t:
        shutil.copy(st.ledger(), os.path.join(t, "0.seg"))
        v = subprocess.run([trailtool, "verify", t], capture_output=True, text=True).stdout.split()
        check("trailtool verifies the ledger: clean, one event", (v[1], v[5]), ("0", "1"))
    # (3) many envelopes in one ledger, each once; and a different id for the same transaction is another entry
    c = live_case(rng)
    st.reset(c)
    ids = []
    for k in range(5):
        d = with_nonce(c, c.tx.nonce)  # same tx; the id differs per envelope
        d.id = bytes([k + 1]) * 32
        d.env = ce.layout(d)
        ids.append(d.id)
        rc, j, _ = st.run(d)
        check(f"five envelopes: the {k + 1}th is fresh", (rc, (j or {}).get("entry")), (0, "fresh"))
    check("five envelopes: five chained events", [p["id"] for _, p, _ in read_events(st.ledger())], [i.hex() for i in ids])
    d = with_nonce(c, c.tx.nonce)
    d.id = ids[2]
    d.env = ce.layout(d)
    rc, j, _ = st.run(d)
    check("an id used before, for the same transaction, is the same entry", (rc, (j or {}).get("entry")), (0, "same"))
    # (4) the refusals of the envelope, as rule tags, and nothing is written
    base = live_case(rng)
    other_key = (rng.randrange(1, ce.N)).to_bytes(32, "big")
    cases = []
    st.reset(base)
    cases.append(("signed by another key", dict(sig=ce.sign(ce.env_digest(base.env), other_key)), "envelope-issuer"))
    cases.append(("a malformed signature", dict(sig=bytes(32) + ce.sign(ce.env_digest(base.env), base.issuer_key)[32:]), "envelope-signature"))
    cases.append(("a truncated envelope", dict(env=base.env[:-1], sig=ce.sign(ce.env_digest(base.env), base.issuer_key)), "envelope-format"))
    cases.append(("another caller", dict(caller=bytes([base.caller[0] ^ 1]) + base.caller[1:]), "envelope-caller"))
    cases.append(("another transaction", dict(msg=base.tx.unsigned()[:-1] + bytes([base.tx.unsigned()[-1] ^ 1])), "envelope-digest"))
    e2 = ce.layout(base, recipient=bytes([base.tx.recipient[0] ^ 1]) + base.tx.recipient[1:])
    cases.append(("a transaction that is not the envelope's expectation", dict(env=e2, sig=ce.sign(ce.env_digest(e2), base.issuer_key)), "envelope-transaction-invalid"))
    for name, kw, tag in cases:
        st.reset(base)
        expect_refusal(name, st.run(base, **kw), tag, st, b"")
    for name, c2, tag in (("an expired envelope", live_case(rng, ttl=-10, issued=-100, decided=-120), "envelope-expired"), ("an envelope not yet valid", live_case(rng, ttl=500, issued=300, decided=290), "envelope-not-yet-valid")):
        st.reset(c2)
        expect_refusal(name, st.run(c2), tag, st, b"")
    # configuration against the envelope: the chain, the wallet
    c = live_case(rng)
    st.reset(c)
    open(os.path.join(st.dir, "signer.conf"), "w").write(f"issuer={c.issuer.hex()}\nchain={c.tx.chain + 1}\n")
    expect_refusal("the signer's chain differs", st.run(c), "envelope-chain", st, b"")
    st.reset(c)
    open(os.path.join(st.dir, "wallet.key"), "w").write((rng.randrange(1, ce.N)).to_bytes(32, "big").hex() + "\n")
    expect_refusal("the signer's wallet differs", st.run(c), "envelope-wallet", st, b"")
    st.reset(c)
    open(os.path.join(st.dir, "signer.conf"), "w").write(f"issuer={ce.address_of(other_key).hex()}\nchain={c.tx.chain}\n")
    expect_refusal("the signer's issuer differs", st.run(c), "envelope-issuer", st, b"")
    # a different transaction under a used id
    c = live_case(rng)
    st.reset(c)
    st.run(c)
    before = open(st.ledger(), "rb").read()
    expect_refusal("an envelope id used for another transaction", st.run(with_nonce(c, c.tx.nonce + 1)), "envelope-replayed", st, before)
    # (5) configuration and key
    c = live_case(rng)
    for name, conf, key, tag in (
        ("no signer.conf", None, c.wallet_key.hex() + "\n", "signer-config"),
        ("an issuer of 39 digits", f"issuer={c.issuer.hex()[:-1]}\nchain=1\n", c.wallet_key.hex() + "\n", "signer-config"),
        ("an upper-case issuer", f"issuer={c.issuer.hex().upper()}\nchain=1\n", c.wallet_key.hex() + "\n", "signer-config"),
        ("a chain with a leading zero", f"issuer={c.issuer.hex()}\nchain=01\n", c.wallet_key.hex() + "\n", "signer-config"),
        ("a chain that is not a number", f"issuer={c.issuer.hex()}\nchain=1x\n", c.wallet_key.hex() + "\n", "signer-config"),
        ("issuer with a colon instead of =", f"issuer:{c.issuer.hex()}\nchain=1\n", c.wallet_key.hex() + "\n", "signer-config"),
        ("chain with a colon instead of =", f"issuer={c.issuer.hex()}\nchain:1\n", c.wallet_key.hex() + "\n", "signer-config"),
        ("the issuer's last digit in upper case", f"issuer={c.issuer.hex()[:-1]}A\nchain=1\n", c.wallet_key.hex() + "\n", "signer-config"),
        ("the issuer's first digit in upper case", f"issuer=A{c.issuer.hex()[1:]}\nchain=1\n", c.wallet_key.hex() + "\n", "signer-config"),
        ("a chain of 19 digits", f"issuer={c.issuer.hex()}\nchain=9999999999999999999\n", c.wallet_key.hex() + "\n", "signer-config"),
        ("an empty chain", f"issuer={c.issuer.hex()}\nchain=\n", c.wallet_key.hex() + "\n", "signer-config"),
        ("a chain with a colon in it", f"issuer={c.issuer.hex()}\nchain=1:\n", c.wallet_key.hex() + "\n", "signer-config"),
        ("a chain with a slash in it", f"issuer={c.issuer.hex()}\nchain=1/\n", c.wallet_key.hex() + "\n", "signer-config"),
        ("a config longer than the buffer", f"issuer={c.issuer.hex()}\nchain=1\n" + " " * 300, c.wallet_key.hex() + "\n", "signer-config"),
        ("a key of 66 digits", f"issuer={c.issuer.hex()}\nchain={c.tx.chain}\n", c.wallet_key.hex() + "00\n", "signer-key"),
        ("a key file longer than the buffer", f"issuer={c.issuer.hex()}\nchain={c.tx.chain}\n", c.wallet_key.hex() + " " * 200, "signer-key"),
        ("a third line", f"issuer={c.issuer.hex()}\nchain=1\nextra=1\n", c.wallet_key.hex() + "\n", "signer-config"),
        ("the lines swapped", f"chain=1\nissuer={c.issuer.hex()}\n", c.wallet_key.hex() + "\n", "signer-config"),
        ("no wallet.key", f"issuer={c.issuer.hex()}\nchain={c.tx.chain}\n", None, "signer-key"),
        ("a key of 63 digits", f"issuer={c.issuer.hex()}\nchain={c.tx.chain}\n", c.wallet_key.hex()[:-1] + "\n", "signer-key"),
        ("a key that is not hex", f"issuer={c.issuer.hex()}\nchain={c.tx.chain}\n", "zz" + c.wallet_key.hex()[2:] + "\n", "signer-key"),
        ("a zero key", f"issuer={c.issuer.hex()}\nchain={c.tx.chain}\n", "00" * 32 + "\n", "signer-key"),
        ("the issuer is the wallet", f"issuer={c.wallet.hex()}\nchain={c.tx.chain}\n", c.wallet_key.hex() + "\n", "signer-same-key"),
    ):
        st.reset()
        if conf is not None:
            open(os.path.join(st.dir, "signer.conf"), "w").write(conf)
        if key is not None:
            open(os.path.join(st.dir, "wallet.key"), "w").write(key)
        expect_refusal(name, st.run(c), tag, st, b"")
    st.reset(c)
    open(os.path.join(st.dir, "wallet.key"), "w").write(c.wallet_key.hex())  # no newline: allowed
    check("a key without a final newline is accepted", st.run(c)[0], 0)
    # (6) the request line
    st.reset(c)
    ok = f"{c.env.hex()} {ce.sign(ce.env_digest(c.env), c.issuer_key).hex()} {c.tx.unsigned().hex()} {c.caller.hex()}"
    parts = ok.split()
    for name, line in (("an empty line", ""), ("three fields", " ".join(parts[:3])), ("five fields", ok + " 00"), ("an odd number of digits", ok[:-1]), ("a digit that is not hex", ok[:-1] + "g"),
                       ("a double space", ok.replace(" ", "  ", 1)), ("a line over 4096 bytes", ok + " " + "0" * 5000), ("a trailing space", ok + " "), ("a double space with four fields", f"{parts[0]}  {parts[1]} {parts[2]}"), ("an empty field", f"{parts[0]} {parts[1]} {parts[2]} ")):
        st.reset(c)
        expect_refusal(name, st.run(c, line=line), "signer-request", st, b"")
    # (7) the ledger: damage is never repaired by cutting anything but a torn tail, and a ledger that does not verify signs nothing
    c = live_case(rng)
    envs = []
    for k in range(4):
        d = with_nonce(c, c.tx.nonce)
        d.id = bytes([0x40 + k]) * 32
        d.env = ce.layout(d)
        envs.append(d)

    def filled(n):
        st.reset(c)
        for d in envs[:n]:
            assert st.run(d)[0] == 0
        return open(st.ledger(), "rb").read()

    good = filled(3)
    offs = ledger_record_offsets(st.ledger())
    # a torn tail shorter than a record is cut, and the ledger goes on
    open(st.ledger(), "ab").write(good[offs[2]:offs[2] + 17])
    rc, j, _ = st.run(envs[1])
    check("a torn tail is cut and an earlier envelope is the same entry", (rc, (j or {}).get("entry")), (0, "same"))
    check("a torn tail: the ledger is back to its whole records", open(st.ledger(), "rb").read(), good)
    rc, j, _ = st.run(envs[3])
    check("after the cut the next envelope is fresh and the chain goes on", (rc, (j or {}).get("entry"), len(read_events(st.ledger()))), (0, "fresh", 4))
    # damage in the middle, in any of its forms
    flips = {
        "a flipped payload byte in the middle record": lambda b: b[:offs[1] + 60] + bytes([b[offs[1] + 60] ^ 1]) + b[offs[1] + 61:],
        "a flipped length byte in the middle record": lambda b: b[:offs[1]] + bytes([b[offs[1]] ^ 0x40]) + b[offs[1] + 1:],
        "a flipped checksum byte in the first record": lambda b: b[:offs[0] + 5] + bytes([b[offs[0] + 5] ^ 1]) + b[offs[0] + 6:],
        "a flipped byte in the last record": lambda b: b[:-5] + bytes([b[-5] ^ 1]) + b[-4:],
        "a deleted middle record": lambda b: b[:offs[1]] + b[offs[2]:],
        "the first record deleted": lambda b: b[offs[1]:],
        "two records swapped": lambda b: b[:offs[0]] + b[offs[1]:offs[2]] + b[offs[0]:offs[1]] + b[offs[2]:],
        "a zeroed block in the middle": lambda b: b[:offs[1] + 8] + bytes(40) + b[offs[1] + 48:],
        "a long garbage tail": lambda b: b + bytes(range(256)) * 20,
    }
    for name, f in flips.items():
        st.reset(c)
        damaged = f(good)
        open(st.ledger(), "wb").write(damaged)
        res = st.run(envs[0])
        expect_refusal(name, res, "signer-ledger-corrupt", st, damaged)
    # an event that verifies as an event but is not a ledger entry
    st.reset(c)
    # an event that verifies as an event but is not a ledger entry
    for name, payload in (("a payload of another shape", b'{"id":"' + b"0" * 64 + b'"}'), ("an upper-case digit in the payload", b'{"id":"' + b"A" * 64 + b'","digest":"' + b"0" * 64 + b'"}'),
                          ("an empty payload", b""),
                          ("a payload with another quote", b"{\"id\":\"" + b"0" * 64 + b"\",\"digest\":'" + b"0" * 64 + b"\"}"), ("a payload one byte too long", b"{\"id\":\"" + b"0" * 64 + b"\",\"digest\":\"" + b"0" * 64 + b"\"} ")):
        st.reset(c)
        write_chain(st.ledger(), [(b"envelope.consumed", payload, 1000)])
        st.adopt()
        raw = open(st.ledger(), "rb").read()
        expect_refusal("a whole event with " + name, st.run(envs[0]), "signer-ledger-corrupt", st, raw)
    # a ledger the signer wrote, extended by a model-written chain that is valid, is read
    st.reset(c)
    entries = [(b"envelope.consumed", json.dumps({"id": d.id.hex(), "digest": ce.kec(d.tx.unsigned()).hex()}, separators=(",", ":")).encode(), 1000 + i) for i, d in enumerate(envs[:3])]
    write_chain(st.ledger(), entries)
    st.adopt()
    rc, j, _ = st.run(envs[1])
    check("a ledger written by the model is read: an entry in it is the same", (rc, (j or {}).get("entry")), (0, "same"))
    rc, j, _ = st.run(envs[3])
    check("and a new envelope is fresh after it", (rc, (j or {}).get("entry"), len(read_events(st.ledger()))), (0, "fresh", 4))
    # (7b) the anchor (docs/design.md section 19)
    def anchor_of(path):
        read_events(path)
        ids = read_events.ids
        return (len(ids), ids[-1].decode()) if ids else (0, "")

    def refused_unchanged(name, tag, witness=None, env=None):
        """A request that must be refused with `tag`, with the ledger and the anchor exactly as they were."""
        led = open(st.ledger(), "rb").read() if os.path.exists(st.ledger()) else b""
        anc = st.anchor_text()
        expect_refusal(name, st.run(envs[0] if env is None else env, witness=witness), tag)
        check(f"{name}: the ledger is untouched (nothing is cut)", open(st.ledger(), "rb").read() if os.path.exists(st.ledger()) else b"", led)
        check(f"{name}: the anchor is untouched", st.anchor_text(), anc)

    # after each fresh request the anchor is (count, head) as the independent reader computes them, in the file and in the answer; a retry changes neither
    st.reset(c)
    for k, d in enumerate(envs):
        rc, j, out = st.run(d)
        count, head = anchor_of(st.ledger())
        check(f"anchor after request {k + 1}: the file is `<count> <head>` and a newline", st.anchor_text(), f"{count} {head}\n".encode())
        check(f"anchor after request {k + 1}: the answer carries the same", (j or {}).get("anchor"), {"count": count, "head": head})
        before = st.anchor_text()
        rc, j, out = st.run(d)
        check(f"anchor after a retry {k + 1}: the same entry, the same anchor", ((j or {}).get("entry"), st.anchor_text(), (j or {}).get("anchor")), ("same", before, {"count": count, "head": head}))
    with tempfile.TemporaryDirectory() as t:
        shutil.copy(st.ledger(), os.path.join(t, "0.seg"))
        count, head = anchor_of(st.ledger())
        v = subprocess.run([trailtool, "verify", t, str(count), head], capture_output=True, text=True).stdout.split()
        check("trailtool confirms the signer's anchor against the ledger", v[v.index("anchor") + 1], "1")
    good = filled(3)
    offs = ledger_record_offsets(st.ledger())
    c3, h3 = anchor_of(st.ledger())
    sig2 = st.run(envs[2])[1]["signature"]
    # no anchor with entries: refused, and it is not made up
    os.unlink(st.anchor())
    refused_unchanged("no anchor and a ledger of three", "signer-anchor-missing")
    # no anchor and exactly one entry is what a crash at the first entry leaves: covered, and it goes on
    st.reset(c)
    st.run(envs[0])
    os.unlink(st.anchor())
    rc, j, out = st.run(envs[0])
    check("no anchor and one entry: covered, the same entry", (rc, (j or {}).get("entry"), st.anchor_text()), (0, "same", f"1 {anchor_of(st.ledger())[1]}\n".encode()))
    st.reset(c)
    for d in envs[:2]:
        st.run(d)
    os.unlink(st.anchor())
    refused_unchanged("no anchor and a ledger of two", "signer-anchor-missing")
    # an anchor that is not exactly what the signer writes
    h = h3
    for name, text in (("a leading zero", f"03 {h}\n"), ("a count of zero", f"0 {h}\n"), ("a count over the limit", f"65537 {h}\n"), ("a six-digit count", f"100000 {h}\n"), ("no newline", f"3 {h}"),
                       ("two newlines", f"3 {h}\n\n"), ("two lines", f"3 {h}\n3 {h}\n"), ("upper-case digits", f"3 {h.upper()}\n"), ("a head of 63 digits", f"3 {h[:-1]}\n"), ("a head of 65 digits", f"3 {h}0\n"),
                       ("a tab for the space", f"3\t{h}\n"), ("two spaces", f"3  {h}\n"), ("an empty file", ""), ("a count that is not a number", f"x {h}\n"), ("a head that is not hex", f"3 {'g' * 64}\n"),
                       ("a sign on the count", f"+3 {h}\n"), ("a colon in the count", f"3: {h}\n"), ("a carriage return", f"3 {h}\r\n"), ("a file much longer than an anchor", f"3 {h}\n" + "0" * 5000)):
        open(st.anchor(), "w").write(text)
        refused_unchanged(f"an anchor with {name}", "signer-anchor-corrupt")
    os.unlink(st.anchor())
    os.mkdir(st.anchor())
    refused_unchanged("an anchor that is a directory", "signer-anchor-corrupt")
    os.rmdir(st.anchor())
    # a corrupt anchor with an empty ledger is refused too (it is not "no anchor")
    st.reset(c)
    open(st.anchor(), "w").write("zzz\n")
    expect_refusal("a corrupt anchor and an empty ledger", st.run(envs[0]), "signer-anchor-corrupt")
    # the ledger cut below the anchor: at every record boundary, the whole ledger or nothing
    for cut in (0, offs[1], offs[2]):
        st.reset(c)
        open(st.ledger(), "wb").write(good[:cut])
        open(st.anchor(), "w").write(f"{c3} {h3}\n")
        refused_unchanged(f"a ledger cut to {cut} bytes below an anchor of three", "signer-anchor-short")
    # a torn or damaged last record that the anchor covers is refused, not cut: the length field of the last record, damaged in each of its four bytes
    for b in range(4):
        for bit in (0x01, 0x40):
            st.reset(c)
            damaged = good[:offs[2] + b] + bytes([good[offs[2] + b] ^ bit]) + good[offs[2] + b + 1:]
            open(st.ledger(), "wb").write(damaged)
            open(st.anchor(), "w").write(f"{c3} {h3}\n")
            res = st.run(envs[2])
            tag = (res[1] or {}).get("rule")
            check(f"a damaged length (byte {b}, bit {bit:#x}) of a covered last record: refused, never signed, never cut", (res[0], tag in ("chain.signer-anchor-short", "chain.signer-ledger-corrupt"), open(st.ledger(), "rb").read(), '"signature"' in res[2]), (2, True, damaged, False))
    # ... and one beyond the anchor was never signed, so it is cut (the one case section 14.5 could not decide)
    st.reset(c)
    open(st.ledger(), "wb").write(good[:offs[2]])
    h2 = anchor_of(st.ledger())[1]
    cut_seen = 0
    for b in range(4):
        for bit in (0x01, 0x40, 0x80):
            st.reset(c)
            damaged = good[:offs[2] + b] + bytes([good[offs[2] + b] ^ bit]) + good[offs[2] + b + 1:]
            open(st.ledger(), "wb").write(damaged)
            open(st.anchor(), "w").write(f"2 {h2}\n")
            st.wit = f"2 {h2}"
            rc, j, out = st.run(envs[2])
            if rc == 0:
                # the record only looked torn: it is cut, it was never signed, so the entry is fresh and now covered
                cut_seen += 1
                check(f"a damaged length (byte {b}, bit {bit:#x}) of a last record beyond the anchor: cut, and the entry is fresh and signed", ((j or {}).get("entry"), len(read_events(st.ledger()))), ("fresh", 3))
                check(f"a damaged length (byte {b}, bit {bit:#x}) beyond the anchor: the anchor now covers three entries", st.anchor_text(), f"3 {anchor_of(st.ledger())[1]}\n".encode())
            else:
                check(f"a damaged length (byte {b}, bit {bit:#x}) that does not look torn, beyond the anchor: refused as corrupt, nothing cut", ((j or {}).get("rule"), open(st.ledger(), "rb").read()), ("chain.signer-ledger-corrupt", damaged))
    check("at least one damaged length looks torn and is cut (the case of design 14.5)", cut_seen >= 1, True)
    # the ledger rewritten consistently (another entry at the anchor's count): refused
    st.reset(c)
    evs = [(b"envelope.consumed", json.dumps({"id": d.id.hex(), "digest": ce.kec(d.tx.unsigned()).hex()}, separators=(",", ":")).encode(), 1000 + i) for i, d in enumerate(envs[:3])]
    write_chain(st.ledger(), evs)
    st.adopt()
    other = evs[:2] + [(b"envelope.consumed", json.dumps({"id": "ab" * 32, "digest": "cd" * 32}, separators=(",", ":")).encode(), 1002)]
    write_chain(st.ledger(), other)
    refused_unchanged("a ledger rewritten consistently with another third entry", "signer-anchor-mismatch")
    write_chain(st.ledger(), [(b"envelope.consumed", json.dumps({"id": "ab" * 32, "digest": "cd" * 32}, separators=(",", ":")).encode(), 1000 + i) for i in range(3)])
    refused_unchanged("a ledger rewritten whole with the same number of entries", "signer-anchor-mismatch")
    # a ledger longer than the anchor by more than one: the anchor was restored from an older copy
    st.reset(c)
    for d in envs:
        st.run(d)
    st.adopt(count=2)
    refused_unchanged("a ledger of four and an anchor of two", "signer-anchor-behind")
    st.adopt(count=1)
    refused_unchanged("a ledger of four and an anchor of one", "signer-anchor-behind")
    # a ledger one ahead of its anchor is what a crash between the flush and the anchor write leaves: the next start covers it, before any signature
    st.reset(c)
    for d in envs[:3]:
        st.run(d)
    st.adopt(count=2)
    rc, j, out = st.run(envs[2])
    check("one ahead of the anchor: the entry is the same, signed, and the anchor now covers it", (rc, (j or {}).get("entry"), st.anchor_text()), (0, "same", f"3 {anchor_of(st.ledger())[1]}\n".encode()))
    check("one ahead of the anchor: the signature is the one a clean run gives", (j or {}).get("signature"), sig2)
    st.adopt(count=2)
    rc, j, out = st.run(envs[3])
    check("one ahead of the anchor: a fresh envelope is appended and the anchor covers four", (rc, (j or {}).get("entry"), st.anchor_text()), (0, "fresh", f"4 {anchor_of(st.ledger())[1]}\n".encode()))
    # an anchor and no ledger
    st.reset(c)
    open(st.anchor(), "w").write(f"1 {'0' * 64}\n")
    expect_refusal("an anchor and no ledger", st.run(envs[0]), "signer-anchor-short")
    # the anchor cannot be written: no signature; the entry is on the ledger, and the next run covers it and signs
    st.reset(c)
    os.symlink("/dev/full", os.path.join(st.adir, "anchor.new"))
    res = st.run(envs[0])
    expect_refusal("an anchor that cannot be written (/dev/full)", res, "signer-anchor-write")
    check("an anchor that cannot be written: the entry is on the ledger and there is no anchor", (len(read_events(st.ledger())), st.anchor_text()), (1, None))
    os.unlink(os.path.join(st.adir, "anchor.new"))
    rc, j, out = st.run(envs[0])
    check("the next run: the same entry, the anchor covers it, and the signature is the model's", (rc, (j or {}).get("entry"), st.anchor_text(), (j or {}).get("signature")), (0, "same", f"1 {anchor_of(st.ledger())[1]}\n".encode(), ce.sign(ce.kec(envs[0].tx.unsigned()), c.wallet_key).hex()))
    # a ledger that is not clean is refused as it was before, whatever the anchor says
    st.reset(c)
    for d in envs[:3]:
        st.run(d)
    damaged = good[:offs[1] + 60] + bytes([good[offs[1] + 60] ^ 1]) + good[offs[1] + 61:]
    open(st.ledger(), "wb").write(damaged)
    expect_refusal("damage in the middle, with an anchor", st.run(envs[0]), "signer-ledger-corrupt", st, damaged)
    # (7c) the front's witness (docs/design.md section 20)
    def wit_of(n):
        read_events(st.ledger())
        return f"{n} {read_events.ids[n - 1].decode()}"

    def four(n):
        st.reset(c)
        for d in envs[:n]:
            assert st.run(d)[0] == 0
        return n

    # equal, and one behind (the front crashed between the signature and its write): the same entry, signed; two behind: refused
    four(3)
    w3, w2, w1 = wit_of(3), wit_of(2), wit_of(1)
    rc, j, out = st.run(envs[2], witness=w2)
    check("a witness one behind the ledger: signed, and the answer's anchor is the ledger's", (rc, (j or {}).get("entry"), (j or {}).get("anchor", {}).get("count")), (0, "same", 3))
    refused_unchanged("a witness two behind the ledger", "signer-witness-behind", witness=w1)
    # a witness ahead of the ledger, and one naming another entry
    refused_unchanged("a witness ahead of the ledger", "signer-witness-short", witness=f"4 {'0' * 64}")
    refused_unchanged("a witness of 65,536 over a ledger of three", "signer-witness-short", witness=f"65536 {'0' * 64}")
    refused_unchanged("a witness that names another entry", "signer-witness-mismatch", witness=f"3 {'0' * 64}")
    refused_unchanged("a witness with the head of another entry", "signer-witness-mismatch", witness=f"2 {w3.split()[1]}")
    refused_unchanged("a witness with the right head and the wrong count", "signer-witness-mismatch", witness=f"2 {w1.split()[1]}")
    # no witness: allowed for at most one entry
    for n, ok_ in ((0, True), (1, True), (2, False), (3, False)):
        four(n)
        if ok_:
            rc, j, out = st.run(envs[0], witness="-")
            check(f"no witness and a ledger of {n}: signed", (rc, (j or {}).get("ok")), (0, True))
        else:
            refused_unchanged(f"no witness and a ledger of {n}", "signer-witness-missing", witness="-")
    # a restore: the ledger and the local anchor put back to an earlier state, together; the local anchor cannot see it, the witness does
    four(2)
    snap = (open(st.ledger(), "rb").read(), open(st.anchor(), "rb").read())
    for d in envs[2:]:
        st.run(d)
    w4 = st.wit
    open(st.ledger(), "wb").write(snap[0])
    open(st.anchor(), "wb").write(snap[1])
    refused_unchanged("a restore of the signer's directory to two entries, with the front's witness at four", "signer-witness-short", witness=w4)
    rc, j, out = st.run(envs[0], witness=wit_of(2))
    check("... the same restore with a witness that was restored too is accepted (the witness is only as independent as its directory)", (rc, (j or {}).get("entry")), (0, "same"))
    # the order of the checks: a ledger that the local anchor refuses is refused with the local anchor's tag whatever the witness says
    four(3)
    os.unlink(st.anchor())
    refused_unchanged("no local anchor and a good witness", "signer-anchor-missing", witness=w3)
    # a ledger that is not clean is refused as before, whatever the witness says
    four(3)
    damaged = good[:offs[1] + 60] + bytes([good[offs[1] + 60] ^ 1]) + good[offs[1] + 61:]
    open(st.ledger(), "wb").write(damaged)
    expect_refusal("damage in the middle, with a witness", st.run(envs[0]), "signer-ledger-corrupt", st, damaged)
    # the request line: four fields, a witness that is not one, six or seven fields
    four(1)
    e0 = envs[0]
    base = f"{e0.env.hex()} {ce.sign(ce.env_digest(e0.env), e0.issuer_key).hex()} {e0.tx.unsigned().hex()} {e0.caller.hex()}"
    h1 = wit_of(1).split()[1]   # this ledger's own: event ids hold the time, so another run's are not
    for name, tail in (("no witness field", None), ("an empty witness", ""), ("a witness of two dashes", "--"), ("a dash and a space", "- "), ("a dash and a head", f"- {h1}"), ("a count and no head", "1"),
                       ("a count with a leading zero", f"01 {h1}"), ("a count of zero", f"0 {h1}"), ("a head in upper case", f"1 {h1.upper()}"), ("a head of 63 digits", f"1 {h1[:-1]}"),
                       ("a head of 65 digits", f"1 {h1}0"), ("a witness with a trailing space", f"1 {h1} "), ("a witness with two spaces", f"1  {h1}"), ("a witness with another field after it", f"1 {h1} 00"),
                       ("a count over the limit", f"65537 {h1}"), ("a count that is not a number", f"x {h1}"), ("a tab for the space", f"1\t{h1}")):
        line = base if tail is None else f"{base} {tail}"
        expect_refusal(f"the request with {name}", st.run(c, line=line), "signer-request")
    base3 = " ".join(base.split()[:3])
    expect_refusal("a request with an empty caller field and no witness shift", st.run(c, line=f"{base3}  -"), "signer-request")
    expect_refusal("a request with an empty caller field and a witness", st.run(c, line=f"{base3}  1 {h1}"), "signer-request")
    rc, j, out = st.run(c, line=f"{base} 1 {h1}")
    check("a request with a good witness on the line is served", (rc, (j or {}).get("ok"), (j or {}).get("rule")), (0, True, None))
    # (8) no signature when the ledger cannot be written, and no second signer on one ledger
    st.reset(c)
    os.symlink("/dev/full", st.ledger())
    rc, j, out = st.run(c)
    expect_refusal("a ledger that cannot be written (/dev/full)", (rc, j, out), "signer-ledger-write")
    st.reset(c)
    os.symlink("/dev/null", st.ledger())
    expect_refusal("a ledger whose flush fails (/dev/null: the write succeeds, fsync does not)", st.run(c), "signer-ledger-write")
    st.reset(c)
    os.mkdir(st.ledger())
    expect_refusal("a ledger that is a directory", st.run(c), "signer-ledger-write")
    st.reset(c)
    open(st.ledger(), "wb").close()
    import fcntl
    fd = os.open(st.ledger(), os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    expect_refusal("a ledger another process holds locked", st.run(c), "signer-locked", st, b"")
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)
    rc, j, _ = st.run(c)
    check("the lock is gone with its holder", (rc, (j or {}).get("entry")), (0, "fresh"))
    check("the signer's own lock is gone when it exits", st.run(c)[0], 0)
    # the process is the real thing: no clock field, no way to name another directory, no key on any output
    c = live_case(rng)
    st.reset(c)
    rc, j, out = st.run(c)
    check("the key is nowhere on the output", c.wallet_key.hex() not in out and c.issuer_key.hex() not in out, True)
    p = subprocess.run([st.exe, "--now", "5", "/tmp"], input=(f"{c.env.hex()} {ce.sign(ce.env_digest(c.env), c.issuer_key).hex()} {c.tx.unsigned().hex()} {c.caller.hex()} -\n").encode(), capture_output=True)
    check("arguments are ignored: the answer is the same", p.returncode, 0)
    # (9) the authority: the one directory, the clock, standard input and output, and nothing else
    r = subprocess.run([cancho, "authority", "--std", os.path.join(ROOT, "tools/signer/main.cho"), *sources(os.path.join(ROOT, "lib"))], capture_output=True, text=True)
    if "cannot be evaluated" in r.stdout + r.stderr:
        # The Rust front end of a compiler built with cargo cannot run cancho's secp256k1 package's statics (they call a function, `fill_hex`); the self-hosted `cancho authority` can.
        # Said, not hidden: CI built with cargo prints this and does not check the signer's authority; run it with the self-hosted compiler (README) for that claim.
        print("SKIPPED: the signer's authority (this compiler's evaluator cannot run the secp256k1 package's statics: " + (r.stdout + r.stderr).strip().splitlines()[0][:160] + ")")
    else:
        perf = r.stdout.split("performs")[1].split("never touches")[0].split()
        check("authority: performs exactly these (two directories)", sorted(perf), sorted(["clock", "file_read", "file_write", f'fs_read("{CONST}")', f'fs_write("{CONST}")', f'fs_read("{ANCH}")', f'fs_write("{ANCH}")', "heap", "io_read", "io_write"]))
        check("authority: never touches the network, the command line, signals, other programs or foreign code", all(w in r.stdout for w in ("the network", "the command line", "signals", "other programs", "foreign code")), True)
    if slow:
        c = live_case(rng)
        st.reset(c)
        write_chain(st.ledger(), [(b"envelope.consumed", json.dumps({"id": i.to_bytes(32, "big").hex(), "digest": "0" * 64}, separators=(",", ":")).encode(), 1000) for i in range(65537)])
        st.adopt(count=65536)  # one behind the ledger: allowed, and then the ledger is full
        expect_refusal("a ledger over 65,536 entries", st.run(c), "signer-ledger-full", st)


# (name, file, old, new): `old` must occur exactly once in the file. "main" is tools/signer/main.cho, "signer" is lib/signer/signer.cho.
MUTANTS = [
    ("main: the issuer may be the wallet", "main", "} else if bytes_equal(wallet, issuer) {", "} else if false {"),
    ("main: a failed lock is ignored", "main", "Done::Failed(e) => {\n                                    locked = false;", "Done::Failed(e) => {\n                                    locked = true;"),
    ("main: any torn length is cut", "main", "tail < max_log_len() + 4", "tail < max_log_len() * 1000"),
    ("main: a ledger that is not clean is accepted", "main", "if v.0 == trail.clean() || v.0 == trail.torn() && tail < max_log_len() + 4 {", "if v.0 != 99 {"),
    ("main: a torn tail is refused", "main", "if v.0 == trail.clean() || v.0 == trail.torn() && tail < max_log_len() + 4 {", "if v.0 == trail.clean() {"),
    ("main: the entry is looked up by the wrong bytes", "main", "envelope.ledger_check(ledger, env[1..33], env[65..97])", "envelope.ledger_check(ledger, env[33..65], env[65..97])"),
    ("main: the digest is looked up by the wrong bytes", "main", "envelope.ledger_check(ledger, env[1..33], env[65..97])", "envelope.ledger_check(ledger, env[1..33], env[33..65])"),
    ("main: a fresh entry is not written", "main", "    if seen == 0 {\n        // Fresh:", "    if seen == 7 {\n        // Fresh:"),
    ("main: a failed write does not stop the signature", "main", "if r.0 == 0 && log.flush(lg) == 0 {", "if true {"),
    ("main: a failed flush does not stop the signature", "main", "if r.0 == 0 && log.flush(lg) == 0 {", "if r.0 == 0 {"),
    ("main: the entry is not flushed", "main", "log.flush(lg) == 0", "log.size(lg) >= 0"),
    ("main: the event time", "main", "\"envelope.consumed\", parent[0..plen], body, ms, max_log_len()", "\"envelope.consumed\", parent[0..plen], body, ms + 1000000, max_log_len()"),
    ("main: the clock in seconds", "main", "ms / 1000, detail)", "ms / 100, detail)"),
    ("main: the signature is hedged", "main", "secp256k1.sign(env[65..97], key, sg[0..0], sg, work)", "secp256k1.sign(env[65..97], key, env[1..33], sg, work)"),
    ("main: the wrong digest is signed", "main", "secp256k1.sign(env[65..97], key", "secp256k1.sign(env[33..65], key"),
    ("main: the entry label is swapped", "main", "if seen == 0 {\n                say(io, \"\\\",\\\"entry\\\":\\\"fresh\\\",", "if seen == 1 {\n                say(io, \"\\\",\\\"entry\\\":\\\"fresh\\\","),
    ("main: a refusal exits 0", "main", "    io.newline(io);\n    return 2;\n}\n\n// The whole of the file", "    io.newline(io);\n    return 0;\n}\n\n// The whole of the file"),
    ("main: the first event names a parent", "main", "if log.records(lg) > 0 {\n                plen = 64;", "if true {\n                plen = 64;"),
    ("main: the parent is cut short", "main", "plen = 64;", "plen = 63;"),
    ("main: a line may be one byte over", "main", "if n >= len(out) {\n            return -275;", "if n > len(out) {\n            return -275;"),
    ("main: the file may be longer than its buffer", "main", "if size <= len(out) {", "if size <= len(out) + 1000000 {"),
    ("main: the ledger is read from the wrong pair", "main", "signer.parse_payload(window[p3.2..p3.2 + p3.3]", "signer.parse_payload(window[p2.2..p2.2 + p2.3]"),
    ("main: the ledger is read to the wrong place", "main", "ledger[k * 64..k * 64 + 32], ledger[k * 64 + 32..k * 64 + 64]", "ledger[k * 64 + 32..k * 64 + 64], ledger[k * 64..k * 64 + 32]"),
    ("signer: the config's issuer prefix", "signer", "let a = \"issuer=\";\n    var k = 0;\n    while k < 7 {", "let a = \"issuer=\";\n    var k = 0;\n    while k < 6 {"),
    ("signer: the issuer's last digit", "signer", "while k < 40 {\n        if !is_lower_hex(int_of(text[7 + k])) {", "while k < 39 {\n        if !is_lower_hex(int_of(text[7 + k])) {"),
    ("signer: the issuer may be upper case", "signer", "fn is_lower_hex(c: int) -> [] bool {\n    return c >= 48 && c <= 57 || c >= 97 && c <= 102;", "fn is_lower_hex(c: int) -> [] bool {\n    return c >= 48 && c <= 57 || c >= 97 && c <= 102 || c >= 65 && c <= 70;"),
    ("signer: the newline after the issuer", "signer", "if int_of(text[47]) != 10 {", "if int_of(text[47]) != 32 {"),
    ("signer: the chain prefix", "signer", "let b = \"chain=\";\n    k = 0;\n    while k < 6 {", "let b = \"chain=\";\n    k = 0;\n    while k < 5 {"),
    ("signer: a chain with a leading zero", "signer", "digits > 1 && int_of(text[54]) == 48", "digits > 2 && int_of(text[54]) == 48"),
    ("signer: a chain of 19 digits", "signer", "digits < 1 || digits > 18 ||", "digits < 1 || digits > 19 ||"),
    ("signer: an empty chain", "signer", "digits < 1 || digits > 18 ||", "digits < 0 || digits > 18 ||"),
    ("signer: a chain digit", "signer", "if c < 48 || c > 57 {\n            return -276;", "if c < 48 || c > 58 {\n            return -276;"),
    ("signer: the chain's value", "signer", "chain = chain * 10 + (c - 48);", "chain = chain * 10 + (c - 47);"),
    ("signer: the final newline of the config", "signer", "if int_of(text[end - 1]) == 10 {\n        end = end - 1;", "if int_of(text[end - 1]) == 11 {\n        end = end - 1;"),
    ("signer: a key of 65 digits", "signer", "if n == 65 && int_of(text[64]) == 10 {", "if n >= 65 {"),
    ("signer: the payload's first byte", "signer", "var p = 0;\n    let a = \"{\\\"id\\\":\\\"\";\n    while p < 7 {", "var p = 1;\n    let a = \"{\\\"id\\\":\\\"\";\n    while p < 7 {"),
    ("signer: the payload's id offset", "signer", "hex.encode(id, out[7..71]);", "hex.encode(id, out[7..71]);\n    hex.encode(digest, out[7..71]);"),
    ("signer: the payload's digest offset", "signer", "hex.encode(digest, out[83..147]);", "hex.encode(id, out[83..147]);"),
    ("signer: a payload digit", "signer", "let inhex = k >= 7 && k < 71 || k >= 83 && k < 147;", "let inhex = k >= 7 && k < 71 || k >= 83 && k < 146;"),
    ("signer: the payload's first hex digit", "signer", "let inhex = k >= 7 && k < 71 || k >= 83 && k < 147;", "let inhex = k >= 8 && k < 71 || k >= 83 && k < 147;"),
    ("signer: the payload's text is not compared", "signer", "} else if int_of(text[k]) != int_of(m[k]) {", "} else if int_of(text[k]) == 1000 {"),
    ("signer: the payload's length", "signer", "if len(text) != 149 || len(id) != 32 || len(digest) != 32 {", "if len(text) < 149 || len(id) != 32 || len(digest) != 32 {"),
    ("signer: a refusal tag", "signer", "return \"signer-ledger-corrupt\";", "return \"signer-ledger-damaged\";"),
    ("signer: another refusal tag", "signer", "return \"signer-locked\";", "return \"signer-busy\";"),
    ("signer: the key's tag", "signer", "return \"signer-key\";", "return \"signer-wallet\";"),
    ("signer: the request's tag", "signer", "return \"signer-request\";", "return \"signer-line\";"),
    # the anchor (section 19)
    ("main: the anchor is not given to verify", "main", "head, an, ahead);", "head, 0, \"\");"),
    ("main: a missing anchor is accepted", "main", "if v.2 > 1 {\n                                                    arefuse = -281;", "if v.2 > 1000000 {\n                                                    arefuse = -281;"),
    ("main: a missing anchor with one entry is refused", "main", "if v.2 > 1 {\n                                                    arefuse = -281;", "if v.2 > 0 {\n                                                    arefuse = -281;"),
    ("main: a corrupt anchor is taken for a missing one", "main", "if ac == -280 {\n                                                arefuse = -280;", "if ac == -999 {\n                                                arefuse = -280;"),
    ("main: a cut ledger is accepted", "main", "} else if v.4 == trail.anchor_short() {", "} else if v.4 == 99 {"),
    ("main: a rewritten ledger is accepted", "main", "} else if v.4 == trail.anchor_mismatch() {", "} else if v.4 == 99 {"),
    ("main: an anchor far behind the ledger is accepted", "main", "} else if v.2 - ac > 1 {", "} else if v.2 - ac > 1000000 {"),
    ("main: a ledger one ahead of the anchor is refused", "main", "} else if v.2 - ac > 1 {", "} else if v.2 - ac > 0 {"),
    ("main: the anchor's refusal is not reported", "main", "} else if arefuse != 0 {\n                            status = refuse(io, arefuse);", "} else if false {\n                            status = refuse(io, arefuse);"),
    ("main: the anchor is never written", "main", "    if total != acount {\n", "    if total == 424242 {\n"),
    ("main: the anchor is written only when it changed by two", "main", "    if total != acount {\n", "    if total != acount && total - acount > 1 {\n"),
    ("main: a fresh entry is not counted in the anchor", "main", "    if seen == 0 {\n        total = total + 1;", "    if seen == 7 {\n        total = total + 1;"),
    ("main: a failed anchor write does not stop the signature", "main", "if write_anchor(anc, total, head) != 0 {", "if write_anchor(anc, total, head) == 99 {"),
    ("main: the anchor is renamed to itself", "main", "\"/var/lib/cancho-anchor/anchor.new\", \"/var/lib/cancho-anchor/anchor\")", "\"/var/lib/cancho-anchor/anchor.new\", \"/var/lib/cancho-anchor/anchor.new\")"),
    ("main: a short anchor write is not noticed", "main", "text[0..n]) == n {", "text[0..n]) != 99 {"),
    ("main: the anchor's count in the answer", "main", "say_count(io, total);", "say_count(io, total + 1);"),
    ("main: the anchor's digits in the answer", "main", "buf[at] = byte_of(48 + v % 10);", "buf[at] = byte_of(47 + v % 10);"),
    ("main: the anchor's head in the answer", "main", "io.write_all(io, head[0..64]);", "io.write_all(io, head[32..64]);"),
    ("main: an anchor file of any size is read", "main", "if size > 0 && size <= len(buf) {", "if size > 0 {"),
    ("signer: an anchor's leading zero", "signer", "if sp > 1 && int_of(text[0]) == 48 {", "if sp > 7 && int_of(text[0]) == 48 {"),
    ("signer: an anchor's count of zero", "signer", "if count < 1 || count > max_entries() {\n        return -280;\n    }\n    k = 0;", "if count < 0 || count > max_entries() {\n        return -280;\n    }\n    k = 0;"),
    ("signer: an anchor's count over the limit", "signer", "if count < 1 || count > max_entries() {\n        return -280;\n    }\n    k = 0;", "if count < 1 || count > max_entries() * 2 {\n        return -280;\n    }\n    k = 0;"),
    ("signer: an anchor's count of six digits", "signer", "if sp < 1 || sp > 5 ||", "if sp < 1 || sp > 6 ||"),
    ("signer: an anchor's newline", "signer", "if int_of(text[sp + 65]) != 10 {", "if int_of(text[sp + 65]) != 13 {"),
    ("signer: an anchor's length", "signer", "|| len(text) != sp + 66 {", "|| len(text) < sp + 66 {"),
    ("signer: an anchor's count digit", "signer", "if c < 48 || c > 57 {\n            return -280;", "if c < 48 || c > 58 {\n            return -280;"),
    ("signer: an anchor's head in upper case", "signer", "if !is_lower_hex(int_of(text[sp + 1 + k])) {", "if !is_lower_hex(int_of(text[sp + 1 + k])) && int_of(text[sp + 1 + k]) < 71 {"),
    ("signer: an anchor's head is not copied", "signer", "head[k] = text[sp + 1 + k];", "head[k] = text[sp + 1];"),
    ("signer: an anchor's separator", "signer", "while sp < len(text) && int_of(text[sp]) != 32 {", "while sp < len(text) && int_of(text[sp]) != 9 {"),
    ("signer: the anchor's file text", "signer", "out[digits] = byte_of(32);", "out[digits] = byte_of(9);"),
    ("signer: the anchor's file newline", "signer", "out[digits + 65] = byte_of(10);", "out[digits + 65] = byte_of(13);"),
    ("signer: the anchor's file length", "signer", "return digits + 66;", "return digits + 65;"),
    ("signer: the anchor's count digits", "signer", "out[at] = byte_of(48 + v % 10);", "out[at] = byte_of(49 + v % 10);"),
    ("signer: the anchor's tag", "signer", "return \"signer-anchor-short\";", "return \"signer-anchor-cut\";"),
    ("signer: another anchor tag", "signer", "return \"signer-anchor-write\";", "return \"signer-anchor-disk\";"),
    # the witness (section 20)
    ("main: a fifth hex field", "main", "    while n < 4 {\n        if i >= len(text) {", "    while n < 5 {\n        if i >= len(text) {"),
    ("main: an empty field", "main", "if j - i == 0 || (j - i) % 2 != 0 {", "if (j - i) % 2 != 0 {"),
    ("main: an odd field", "main", "if j - i == 0 || (j - i) % 2 != 0 {", "if j - i == 0 {"),
    ("main: fewer than four fields", "main", "    while n < 4 {\n        if i >= len(text) {\n            return -275;\n        }", "    while n < 4 {\n        if i >= len(text) + 1000 {\n            return -275;\n        }"),
    ("main: the witness is not looked at", "main", "if meta[8] < 0 {\n                                                    if v.2 > 1 {", "if true {\n                                                    if v.2 > 1 {"),
    ("main: no witness is always accepted", "main", "arefuse = -286;", "arefuse = 0;"),
    ("main: no witness with one entry is refused", "main", "if meta[8] < 0 {\n                                                    if v.2 > 1 {", "if meta[8] < 0 {\n                                                    if v.2 > 0 {"),
    ("main: a witness ahead of the ledger is accepted", "main", "if wv.4 == trail.anchor_short() {", "if wv.4 == 99 {"),
    ("main: a witness for another entry is accepted", "main", "} else if wv.4 == trail.anchor_mismatch() {", "} else if wv.4 == 99 {"),
    ("main: a ledger far ahead of the witness is accepted", "main", "} else if v.2 - meta[8] > 1 {", "} else if v.2 - meta[8] > 1000000 {"),
    ("main: a ledger one ahead of the witness is refused", "main", "} else if v.2 - meta[8] > 1 {", "} else if v.2 - meta[8] > 0 {"),
    ("main: the witness's count is not given to verify", "main", "head2, meta[8], arena[meta[9]..meta[9] + 64]);", "head2, 0, arena[meta[9]..meta[9] + 64]);"),
    ("main: the witness's head is read from the wrong place", "main", "head2, meta[8], arena[meta[9]..meta[9] + 64]);", "head2, meta[8], arena[meta[9] + 1..meta[9] + 65]);"),
    ("main: a dash and more is no witness", "main", "if len(rest) == 1 && int_of(rest[0]) == 45 {", "if int_of(rest[0]) == 45 {"),
    ("main: a request without a witness field", "main", "    if i >= len(text) {\n        return -275;\n    }\n    let rest", "    if i > len(text) + 1000 {\n        return -275;\n    }\n    let rest"),
    ("main: the witness's count is kept", "main", "meta[8] = count;", "meta[8] = count + 1;"),
    ("main: the witness's head offset is kept", "main", "meta[9] = at;", "meta[9] = 0;"),
    ("main: a bad witness is taken for one", "main", "if count > 0 {\n            meta[8] = count;", "if count > -999 {\n            meta[8] = count;"),
    ("main: a dash is another number", "main", "int_of(rest[0]) == 45", "int_of(rest[0]) == 46"),
    ("signer: the witness-missing tag", "signer", "return \"signer-witness-missing\";", "return \"signer-witness-none\";"),
    ("signer: the witness-short tag", "signer", "return \"signer-witness-short\";", "return \"signer-witness-cut\";"),
    ("signer: the witness-mismatch tag", "signer", "return \"signer-witness-mismatch\";", "return \"signer-witness-other\";"),
    ("signer: the witness-behind tag", "signer", "return \"signer-witness-behind\";", "return \"signer-witness-old\";"),
]

# Mutants no request can tell from the original, each with the reason.
EQUIVALENT = {
    "main: an odd field": "`hex.decode` refuses an odd number of digits with the same refusal, one line below",
    "main: fewer than four fields": "a line with fewer than four fields reaches the empty-field check with nothing left, and that refuses it with the same tag: each guard is redundant given the other (with both gone it would trap)",
    "signer: an anchor's count of six digits": "every six-digit count is over max_entries (65,536), which the next check refuses with the same tag: the digit bound is defence in depth",
    "main: any torn length is cut": "a file that ends inside a record has a declared length of at most max_len (a larger one is `bad`, not `torn`), so what is left is at most max_len + 3 bytes and the bound is always met: it is defence in depth",
}


def mutants(cancho, trailtool):
    main_text = open(os.path.join(ROOT, "tools/signer/main.cho")).read()
    signer_text = open(os.path.join(ROOT, "lib/signer/signer.cho")).read()
    work = []
    for name, which, old, new in MUTANTS:
        text = main_text if which == "main" else signer_text
        if text.count(old) != 1:
            sys.exit(f"mutant {name!r}: the pattern occurs {text.count(old)} times")
        work.append((name, which, text.replace(old, new)))

    def one(item):
        name, which, body = item
        d = tempfile.mkdtemp()
        try:
            libdir = os.path.join(d, "lib")
            shutil.copytree(os.path.join(ROOT, "lib"), libdir)
            state = os.path.join(d, "state")
            os.mkdir(state)
            exe = os.path.join(d, "signer")
            main = main_text
            if which == "main":
                main = body
            else:
                open(os.path.join(libdir, "signer/signer.cho"), "w").write(body)
            with tempfile.TemporaryDirectory() as t:
                m = os.path.join(t, "main.cho")
                open(m, "w").write(main.replace(CONST, state).replace(ANCH, state + "-anchor"))
                os.makedirs(state + "-anchor", exist_ok=True)
                r = subprocess.run([cancho, "build", "--std", m, *sources(libdir), "-o", exe], capture_output=True, text=True)
            if r.returncode != 0:
                return name, "did not build: " + r.stderr[:200]
            r = subprocess.run([sys.executable, "-I", os.path.abspath(__file__), "--exe", exe, "--state", state, "--trailtool", trailtool], capture_output=True, text=True, timeout=3000)
            return name, ("killed" if r.returncode != 0 else "SURVIVED")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    survivors, broken = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=int(os.environ.get("JOBS", "5"))) as pool:
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
    cancho = os.environ.get("CANCHO", "cancho")
    slow = "--slow" in sys.argv
    arg = lambda name: sys.argv[sys.argv.index(name) + 1]
    if "--exe" in sys.argv:  # a child of --mutants: the binary, the directory compiled into it and cancho-log's tool are given
        run_checks(State(arg("--state"), arg("--exe")), arg("--trailtool"), cancho, random.Random(31337), False)
        print(f"{COUNT[0]} checks, {len(FAILS)} failed")
        sys.exit(1 if FAILS else 0)
    with tempfile.TemporaryDirectory() as t:
        state = os.path.join(t, "state")
        os.mkdir(state)
        exe = os.path.join(t, "signer")
        build(cancho, os.path.join(ROOT, "lib"), open(os.path.join(ROOT, "tools/signer/main.cho")).read(), state, exe)
        trailtool = os.path.join(t, "trailtool")
        r = subprocess.run([cancho, "build", "--std", *[os.path.join(LOGSRC, f) for f in ("trailtool.cho", "trail.cho", "log.cho", "segment.cho", "record.cho", "crc.cho")], "-o", trailtool], capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("trailtool build failed:\n" + r.stderr[:800])
        if "--mutants" in sys.argv:
            mutants(cancho, trailtool)
        run_checks(State(state, exe), trailtool, cancho, random.Random(31337), slow)
    print(f"{COUNT[0]} checks, {len(FAILS)} failed")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
