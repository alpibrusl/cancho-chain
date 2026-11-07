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


def sources(libdir):
    lib = lambda *p: os.path.join(libdir, *p)
    eth = [os.path.join(ROOT, "lib/eth", f) for f in ("hex.cho", "address.cho", "rlp.cho", "txcheck.cho")]
    return ([lib("signer/signer.cho"), os.path.join(ROOT, "lib/keccak/keccak.cho")] + eth + [lib("envelope/envelope.cho"), os.path.join(ROOT, "lib/policy/policy.cho"), os.path.join(ROOT, "lib/policy/decide.cho"),
            os.path.join(ROOT, "lib/intent/intent.cho"), SCHEMA] + [os.path.join(PKGS, "secp256k1", f) for f in ("secp256k1.cho", "comb.cho", "field.cho", "scalar.cho")]
            + [os.path.join(LOGSRC, f) for f in ("crc.cho", "record.cho", "segment.cho", "log.cho", "trail.cho")])


def build(cancho, libdir, main_text, state_dir, out):
    with tempfile.TemporaryDirectory() as t:
        main = os.path.join(t, "main.cho")
        open(main, "w").write(main_text.replace(CONST, state_dir))
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

    def reset(self, c=None, conf=True, key=True):
        for f in os.listdir(self.dir):
            p = os.path.join(self.dir, f)
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

    def run(self, c, env=None, sig=None, msg=None, caller=None, line=None, pre=None):
        e = c.env if env is None else env
        s = sig if sig is not None else ce.sign(ce.env_digest(e), c.issuer_key)
        m = c.tx.unsigned() if msg is None else msg
        text = line if line is not None else f"{e.hex()} {s.hex()} {m.hex()} {(c.caller if caller is None else caller).hex()}"
        p = subprocess.run([self.exe], input=(text + "\n").encode(), capture_output=True, timeout=120)
        out = p.stdout.decode().strip()
        try:
            j = json.loads(out)
        except ValueError:
            j = None
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
    at, events, parent = 0, [], b""
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
        events.append((d[b"kind"], json.loads(d[b"payload"]), int(d[b"ts_ms"])))
        parent = eid
        at += 4 + length
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
                       ("a double space", ok.replace(" ", "  ", 1)), ("a line over 4096 bytes", ok + " " + "0" * 5000), ("a trailing space", ok + " "), ("an empty field", f"{parts[0]} {parts[1]} {parts[2]} ")):
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
                          ("an empty payload", b"")):
        st.reset(c)
        write_chain(st.ledger(), [(b"envelope.consumed", payload, 1000)])
        raw = open(st.ledger(), "rb").read()
        expect_refusal("a whole event with " + name, st.run(envs[0]), "signer-ledger-corrupt", st, raw)
    # a ledger the signer wrote, extended by a model-written chain that is valid, is read
    st.reset(c)
    entries = [(b"envelope.consumed", json.dumps({"id": d.id.hex(), "digest": ce.kec(d.tx.unsigned()).hex()}, separators=(",", ":")).encode(), 1000 + i) for i, d in enumerate(envs[:3])]
    write_chain(st.ledger(), entries)
    rc, j, _ = st.run(envs[1])
    check("a ledger written by the model is read: an entry in it is the same", (rc, (j or {}).get("entry")), (0, "same"))
    rc, j, _ = st.run(envs[3])
    check("and a new envelope is fresh after it", (rc, (j or {}).get("entry"), len(read_events(st.ledger()))), (0, "fresh", 4))
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
    p = subprocess.run([st.exe, "--now", "5", "/tmp"], input=(f"{c.env.hex()} {ce.sign(ce.env_digest(c.env), c.issuer_key).hex()} {c.tx.unsigned().hex()} {c.caller.hex()}\n").encode(), capture_output=True)
    check("arguments are ignored: the answer is the same", p.returncode, 0)
    # (9) the authority: the one directory, the clock, standard input and output, and nothing else
    r = subprocess.run([cancho, "authority", "--std", os.path.join(ROOT, "tools/signer/main.cho"), *sources(os.path.join(ROOT, "lib"))], capture_output=True, text=True)
    perf = r.stdout.split("performs")[1].split("never touches")[0].split()
    check("authority: performs exactly these", perf, ["clock", "file_read", "file_write", f'fs_read("{CONST}")', f'fs_write("{CONST}")', "heap", "io_read", "io_write"])
    check("authority: never touches the network, the command line, signals, other programs or foreign code", all(w in r.stdout for w in ("the network", "the command line", "signals", "other programs", "foreign code")), True)
    if slow:
        c = live_case(rng)
        st.reset(c)
        write_chain(st.ledger(), [(b"envelope.consumed", json.dumps({"id": i.to_bytes(32, "big").hex(), "digest": "0" * 64}, separators=(",", ":")).encode(), 1000) for i in range(65537)])
        expect_refusal("a ledger over 65,536 entries", st.run(c), "signer-ledger-full", st)


def main():
    cancho = os.environ.get("CANCHO", "cancho")
    slow = "--slow" in sys.argv
    with tempfile.TemporaryDirectory() as t:
        state = os.path.join(t, "state")
        os.mkdir(state)
        exe = os.path.join(t, "signer")
        build(cancho, os.path.join(ROOT, "lib"), open(os.path.join(ROOT, "tools/signer/main.cho")).read(), state, exe)
        trailtool = os.path.join(t, "trailtool")
        r = subprocess.run([cancho, "build", "--std", *[os.path.join(LOGSRC, f) for f in ("trailtool.cho", "trail.cho", "log.cho", "segment.cho", "record.cho", "crc.cho")], "-o", trailtool], capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("trailtool build failed:\n" + r.stderr[:800])
        run_checks(State(state, exe), trailtool, cancho, random.Random(31337), slow)
    print(f"{COUNT[0]} checks, {len(FAILS)} failed")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
