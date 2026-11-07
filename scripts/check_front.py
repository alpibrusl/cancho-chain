#!/usr/bin/env python3
"""The front, with the real signer behind it (docs/design.md section 15.3).

    CANCHO=the-compiler CANCHO_PACKAGES=../cancho/packages CANCHO_SCHEMA=../alpibrusl/cancho-schema/src/schema.cho CANCHO_LOG=../cancho-log/src \
        python3 -I scripts/check_front.py [--mutants]
    needs what check_signer.py needs

The front is built with a test port and the path of a wrapper script in place of the signer's: the wrapper counts how often it is started and, for the failure tests, crashes, hangs,
says nothing or floods; otherwise it is the real signer built for a test directory. Requests are written on a socket by hand, so that a header can be doubled or a body malformed.
"""
import concurrent.futures, json, os, random, shutil, socket, stat, subprocess, sys, tempfile, threading, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import check_envelope as ce
import check_signer as cs

PKGS = cs.PKGS
FRONT_PATH = "/usr/local/lib/cancho-chain/signer"
FRONT_PORT = "8742"
FRONT_DIR = "/var/lib/cancho-front"   # the witness's directory; a copy of the front is built with another
FAILS, COUNT = cs.FAILS, cs.COUNT
check = cs.check


def front_sources(libdir):
    return [os.path.join(PKGS, "http-server", "server.cho")]


def build_front(cancho, text, port, signer_path, fdir, out):
    with tempfile.TemporaryDirectory() as t:
        m = os.path.join(t, "main.cho")
        open(m, "w").write(text.replace(FRONT_PATH, signer_path).replace(FRONT_PORT, str(port)).replace(FRONT_DIR, fdir))
        r = subprocess.run([cancho, "build", "--std", m, *front_sources(None), "-o", out], capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("front build failed:\n" + r.stderr[:1500])


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Stack:
    """The front on a port, the wrapper that counts the signer's starts, and the signer's state directory."""

    def __init__(self, tmp, front_exe, signer_exe, state, port, fdir):
        self.tmp, self.port, self.fdir = tmp, port, fdir
        self.count = os.path.join(tmp, "count")
        self.mode = os.path.join(tmp, "mode")
        self.wrapper = os.path.join(tmp, "signer")
        self.state = cs.State(state, signer_exe)
        self.state.extra = [fdir]
        self.proc = subprocess.Popen([front_exe], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise SystemExit("the front did not start")

    def witness(self):
        p = os.path.join(self.fdir, "witness")
        return open(p, "rb").read() if os.path.isfile(p) else None

    def lastline(self):
        return open(os.path.join(self.tmp, "lastline")).read().split()

    def starts(self):
        return open(self.count).read().count("x") if os.path.exists(self.count) else 0

    def set_mode(self, mode):
        open(self.mode, "w").write(mode)

    def stop(self):
        self.proc.kill()
        self.proc.wait()

    def request(self, raw, timeout=30):
        """raw bytes on a fresh connection; the first response read whole: (status, headers dict (lower-case), body)."""
        s = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        try:
            s.sendall(raw)
            return read_response(s)
        finally:
            s.close()

    def post(self, body, identity="agent-procurement-01", extra=b"", path=b"/sign", method=b"POST", ident_headers=None):
        hdr = b""
        for v in ([identity] if ident_headers is None else ident_headers):
            if v is not None:
                hdr += b"X-Auth-Identity: " + (v.encode() if isinstance(v, str) else v) + b"\r\n"
        raw = method + b" " + path + b" HTTP/1.1\r\nHost: front\r\n" + hdr + extra + b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
        return self.request(raw)


def read_response(s):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for l in lines[1:]:
        k, _, v = l.partition(b":")
        headers[k.strip().lower().decode()] = v.strip().decode()
    n = int(headers.get("content-length", "0"))
    while len(rest) < n:
        chunk = s.recv(65536)
        if not chunk:
            break
        rest += chunk
    return status, headers, rest[:n]


def sign_body(c, env=None, sig=None, msg=None):
    e = c.env if env is None else env
    s = sig if sig is not None else ce.sign(ce.env_digest(e), c.issuer_key)
    m = c.tx.unsigned() if msg is None else msg
    return json.dumps({"envelope": e.hex(), "signature": s.hex(), "message": m.hex()}, separators=(",", ":")).encode()


def run_checks(sk, rng):
    state = sk.state
    # (1) a valid request: 200 and the signer's line, byte for byte what the signer says to the same line
    for i in range(4):
        c = cs.live_case(rng)
        c.caller = b"agent-procurement-01"
        c.decision = ce.decision_record(c.decision[4:36], c.decision[36:68], c.decided, c.expires, c.tx.amount, c.caller)
        c.env = ce.layout(c)
        state.reset(c)
        n0 = sk.starts()
        status, h, body = sk.post(sign_body(c))
        check(f"valid {i}: 200, JSON, and the signer started once", (status, h.get("content-type"), sk.starts() - n0), (200, "application/json", 1))
        j = json.loads(body)
        tdigest = ce.kec(c.tx.unsigned())
        check(f"valid {i}: the signature is the model's", bytes.fromhex(j.get("signature", "")), ce.sign(tdigest, c.wallet_key))
        check(f"valid {i}: the entry is fresh", j.get("entry"), "fresh")
        # the same request again: the same bytes, "same"
        status2, _, body2 = sk.post(sign_body(c))
        j2 = json.loads(body2)
        check(f"valid {i}: a retry is 200 with the same signature", (status2, j2.get("signature"), j2.get("entry")), (200, j["signature"], "same"))
        # and what the signer itself says to this line
        direct = state.run(c)
        check(f"valid {i}: the answer is the signer's line as it is", body2, direct[2].encode())
    # (2) the signer's refusals arrive with their tags and status
    c = cs.live_case(rng)
    c.caller = b"agent-procurement-01"
    c.decision = ce.decision_record(c.decision[4:36], c.decision[36:68], c.decided, c.expires, c.tx.amount, c.caller)
    c.env = ce.layout(c)
    other_key = (rng.randrange(1, ce.N)).to_bytes(32, "big")
    for name, kw, tag in (("another issuer", dict(sig=ce.sign(ce.env_digest(c.env), other_key)), "envelope-issuer"), ("a truncated envelope", dict(env=c.env[:-1]), "envelope-format"),
                          ("another transaction", dict(msg=c.tx.unsigned()[:-1] + bytes([c.tx.unsigned()[-1] ^ 1])), "envelope-digest")):
        state.reset(c)
        body = sign_body(c, **kw) if "env" not in kw else sign_body(c, env=kw["env"], sig=ce.sign(ce.env_digest(c.env), c.issuer_key))
        status, _, out = sk.post(body)
        j = json.loads(out)
        check(f"refusal {name}: 422 and chain.{tag}", (status, j.get("rule"), j.get("ok")), (422, "chain." + tag, False))
    state.reset(c)
    status, _, out = sk.post(sign_body(c), identity="someone-else")
    check("a caller the envelope was not issued to is 422 envelope-caller", (status, json.loads(out).get("rule")), (422, "chain.envelope-caller"))
    # an unwell signer is 503, with the signer's own line
    state.reset(c)
    os.symlink("/dev/full", state.ledger())
    status, _, out = sk.post(sign_body(c))
    check("a ledger that cannot be written is 503 signer-ledger-write", (status, json.loads(out).get("rule")), (503, "chain.signer-ledger-write"))
    state.reset(c)
    open(state.ledger(), "wb").close()
    import fcntl
    fd = os.open(state.ledger(), os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    status, _, out = sk.post(sign_body(c))
    check("a ledger held locked is 503 signer-locked", (status, json.loads(out).get("rule")), (503, "chain.signer-locked"))
    os.close(fd)
    state.reset(c)
    open(os.path.join(state.dir, "wallet.key"), "w").write("zz")
    status, _, out = sk.post(sign_body(c))
    check("a bad wallet.key is 503 signer-key", (status, json.loads(out).get("rule")), (503, "chain.signer-key"))
    state.reset(c)
    open(os.path.join(state.dir, "signer.conf"), "w").write(f"issuer={c.wallet.hex()}\nchain={c.tx.chain}\n")
    status, _, out = sk.post(sign_body(c))
    check("an issuer that is the wallet is 503 signer-same-key", (status, json.loads(out).get("rule")), (503, "chain.signer-same-key"))
    state.reset(c)
    sk.post(sign_body(c))
    raw = open(state.ledger(), "rb").read()
    open(state.ledger(), "wb").write(raw[:60] + bytes([raw[60] ^ 1]) + raw[61:])
    status, _, out = sk.post(sign_body(c))
    check("a damaged ledger is 503 signer-ledger-corrupt", (status, json.loads(out).get("rule")), (503, "chain.signer-ledger-corrupt"))
    state.reset(c, conf=False)
    status, _, out = sk.post(sign_body(c))
    check("no signer.conf is 503 signer-config", (status, json.loads(out).get("rule")), (503, "chain.signer-config"))
    # (3) the identity: exactly one valid header, or the signer is never started
    state.reset(c)
    body = sign_body(c)
    n0 = sk.starts()
    for name, kw in (("missing", dict(ident_headers=[])), ("twice", dict(ident_headers=["a", "b"])), ("twice, the same", dict(ident_headers=["a", "a"])), ("empty", dict(identity="")),
                     ("upper case", dict(identity="Agent")), ("33 bytes", dict(identity="a" * 33)), ("a space inside", dict(identity="a b")), ("a comma", dict(identity="a,b")),
                     ("a slash", dict(identity="a/b")), ("a brace", dict(identity="a{")), ("a colon", dict(identity="a:")), ("a backquote", dict(identity="a`")), ("an at sign", dict(identity="a@")), ("a bracket", dict(identity="a[")), ("non-ascii", dict(identity="café".encode("utf-8")))):
        status, _, out = sk.post(body, **kw)
        j = json.loads(out)
        check(f"identity {name}: 401 front-no-identity", (status, j.get("rule")), (401, "chain.front-no-identity"))
    check("identity: the signer was never started", sk.starts() - n0, 0)
    for other in (b"X-Auth-Identity-Extra: z\r\n", b"X-Auth-Identit: z\r\n", b"X-Auth-Identityx: z\r\n", b"Y-Auth-Identity: z\r\n"):
        status, _, out = sk.post(body, extra=other)
        check(f"identity: a header named {other.split(b':')[0].decode()} is not the identity", (status, json.loads(out).get("ok")), (200, True))
    status, _, out = sk.post(body, extra=b"x-auth-identity: agent-procurement-01\r\n", ident_headers=[])
    check("identity: the header name in any case is the header", (status, json.loads(out).get("ok")), (200, True))
    for name_ in ("a", "a" * 32, "a.b_c-9"):
        c3 = cs.live_case(rng)
        c3.caller = name_.encode()
        c3.decision = ce.decision_record(c3.decision[4:36], c3.decision[36:68], c3.decided, c3.expires, c3.tx.amount, c3.caller)
        c3.env = ce.layout(c3)
        state.reset(c3)
        status, _, out = sk.post(sign_body(c3), identity=name_)
        check(f"identity: the name {name_!r} is within the rule", (status, json.loads(out).get("ok")), (200, True))
    state.reset(c)
    # (4) the body: exactly three members, or the signer is never started
    good = sign_body(c)
    obj = json.loads(good)
    spell = lambda **kw: json.dumps({**obj, **kw}, separators=(",", ":")).encode()
    reorder = json.dumps({"signature": obj["signature"], "envelope": obj["envelope"], "message": obj["message"]}, separators=(",", ":")).encode()
    n0 = sk.starts()
    for name, b in (("an empty body", b""), ("not JSON", b"hello"), ("a member missing", json.dumps({"envelope": obj["envelope"], "signature": obj["signature"]}, separators=(",", ":")).encode()),
                    ("a member doubled", good[:-1] + b',"message":"00"}'), ("members reordered", reorder), ("whitespace", json.dumps(obj).encode()), ("a newline at the end", good + b"\n"),
                    ("trailing bytes", good + b" "), ("an upper-case digit", spell(message=obj["message"][:-1].replace("a", "b") + "A")), ("an odd length", spell(message=obj["message"][:-1])),
                    ("a non-hex digit", spell(message=obj["message"][:-2] + "zz")),
                    ("a g among the digits", spell(message=obj["message"][:-2] + "0g")), ("a backquote among the digits", spell(message=obj["message"][:-2] + "0`")),
                    ("a slash among the digits", spell(message="/0" + obj["message"][2:])), ("a colon among the digits", spell(message=":0" + obj["message"][2:])),
                    ("an empty envelope", spell(envelope="")), ("the envelope member misspelt", good.replace(b'"envelope"', b'"envelopx"')),
                    ("the signature member misspelt", good.replace(b'"signature"', b'"signaturx"')), ("the message member misspelt", good.replace(b'"message"', b'"messagx"')),
                    ("the object closed with a bracket", good[:-1] + b"]"), ("a different opening", b"[" + good[1:]), ("an empty message", spell(message="")), ("a short signature", spell(signature=obj["signature"][:-2])),
                    ("a long signature", spell(signature=obj["signature"] + "00")), ("an envelope of 654 digits", spell(envelope="00" * 327)), ("a message of 2,050 digits", spell(message="00" * 1025)),
                    ("an extra member", good[:-1] + b',"x":"00"}'), ("a number for a member", b'{"envelope":1,"signature":2,"message":3}'), ("an escaped digit", spell(message="\\u0030" + obj["message"][2:]).replace(b"\\\\u", b"\\u"))):
        status, _, out = sk.post(b)
        check(f"body {name}: 400 front-body", (status, (json.loads(out).get("rule") if out[:1] == b"{" else None)), (400, "chain.front-body"))
    status, _, out = sk.post(b"x" * 4097)
    check("body: 4,097 bytes is 413", status, 413)
    check("body: the signer was never started", sk.starts() - n0, 0)
    # (5) routes and methods
    status, h, out = sk.post(good, path=b"/other")
    check("another path is 404", (status, json.loads(out).get("rule")), (404, "chain.front-not-found"))
    status, h, out = sk.post(good, path=b"/sign/")
    check("a path with a slash is 404", status, 404)
    status, h, out = sk.post(good, path=b"/sign?x=1")
    check("a query on /sign is the route /sign (not 404)", status in (200, 422), True)
    for m in (b"GET", b"PUT", b"DELETE", b"PATCH"):
        status, h, out = sk.post(b"" if m == b"GET" else good, method=m)
        check(f"{m.decode()} /sign is 405 with Allow: POST", (status, h.get("allow"), json.loads(out).get("rule")), (405, "POST", "chain.front-method"))
    # (6) a signer that fails is 502, in each way it can
    for mode, name in (("crash", "crashes"), ("silent", "says nothing"), ("flood", "floods its output"), ("badjson", "writes a line that is not the signer's"), ("twolines", "writes two lines")):
        state.reset(c)
        sk.set_mode(mode)
        status, _, out = sk.post(good)
        check(f"a signer that {name}: 502 front-signer", (status, json.loads(out).get("rule")), (502, "chain.front-signer"))
    for tag, want in (("signer-locked", 503), ("signer-ledger-write", 503), ("signer-ledger-corrupt", 503), ("signer-ledger-full", 503), ("signer-config", 503), ("signer-key", 503), ("signer-same-key", 503),
                      ("signer-anchor-corrupt", 503), ("signer-anchor-missing", 503), ("signer-anchor-short", 503), ("signer-anchor-mismatch", 503), ("signer-anchor-behind", 503), ("signer-anchor-write", 503),
                      ("signer-witness-missing", 503), ("signer-witness-short", 503), ("signer-witness-mismatch", 503), ("signer-witness-behind", 503),
                      ("envelope-expired", 422), ("signer-request", 422), ("envelope-replayed", 422)):
        sk.set_mode("rule=" + tag)
        status, _, out = sk.post(good)
        check(f"a signer that says chain.{tag}: {want}", (status, json.loads(out).get("rule")), (want, "chain." + tag))
    for mode, name in (("norule", "a refusal with no rule"), ("nobrace", "a refusal that is not closed"), ("tworefusals", "two refusals"), ("badexit", "a refusal and an exit status of 3"), ("bigline", "a line over 4,096 bytes")):
        sk.set_mode(mode)
        status, _, out = sk.post(good)
        check(f"a signer that writes {name}: 502 front-signer", (status, json.loads(out).get("rule")), (502, "chain.front-signer"))
    sk.set_mode("ok")
    t0 = time.time()
    sk.set_mode("hang")
    status, _, out = sk.post(good)
    took = time.time() - t0
    check("a signer that hangs: 502 after about 10 seconds", (status, 9 < took < 20), (502, True))
    sk.set_mode("ok")
    status, _, out = sk.post(good)
    check("and the front serves the next request", status in (200, 422), True)
    # (6b) the witness (docs/design.md section 20): the signer's anchor, kept here and handed back
    def envelope_k(k):
        d = cs.with_nonce(c, c.tx.nonce)
        d.id = bytes([0x50 + k]) * 32
        d.env = ce.layout(d)
        return d

    ks = [envelope_k(k) for k in range(5)]
    state.reset(c)
    check("no witness yet: no file", sk.witness(), None)
    prev = None
    for k in range(3):
        status, _, out = sk.post(sign_body(ks[k]))
        j = json.loads(out)
        check(f"witness {k}: 200", status, 200)
        check(f"witness {k}: the request line carries {'none' if prev is None else 'the last answer'}", sk.lastline()[4:], ["-"] if prev is None else prev.split())
        w = f"{j['anchor']['count']} {j['anchor']['head']}\n".encode()
        check(f"witness {k}: the file is the answer's anchor, `<count> <head>` and a newline", sk.witness(), w)
        prev = w.decode().strip()
    w3 = sk.witness()
    status, _, out = sk.post(sign_body(ks[1]))
    check("a retry (the same entry) leaves the witness as it is", (status, json.loads(out).get("entry"), sk.witness()), (200, "same", w3))
    status, _, out = sk.post(sign_body(ks[3]), identity="someone-else")
    check("a refusal (422) leaves the witness as it is", (status, sk.witness()), (422, w3))
    # the witness cannot be written: the signature is not given, and the retry gives the same one
    os.symlink("/dev/full", os.path.join(sk.fdir, "witness.new"))
    status, _, out = sk.post(sign_body(ks[3]))
    check("a witness that cannot be written (/dev/full): 503 front-witness-write and no signature", (status, json.loads(out).get("rule"), b'"signature":' in out), (503, "chain.front-witness-write", False))
    check("... the witness is as it was and the ledger has the entry", (sk.witness(), len(cs.read_events(state.ledger()))), (w3, 4))
    os.unlink(os.path.join(sk.fdir, "witness.new"))
    status, _, out = sk.post(sign_body(ks[3]))
    j = json.loads(out)
    check("... the retry is the same entry, with the model's signature, and the witness is written", (status, j.get("entry"), bytes.fromhex(j.get("signature", "")), sk.witness()), (200, "same", ce.sign(ce.kec(ks[3].tx.unsigned()), c.wallet_key), f"{j['anchor']['count']} {j['anchor']['head']}\n".encode()))
    # two answers lost in a row: the third request is refused by the signer, not signed
    os.symlink("/dev/full", os.path.join(sk.fdir, "witness.new"))
    status, _, out = sk.post(sign_body(ks[4]))
    check("a first lost answer: 503 front-witness-write", (status, json.loads(out).get("rule")), (503, "chain.front-witness-write"))
    d5 = envelope_k(5)
    status, _, out = sk.post(sign_body(d5))
    check("a second lost answer: 503 front-witness-write (the signer may be one entry ahead of the witness)", (status, json.loads(out).get("rule")), (503, "chain.front-witness-write"))
    d6 = envelope_k(6)
    status, _, out = sk.post(sign_body(d6))
    check("a third request: 503 signer-witness-behind, nothing signed", (status, json.loads(out).get("rule"), b'"signature":' in out), (503, "chain.signer-witness-behind", False))
    os.unlink(os.path.join(sk.fdir, "witness.new"))
    # a witness file that is not one line of lower-case hex and spaces: 503 front-witness and the signer is never started
    n0 = sk.starts()
    wfile = os.path.join(sk.fdir, "witness")
    for name, data in (("empty", b""), ("one byte", b"1"), ("upper case", b"1 " + b"A" * 64 + b"\n"), ("binary", bytes(range(1, 40)) + b"\n"), ("two lines", b"1 " + b"a" * 64 + b"\n1 " + b"a" * 64 + b"\n"),
                       ("no newline", b"1 " + b"a" * 64), ("over 72 bytes", b"1 " + b"a" * 80 + b"\n"), ("a tab", b"1\t" + b"a" * 64 + b"\n"), ("a carriage return", b"1 " + b"a" * 64 + b"\r\n"),
                       ("a g among the digits", b"1 " + b"g" * 64 + b"\n"), ("a backquote", b"1 " + b"`" * 64 + b"\n"), ("a slash", b"1 " + b"/" * 64 + b"\n"), ("a colon", b"1 " + b":" * 64 + b"\n"),
                       ("an at sign", b"1 " + b"@" * 64 + b"\n"), ("a trailing newline too many", b"1 " + b"a" * 64 + b"\n\n")):
        open(wfile, "wb").write(data)
        status, _, out = sk.post(sign_body(ks[0]))
        check(f"a witness file that is {name}: 503 front-witness", (status, json.loads(out).get("rule")), (503, "chain.front-witness"))
    os.unlink(wfile)
    os.mkdir(wfile)
    status, _, out = sk.post(sign_body(ks[0]))
    check("a witness that is a directory: 503 front-witness", (status, json.loads(out).get("rule")), (503, "chain.front-witness"))
    os.rmdir(wfile)
    check("a damaged witness: the signer is never started", sk.starts() - n0, 0)
    # no witness file with a ledger of more than one entry: the signer refuses (the front sends none)
    status, _, out = sk.post(sign_body(ks[0]))
    check("no witness file and a ledger of several entries: 503 signer-witness-missing", (status, json.loads(out).get("rule"), sk.lastline()[4:]), (503, "chain.signer-witness-missing", ["-"]))
    # a restore of the signer's directory: refused through the front
    state.reset(c)
    sk.post(sign_body(ks[0]))
    sk.post(sign_body(ks[1]))
    snap = (open(state.ledger(), "rb").read(), open(state.anchor(), "rb").read())
    sk.post(sign_body(ks[2]))
    sk.post(sign_body(ks[3]))
    w4 = sk.witness()
    open(state.ledger(), "wb").write(snap[0])
    open(state.anchor(), "wb").write(snap[1])
    status, _, out = sk.post(sign_body(ks[0]))
    check("a restore of the signer's directory to two entries: 503 signer-witness-short, nothing signed", (status, json.loads(out).get("rule"), b'"signature":' in out, sk.witness()), (503, "chain.signer-witness-short", False, w4))
    # what the front accepts as the signer's 200: it must carry a well-formed anchor
    state.reset(c)
    for mode, name in (("noanchor", "no anchor"), ("upperhead", "an anchor with an upper-case head"), ("sixdigits", "an anchor with a six-digit count"), ("emptycount", "an anchor with an empty count"), ("countjunk", "an anchor with a letter after the count"), ("lasthead", "an anchor whose last head digit is not hex")):
        sk.set_mode(mode)
        status, _, out = sk.post(good)
        check(f"a signer whose 200 has {name}: 502 front-signer and no witness", (status, json.loads(out).get("rule"), sk.witness()), (502, "chain.front-signer", None))
    sk.set_mode("fake")
    status, _, out = sk.post(good)
    check("a signer's 200 with an anchor of seven: the witness is exactly that", (status, sk.witness()), (200, b"7 " + b"b" * 64 + b"\n"))
    sk.set_mode("ok")
    state.reset(c)
    # (7) one connection, two requests; two connections at once
    state.reset(c)
    s = socket.create_connection(("127.0.0.1", sk.port), timeout=30)
    raw = b"POST /sign HTTP/1.1\r\nHost: front\r\nX-Auth-Identity: agent-procurement-01\r\nContent-Length: " + str(len(good)).encode() + b"\r\n\r\n" + good
    s.sendall(raw)
    r1 = read_response(s)
    s.sendall(raw)
    r2 = read_response(s)
    s.close()
    check("keep-alive: two requests on one connection", (r1[0], r2[0], json.loads(r2[2]).get("entry")), (200, 200, "same"))
    state.reset(c)
    results = []

    def go():
        results.append(sk.post(good))
    ts = [threading.Thread(target=go) for _ in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    check("six clients at once: all 200 with one signature, one ledger entry", (sorted(r[0] for r in results), len({json.loads(r[2])["signature"] for r in results}), len(cs.read_events(state.ledger()))), ([200] * 6, 1, 1))
    # (8) the authority of the front
    r = subprocess.run([cancho_path(), "authority", "--std", os.path.join(ROOT, "tools/front/main.cho"), *front_sources(None)], capture_output=True, text=True)
    perf = r.stdout.split("performs")[1].split("never touches")[0].split()
    check("authority: performs exactly these (one directory)", sorted(perf), sorted(["child_signal", "clock", "conn_accept", "conn_read", "conn_write", f'exec("{FRONT_PATH}")', f'fs_read("{FRONT_DIR}")', f'fs_write("{FRONT_DIR}")', "file_read", "heap", f'net_in("{FRONT_PORT}")', "pipe_read", "pipe_write", "poll"]))
    check("authority: never touches the console, the command line, signals or foreign code", all(w in r.stdout.split("never touches")[1] for w in ("the console", "the command line", "signals", "foreign code")), True)
    check("authority: it is bounded (no UNBOUNDED line)", "UNBOUNDED" not in r.stdout, True)


def cancho_path():
    return os.environ.get("CANCHO", "cancho")


def make_stack(cancho, front_text, signer_main_text, libdir, tmp, port):
    state = os.path.join(tmp, "state")
    os.makedirs(state, exist_ok=True)
    fdir = os.path.join(tmp, "front-state")
    os.makedirs(fdir, exist_ok=True)
    real = os.path.join(tmp, "signer-real")
    cs.build(cancho, libdir, signer_main_text, state, real)
    wrapper = os.path.join(tmp, "signer")
    open(wrapper, "w").write(f"""#!/bin/sh
echo x >> {tmp}/count
mode=$(cat {tmp}/mode 2>/dev/null)
case "$mode" in
  crash) exit 9;;
  silent) exit 0;;
  flood) head -c 100000 /dev/zero | tr '\\0' 'a'; exit 0;;
  badjson) echo hello; exit 0;;
  rule=*) printf '{{"ok":false,"rule":"chain.%s","repair":"x"}}\\n' "${{mode#rule=}}"; exit 2;;
  norule) printf '{{"ok":false,"repair":"xxxxxxxxxxxxxxxxxxxx"}}\\n'; exit 2;;
  badexit) printf '{{"ok":false,"rule":"chain.envelope-expired","repair":"x"}}\\n'; exit 3;;
  bigline) printf '{{"ok":true,"x":"'; head -c 5000 /dev/zero | tr '\\0' 'a'; printf '","anchor":{{"count":1,"head":"%s"}}}}\\n' "$(printf 'a%.0s' $(seq 64))"; exit 0;;
  twolines) printf '{{"ok":true,"signature":"00"}}\\n{{"ok":true,"signature":"00","entry":"fresh","anchor":{{"count":1,"head":"%s"}}}}\\n' "$(printf 'a%.0s' $(seq 64))"; exit 0;;
  nobrace) printf '{{"ok":false,"rule":"chain.envelope-expired","repair":"xxxxxxxxxxxx"\\n'; exit 2;;
  tworefusals) printf '{{"ok":false,"rule":"chain.envelope-expired","repair":"x"}}\\n{{"ok":false,"rule":"chain.envelope-expired","repair":"x"}}\\n'; exit 2;;
  lasthead) printf '{{"ok":true,"signature":"00","entry":"fresh","anchor":{{"count":1,"head":"%sG"}}}}\\n' "$(printf 'a%.0s' $(seq 63))"; exit 0;;
  hang) sleep 60; exit 0;;
  noanchor) printf '{{"ok":true,"signature":"00","entry":"fresh"}}\n'; exit 0;;
  upperhead) printf '{{"ok":true,"signature":"00","entry":"fresh","anchor":{{"count":1,"head":"%s"}}}}\n' "$(printf 'A%.0s' $(seq 64))"; exit 0;;
  sixdigits) printf '{{"ok":true,"signature":"00","entry":"fresh","anchor":{{"count":123456,"head":"%s"}}}}\n' "$(printf 'a%.0s' $(seq 64))"; exit 0;;
  emptycount) printf '{{"ok":true,"signature":"00","entry":"fresh","anchor":{{"count":,"head":"%s"}}}}\n' "$(printf 'a%.0s' $(seq 64))"; exit 0;;
  countjunk) printf '{{"ok":true,"signature":"00","entry":"fresh","anchor":{{"count":1x,"head":"%s"}}}}\n' "$(printf 'a%.0s' $(seq 64))"; exit 0;;
  fake) printf '{{"ok":true,"signature":"00","entry":"fresh","anchor":{{"count":7,"head":"%s"}}}}\n' "$(printf 'b%.0s' $(seq 64))"; exit 0;;
esac
line=$(cat)
printf '%s\n' "$line" > {tmp}/lastline
printf '%s\n' "$line" | {real}
""")
    os.chmod(wrapper, os.stat(wrapper).st_mode | stat.S_IEXEC)
    front = os.path.join(tmp, "front")
    build_front(cancho, front_text, port, wrapper, fdir, front)
    return Stack(tmp, front, real, state, port, fdir)


MUTANTS = [
    ("is_lower_hex: the top of a-f", "fn is_lower_hex(c: int) -> [] bool {\n    return c >= 48 && c <= 57 || c >= 97 && c <= 102;", "fn is_lower_hex(c: int) -> [] bool {\n    return c >= 48 && c <= 57 || c >= 97 && c <= 103;"),
    ("is_lower_hex: upper case", "fn is_lower_hex(c: int) -> [] bool {\n    return c >= 48 && c <= 57 || c >= 97 && c <= 102;", "fn is_lower_hex(c: int) -> [] bool {\n    return c >= 48 && c <= 57 || c >= 97 && c <= 102 || c >= 65 && c <= 70;"),
    ("is_lower_hex: below 0", "fn is_lower_hex(c: int) -> [] bool {\n    return c >= 48 && c <= 57 || c >= 97 && c <= 102;", "fn is_lower_hex(c: int) -> [] bool {\n    return c >= 47 && c <= 57 || c >= 97 && c <= 102;"),
    ("expect: a literal that runs past the body", "if at < 0 || len(body) - at < len(lit) {", "if at < 0 {"),
    ("expect: the literal is compared", "if int_of(body[at + i]) != int_of(lit[i]) {", "if int_of(body[at + i]) == 1000 {"),
    ("hex_run: odd length", "if n % 2 != 0 || n < least", "if n < least"),
    ("hex_run: least", "|| n < least || n > most", "|| n < least - 2 || n > most"),
    ("hex_run: most", "|| n < least || n > most", "|| n < least || n > most + 2"),
    ("hex_run: the closing quote", "|| i >= len(body) || int_of(body[i]) != 34 {", "|| i >= len(body) {"),
    ("parse_body: envelope bound", "at = hex_run(body, at, 2, 652);", "at = hex_run(body, at, 2, 654);"),
    ("parse_body: envelope least", "at = hex_run(body, at, 2, 652);", "at = hex_run(body, at, 0, 652);"),
    ("parse_body: signature length", "at = hex_run(body, at, 130, 130);", "at = hex_run(body, at, 128, 130);"),
    ("parse_body: signature length, above", "at = hex_run(body, at, 130, 130);", "at = hex_run(body, at, 130, 132);"),
    ("parse_body: message bound", "at = hex_run(body, at, 2, 2048);", "at = hex_run(body, at, 2, 2050);"),
    ("parse_body: message least", "at = hex_run(body, at, 2, 2048);", "at = hex_run(body, at, 0, 2048);"),
    ("parse_body: the end", "if at != len(body) {\n        return 0 - 1;\n    }\n    return 0;\n}\n\n// The identity", "if at < 0 {\n        return 0 - 1;\n    }\n    return 0;\n}\n\n// The identity"),
    ("parse_body: the member name", "at = expect(body, at, \"\\\",\\\"signature\\\":\\\"\");", "at = expect(body, at, \"\\\",\\\"signatur\\\":\\\"\");"),
    ("identity_ok: length 33", "if len(value) < 1 || len(value) > 32 {", "if len(value) < 1 || len(value) > 33 {"),
    ("identity_ok: length 0", "if len(value) < 1 || len(value) > 32 {", "if len(value) < 0 || len(value) > 32 {"),
    ("identity_ok: the top of a-z", "c >= 97 && c <= 122 ||", "c >= 97 && c <= 123 ||"),
    ("identity_ok: upper case", "c >= 97 && c <= 122 ||", "c >= 65 && c <= 122 ||"),
    ("identity_ok: a digit", "c >= 48 && c <= 57 || c == 46", "c >= 48 && c <= 58 || c == 46"),
    ("identity_ok: a dot", "|| c == 46 || c == 95 || c == 45", "|| c == 95 || c == 45"),
    ("identity_ok: an underscore", "|| c == 46 || c == 95 || c == 45", "|| c == 46 || c == 45"),
    ("identity_ok: a hyphen", "|| c == 46 || c == 95 || c == 45", "|| c == 46 || c == 95"),
    ("identity_header: more than one", "if n != 1 {\n        return 0 - 1;", "if n < 1 {\n        return 0 - 1;"),
    ("identity_header: none", "if n != 1 {\n        return 0 - 1;", "if n > 1 {\n        return 0 - 1;"),
    ("identity_header: the name", "\"x-auth-identity\") {\n            found = i;", "\"x-auth-identit\") {\n            found = i;"),
    ("is_name: the length", "if len(name) != len(want) {\n        return false;", "if len(name) < len(want) {\n        return false;"),
    ("is_name: case", "if bytes.to_lower(int_of(name[i])) != int_of(want[i]) {", "if int_of(name[i]) != int_of(want[i]) {"),
    ("handle: the path", "if !bytes.equal(http.path(request, table), \"/sign\") {", "if bytes.equal(http.path(request, table), \"/nothing\") {"),
    ("handle: the method", "if !bytes.equal(http.method(request, table), \"POST\") {", "if bytes.equal(http.method(request, table), \"GET\") {"),
    ("handle: the identity is valid", "if at < 0 || !identity_ok(http.header_value(request, table, at)) {", "if at < 0 {"),
    ("handle: body size", "if len(body) > 4096 {", "if len(body) > 4100 {"),
    ("handle: the identity is the caller", "let caller = http.header_value(request, table, at);", "let caller = \"agent\";"),
    ("handle: the caller is hex", "line = buffer.push(heap, line, byte_of(hex_char(int_of(caller[i]) >> 4)));", "line = buffer.push(heap, line, byte_of(hex_char(int_of(caller[i]) >> 3)));"),
    ("handle: the caller's low digit", "line = buffer.push(heap, line, byte_of(hex_char(int_of(caller[i]) & 15)));", "line = buffer.push(heap, line, byte_of(hex_char(int_of(caller[i]) & 7)));"),
    ("handle: the fields are in order", "line = buffer.append(heap, line, body[spans[2]..spans[3]]);", "line = buffer.append(heap, line, body[spans[4]..spans[5]]);"),
    ("hex_char: letters", "return 87 + v;", "return 88 + v;"),
    ("ask_signer: exit 0 is ok", "if n == 0 {\n                                status = 200;", "if n == 1 {\n                                status = 200;"),
    ("ask_signer: exit 2 is a refusal", "} else if n == 2 {\n                                status = 422;", "} else if n == 3 {\n                                status = 422;"),
    ("ask_signer: any other exit", "} else if n == 2 {\n                                status = 422;\n                            }", "} else {\n                                status = 422;\n                            }"),
    ("ask_signer: one line", "let shaped = len(text) > 20 && lines == 1 &&", "let shaped = len(text) > 20 &&"),
    ("ask_signer: a closing brace", "&& int_of(text[len(text) - 2]) == 125;", "&& int_of(text[len(text) - 2]) == 125 || true;"),
    ("ask_signer: an ok line is ok", "if status == 200 && expect(text, 0, \"{\\\"ok\\\":true,\") < 0 {", "if status == 200 && expect(text, 0, \"{\\\"ok\\\":false,\") < 0 {"),
    ("ask_signer: no rule is 502", "if span.1 == 0 {\n                                status = 502;", "if span.1 == 99999 {\n                                status = 502;"),
    ("ask_signer: the output bound", "line, 4096, 10000);", "line, 4096000, 10000);"),
    ("ask_signer: the deadline", "line, 4096, 10000);", "line, 4096, 60000);"),
    ("unwell: signer-locked", "bytes.equal(tag, \"signer-locked\") ||", "bytes.equal(tag, \"signer-lockd\") ||"),
    ("unwell: signer-ledger-write", "bytes.equal(tag, \"signer-ledger-write\") ||", "bytes.equal(tag, \"signer-ledger-writ\") ||"),
    ("unwell: signer-ledger-corrupt", "bytes.equal(tag, \"signer-ledger-corrupt\") ||", "bytes.equal(tag, \"signer-ledger-corrup\") ||"),
    ("unwell: signer-ledger-full", "bytes.equal(tag, \"signer-ledger-full\") ||", "bytes.equal(tag, \"signer-ledger-ful\") ||"),
    ("unwell: signer-config", "bytes.equal(tag, \"signer-config\") ||", "bytes.equal(tag, \"signer-confi\") ||"),
    ("unwell: signer-key", "bytes.equal(tag, \"signer-key\") ||", "bytes.equal(tag, \"signer-ke\") ||"),
    ("unwell: signer-same-key", "bytes.equal(tag, \"signer-same-key\") ||", "bytes.equal(tag, \"signer-same-ke\") ||"),
    ("rule_of: the prefix", "let head = \"{\\\"ok\\\":false,\\\"rule\\\":\\\"chain.\";", "let head = \"{\\\"ok\\\":false,\\\"rule\\\":\\\"chai.\";"),
    ("refusal: the allow header", "keep, \"Allow: POST\\r\\n\");", "keep, \"\");"),
    ("refusal: 404", "refusal(heap, out, 404,", "refusal(heap, out, 400,"),
    ("refusal: 405", "refusal(heap, out, 405,", "refusal(heap, out, 404,"),
    ("refusal: 401", "refusal(heap, out, 401,", "refusal(heap, out, 403,"),
    ("refusal: 413", "refusal(heap, out, 413,", "refusal(heap, out, 400,"),
    ("unwell: signer-anchor-corrupt", "bytes.equal(tag, \"signer-anchor-corrupt\")", "bytes.equal(tag, \"signer-anchor-corruptx\")"),
    ("unwell: signer-anchor-missing", "bytes.equal(tag, \"signer-anchor-missing\")", "bytes.equal(tag, \"signer-anchor-missingx\")"),
    ("unwell: signer-anchor-short", "bytes.equal(tag, \"signer-anchor-short\")", "bytes.equal(tag, \"signer-anchor-shortx\")"),
    ("unwell: signer-anchor-mismatch", "bytes.equal(tag, \"signer-anchor-mismatch\")", "bytes.equal(tag, \"signer-anchor-mismatchx\")"),
    ("unwell: signer-anchor-behind", "bytes.equal(tag, \"signer-anchor-behind\")", "bytes.equal(tag, \"signer-anchor-behindx\")"),
    ("unwell: signer-anchor-write", "bytes.equal(tag, \"signer-anchor-write\")", "bytes.equal(tag, \"signer-anchor-writex\")"),
    ("unwell: signer-witness-missing", "bytes.equal(tag, \"signer-witness-missing\")", "bytes.equal(tag, \"signer-witness-missingx\")"),
    ("unwell: signer-witness-short", "bytes.equal(tag, \"signer-witness-short\")", "bytes.equal(tag, \"signer-witness-shortx\")"),
    ("unwell: signer-witness-mismatch", "bytes.equal(tag, \"signer-witness-mismatch\")", "bytes.equal(tag, \"signer-witness-mismatchx\")"),
    ("unwell: signer-witness-behind", "bytes.equal(tag, \"signer-witness-behind\")", "bytes.equal(tag, \"signer-witness-behindx\")"),
    ("witness: no file is none", "Opened::Failed(e) => {\n            got = 0 - 1;", "Opened::Failed(e) => {\n            got = 0 - 2;"),
    ("witness: a file of any size", "if size >= 3 && size <= len(out) {", "if size >= 3 && size <= len(out) + 100 {"),
    ("witness: an empty file", "if size >= 3 && size <= len(out) {", "if size >= 0 && size <= len(out) {"),
    ("witness: the digits", "c >= 48 && c <= 57 || c >= 97 && c <= 102 || c == 32", "c >= 47 && c <= 57 || c >= 97 && c <= 102 || c == 32"),
    ("witness: the top of the digits", "c >= 48 && c <= 57 || c >= 97 && c <= 102 || c == 32", "c >= 48 && c <= 58 || c >= 97 && c <= 102 || c == 32"),
    ("witness: the letters", "c >= 48 && c <= 57 || c >= 97 && c <= 102 || c == 32", "c >= 48 && c <= 57 || c >= 96 && c <= 102 || c == 32"),
    ("witness: the top of the letters", "c >= 48 && c <= 57 || c >= 97 && c <= 102 || c == 32", "c >= 48 && c <= 57 || c >= 97 && c <= 103 || c == 32"),
    ("witness: a space", "c >= 48 && c <= 57 || c >= 97 && c <= 102 || c == 32", "c >= 48 && c <= 57 || c >= 97 && c <= 102 || c == 33"),
    ("witness: the newline", "if ok && int_of(out[size - 1]) == 10 {", "if ok {"),
    ("witness_of: a short answer", "if len(out) < 72 || n < 100 ||", "if len(out) < 72 || n < 10 ||"),
    ("witness_of: the head's label", "if expect(answer, n - 68 - 9,", "if expect(answer, n - 68 - 8,"),
    ("witness_of: the closing", "|| expect(answer, n - 4,", "|| expect(answer, n - 3,"),
    ("witness_of: the count's digits", "if digits < 1 || digits > 5 ||", "if digits < 1 || digits > 6 ||"),
    ("witness_of: an empty count", "if digits < 1 || digits > 5 ||", "if digits < 0 || digits > 5 ||"),
    ("witness_of: nothing after the count", "|| p != n - 77 {", "|| p > n - 77 {"),
    ("witness_of: the head's digits", "if !is_lower_hex(int_of(answer[n - 68 + k])) {", "if !is_lower_hex(int_of(answer[n - 68])) {"),
    ("witness_of: the head is copied", "out[digits + 1 + k] = answer[n - 68 + k];", "out[digits + 1 + k] = answer[n - 68];"),
    ("witness_of: the separator", "out[digits] = byte_of(32);", "out[digits] = byte_of(9);"),
    ("witness_of: the newline", "out[digits + 65] = byte_of(10);", "out[digits + 65] = byte_of(13);"),
    ("keep_witness: the write is checked", "!= len(text) {\n        return 0 - 1;", "!= 99999 {\n        return 0 - 1;"),
    ("keep_witness: the rename's target", "\"/var/lib/cancho-front/witness.new\", \"/var/lib/cancho-front/witness\")", "\"/var/lib/cancho-front/witness.new\", \"/var/lib/cancho-front/witness.new\")"),
    ("handle: a damaged witness is refused", "if wn == 0 - 2 {", "if wn == 0 - 3 {"),
    ("handle: a missing witness is a dash", "if wn < 0 {\n                line = buffer.push(heap, line, byte_of(45));", "if wn < 0 - 5 {\n                line = buffer.push(heap, line, byte_of(45));"),
    ("ask_signer: a lost witness is refused", "witness_failed = true;", "witness_failed = false;"),
    ("ask_signer: an answer with no anchor", "if wn < 0 {\n                                    status = 502;", "if wn < 0 - 9 {\n                                    status = 502;"),
]

# Mutants no request can tell from the original, each with the reason.
EQUIVALENT = {
    "witness_of: a short answer": "a 200 line that holds the anchor's tail and the key before it is at least 107 bytes, so the length bound never decides: for a shorter text `expect` already refuses a negative position",
    "identity_header: none": "with no such header `found` stays -1 whatever `n > 1` says, and `handle` refuses a negative index",
    "hex_run: the closing quote": "the quote that follows each run is checked again by `expect` of the next literal (or of the closing `\"}`), so a run that is not followed by one is refused there",
}


def mutants(cancho):
    text = open(os.path.join(ROOT, "tools/front/main.cho")).read()
    work = []
    for name, old, new in MUTANTS:
        if text.count(old) != 1:
            sys.exit(f"mutant {name!r}: the pattern occurs {text.count(old)} times")
        work.append((name, text.replace(old, new)))

    def one(item):
        name, body = item
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "mutant.cho")
            open(path, "w").write(body)
            env = dict(os.environ, FRONT_MAIN=path)
            r = subprocess.run([sys.executable, "-I", os.path.abspath(__file__)], capture_output=True, text=True, env=env, timeout=3000)
            if "build failed" in r.stdout + r.stderr:
                return name, "did not build: " + (r.stdout + r.stderr)[-200:]
            return name, ("killed" if r.returncode != 0 else "SURVIVED")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    survivors, broken = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=int(os.environ.get("JOBS", "4"))) as pool:
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
    cancho = cancho_path()
    if "--mutants" in sys.argv:
        mutants(cancho)
    with tempfile.TemporaryDirectory() as tmp:
        front_file = os.environ.get("FRONT_MAIN", os.path.join(ROOT, "tools/front/main.cho"))
        sk = make_stack(cancho, open(front_file).read(), open(os.path.join(ROOT, "tools/signer/main.cho")).read(), os.path.join(ROOT, "lib"), tmp, free_port())
        try:
            run_checks(sk, random.Random(4242))
        finally:
            sk.stop()
    print(f"{COUNT[0]} checks, {len(FAILS)} failed")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
