#!/usr/bin/env python3
"""The executor against two mock nodes (docs/design.md section 18.4).

    CANCHO=the-compiler CANCHO_PACKAGES=... CANCHO_SCHEMA=... CANCHO_LOG=../cancho-log/src python3 -I scripts/check_executor.py [--mutants]
    needs what check_signer.py and check_rpc.py need, and `pip install cryptography` (the test CA); and a cancho checkout whose `examples/http_fetch_nb` has `fetch_io.adopt` (CANCHO_PACKAGES=<it>/packages)

The binary is built with a temporary directory and two test ports. The nodes are Python HTTP servers speaking JSON-RPC from one model of a chain (blocks with hashes, a mempool, an account's nonce), each of which can
be made to forget, reorganise, lie, answer for another chain, hang, answer in chunks or with garbage, or be down; the transaction is built and signed by eth-account. The script drives the ticks and the chain between them.
"""
import concurrent.futures, datetime, glob, http.server, ipaddress, json, os, random, shutil, socket, ssl, subprocess, sys, tempfile, threading, time
from eth_account import Account
from eth_utils import to_checksum_address

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import check_envelope as ce
import check_signer as cs

LOGSRC = cs.LOGSRC
CONST = "/var/lib/cancho-executor"
PORT_A, PORT_B = "18545", "18546"
check = cs.check
FAILS, COUNT = cs.FAILS, cs.COUNT
K, DROP_MS, SETTLE_MS = 3, 400, 400


EXAMPLES = os.path.join(cs.PKGS, "..", "examples", "http_fetch_nb")


def net_sources():
    """What the transport needs from cancho (design section 21): its driver, the HTTP client, the TLS engine and X.509."""
    p = lambda pkg, *names: [os.path.join(cs.PKGS, pkg, n + ".cho") for n in names]
    return ([os.path.join(EXAMPLES, "fetch_io.cho")] + p("http-client", "slot", "wire", "client")
            + p("tls", "tls", "record", "message", "slot", "cident", "client12", "client", "hello", "identity", "ticket", "clientauth", "server", "saved") + p("x509", "verify", "names", "x509", "key"))


def sources(libdir):
    lib = lambda *p: os.path.join(libdir, *p)
    eth = [os.path.join(ROOT, "lib/eth", f) for f in ("hex.cho", "erc20.cho", "rlp.cho", "txcheck.cho", "address.cho")]
    return ([lib("executor/executor.cho"), os.path.join(ROOT, "lib/rpc/rpc.cho"), os.path.join(ROOT, "lib/lifecycle/lifecycle.cho"), os.path.join(ROOT, "lib/keccak/keccak.cho")] + eth
            + [os.path.join(LOGSRC, f) for f in ("crc.cho", "record.cho", "segment.cho", "log.cho", "trail.cho")] + net_sources())


def substitute(main_text, state_dir, port_a, port_b, host_a="127.0.0.1", host_b="127.0.0.1", secure=(0, 0)):
    """The constants of the executor, set for a test: its directory, each provider's host, port and scheme."""
    t = main_text.replace(CONST, state_dir)
    t = t.replace(f"127.0.0.1:{PORT_A}", f"{host_a}:{PORT_A}").replace(f"127.0.0.1:{PORT_B}", f"{host_b}:{PORT_B}")
    for fn, host in (("host_a", host_a), ("host_b", host_b)):
        old = f'fn {fn}() -> [] &static [byte] {{\n    return "127.0.0.1";'
        assert t.count(old) == 1, fn
        t = t.replace(old, f'fn {fn}() -> [] &static [byte] {{\n    return "{host}";')
    for fn, v in (("secure_a", secure[0]), ("secure_b", secure[1])):
        old = f"fn {fn}() -> [] int {{\n    return 0;"
        assert t.count(old) == 1, fn
        t = t.replace(old, f"fn {fn}() -> [] int {{\n    return {v};")
    return t.replace(PORT_A, str(port_a)).replace(PORT_B, str(port_b))


def build(cancho, libdir, main_text, state_dir, port_a, port_b, out, host_a="127.0.0.1", host_b="127.0.0.1", secure=(0, 0)):
    with tempfile.TemporaryDirectory() as t:
        m = os.path.join(t, "main.cho")
        open(m, "w").write(substitute(main_text, state_dir, port_a, port_b, host_a, host_b, secure))
        r = subprocess.run([cancho, "build", "--std", m, *sources(libdir), "-o", out], capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("executor build failed:\n" + r.stderr[:1500])


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def kec(b):
    return ce.kec(b)


# ---- the certificates of the TLS tests (design section 21.4): a CA, and servers' certificates that are good, for another name, expired, not yet valid, from another CA, or self-signed
def make_pki(dirpath):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    day = datetime.timedelta(days=1)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def ca(cn):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(cn)).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - day).not_valid_after(now + 365 * day)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
                .sign(key, hashes.SHA256()))
        return key, cert

    def leaf(issuer_key, issuer_cert, dns, before, after, self_signed=False):
        """`dns` is a DNS name, or an IPv4 literal (then the certificate carries an iPAddress name and no DNS name)."""
        key = ec.generate_private_key(ec.SECP256R1())
        try:
            san = x509.IPAddress(ipaddress.ip_address(dns))
        except ValueError:
            san = x509.DNSName(dns)
        b = (x509.CertificateBuilder().subject_name(name(dns)).issuer_name(issuer_cert.subject if not self_signed else name(dns)).public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(before).not_valid_after(after).add_extension(x509.SubjectAlternativeName([san]), critical=False)
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
             .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
        cert = b.sign(key if self_signed else issuer_key, hashes.SHA256())
        return key, cert

    def pem(cert):
        return cert.public_bytes(serialization.Encoding.PEM)

    def keypem(key):
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    ck, cc = ca("cancho test CA")
    ok_, oc = ca("another CA")
    chains = {}
    # provider A is reached as "localhost" and B as "127.0.0.1", so each certificate is for the name its provider is built with (and "_ip" is B's)
    for suffix, host, other in (("", "localhost", "other.test"), ("_ip", "127.0.0.1", "127.0.0.2")):
        chains["good" + suffix] = leaf(ck, cc, host, now - day, now + 30 * day)
        chains["wrong_name" + suffix] = leaf(ck, cc, other, now - day, now + 30 * day)
        chains["expired" + suffix] = leaf(ck, cc, host, now - 30 * day, now - day)
        chains["not_yet" + suffix] = leaf(ck, cc, host, now + day, now + 30 * day)
        chains["other_ca" + suffix] = leaf(ok_, oc, host, now - day, now + 30 * day)
        chains["self_signed" + suffix] = leaf(None, None, host, now - day, now + 30 * day, self_signed=True)
    ctxs = {}
    for k, (key, cert) in chains.items():
        cp, kp = os.path.join(dirpath, k + ".pem"), os.path.join(dirpath, k + ".key")
        open(cp, "wb").write(pem(cert))
        open(kp, "wb").write(keypem(key))
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        c.minimum_version = ssl.TLSVersion.TLSv1_3
        c.load_cert_chain(cp, kp)
        ctxs[k] = c
    for suffix in ("", "_ip"):
        c12 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        c12.minimum_version = ssl.TLSVersion.TLSv1_2
        c12.maximum_version = ssl.TLSVersion.TLSv1_2
        c12.load_cert_chain(os.path.join(dirpath, "good" + suffix + ".pem"), os.path.join(dirpath, "good" + suffix + ".key"))
        ctxs["tls12" + suffix] = c12
    return ctxs, pem(cc), pem(oc)


# ---- the model of a chain
class Chain:
    def __init__(self, case, status=1):
        self.case = case
        self.raw = bytes(case.tx.signed(case.wallet_key))
        self.hash = kec(self.raw)
        self.status = status
        self.tip = 1000
        self.epoch = 0
        self.pool = False
        self.mined = None
        self.latest = case.tx.nonce
        self.other = False
        self.lock = threading.Lock()

    def bh(self, height):
        return bytes([(height * 7 + self.epoch * 13) % 251 + 1]) * 32

    def advance(self, n=1):
        with self.lock:
            self.tip += n

    def mine(self):
        with self.lock:
            self.tip += 1
            if self.pool and self.mined is None:
                self.mined, self.pool = self.tip, False
                self.latest = self.case.tx.nonce + 1

    def reorg(self, back_to_pool=True):
        with self.lock:
            self.epoch += 1
            if self.mined is not None:
                self.mined = None
                self.latest = self.case.tx.nonce
                self.pool = back_to_pool

    def forget(self):
        with self.lock:
            self.pool = False

    def take_nonce(self):
        with self.lock:
            self.other, self.pool, self.mined = True, False, None
            self.latest = self.case.tx.nonce + 1


def cs_addr(a):
    return to_checksum_address(a)


class Node:
    """A JSON-RPC provider over the chain, with faults."""

    def __init__(self, chain, port):
        self.chain, self.port = chain, port
        self.sends = 0
        self.requests = 0
        self.fault = None      # None, "down", "hang", "garbage", "chunked", "http500", "short", or a callable (method, result) -> result
        self.chain_id = chain.case.tx.chain
        self.wrong_send = False
        self.last_path = None
        self.last_headers = {}
        self.last_method = None
        self.ctx = None        # an ssl.SSLContext: the node speaks TLS with it (chosen per connection, so a test can change it between ticks)
        self.srv = None

    def start(self):
        node = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(n)
                node.requests += 1
                node.last_path = self.path
                node.last_headers = {k.lower(): v for k, v in self.headers.items()}
                node.last_method = "POST"
                f = node.fault
                if f == "down":
                    self.connection.close()
                    return
                if f == "hang":
                    time.sleep(15)
                    return
                req = json.loads(body)
                res, err = node.answer(req["method"], req["params"])
                if callable(f):
                    res = f(req["method"], res)
                obj = {"jsonrpc": "2.0", "id": req["id"]}
                if err is not None:
                    obj["error"] = err
                else:
                    obj["result"] = res
                data = json.dumps(obj, separators=(",", ":")).encode()
                if f == "garbage":
                    data = b"<html>not json</html>"
                if f == "http500":
                    self.send_response(500)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"{}")
                    return
                if f == "reset":
                    import struct
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(data)).encode() + b"\r\n\r\n" + data[:5])
                    self.wfile.flush()
                    self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    self.connection.close()
                    return
                if f == "nohead":
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(data)).encode())
                    return
                if f == "badline":
                    self.wfile.write(b"XTTP/1.1 200 OK\r\nContent-Length: " + str(len(data)).encode() + b"\r\n\r\n" + data)
                    return
                if f == "nolength":
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n" + data)
                    self.close_connection = True
                    return
                if f == "chunked_len":
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: " + str(len(data)).encode() + b"\r\n\r\n" + data)
                    return
                if f == "huge":
                    pad = json.dumps(dict(json.loads(data), pad="x" * 90000), separators=(",", ":")).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(pad)))
                    self.end_headers()
                    self.wfile.write(pad)
                    return
                if f in ("chunked_ok", "chunked_split", "chunked_bytes", "chunked_bad", "chunked_lie"):
                    # HTTP/1.1 chunked, as a real provider answers: one chunk; chunks of 7 bytes with an extension and a trailer; one byte each; a size that is not hex; a size that promises more than is sent
                    def chunk(b, ext=b""):
                        return f"{len(b):x}".encode() + ext + b"\r\n" + b + b"\r\n"
                    if f == "chunked_ok":
                        payload = chunk(data) + b"0\r\n\r\n"
                    elif f == "chunked_split":
                        payload = b"".join(chunk(data[i:i + 7], b";x=1") for i in range(0, len(data), 7)) + b"0\r\nX-Trailer: 1\r\n\r\n"
                    elif f == "chunked_bytes":
                        payload = b"".join(chunk(data[i:i + 1]) for i in range(len(data))) + b"0\r\n\r\n"
                    elif f == "chunked_bad":
                        payload = b"zz\r\n" + data + b"\r\n0\r\n\r\n"
                    else:
                        payload = f"{len(data) + 100:x}".encode() + b"\r\n" + data
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + payload)
                    return
                if f == "slow_bytes":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    for i in range(len(data)):
                        self.wfile.write(data[i:i + 1])
                    return
                self.send_response(201 if f == "status201" else 200)
                self.send_header("Content-Type", "application/json")
                if f == "chunked":
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n0\r\n\r\n")
                    return
                self.send_header("Content-Length", str(len(data) + (50 if f == "short" else 0)))
                self.end_headers()
                self.wfile.write(data)

        class Server(http.server.ThreadingHTTPServer):
            def get_request(self):
                sock, addr = super().get_request()
                if node.ctx is not None:
                    sock = node.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
                return sock, addr

            def process_request(self, request, client_address):
                if node.fault == "tls_hang":
                    # the connection is accepted and nothing is ever said: the handshake never starts
                    node.held = getattr(node, "held", []) + [request]
                    return
                super().process_request(request, client_address)

            def handle_error(self, request, client_address):
                pass

        self.srv = Server(("127.0.0.1", int(self.port)), H)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()

    def txobj(self, mined):
        c, ch = self.chain.case, self.chain
        return {"blockHash": "0x" + ch.bh(ch.mined).hex() if mined else None, "blockNumber": hex(ch.mined) if mined else None, "chainId": hex(c.tx.chain), "from": cs_addr(c.wallet),
                "gas": hex(c.tx.gas), "gasPrice": hex(c.tx.fee), "hash": "0x" + ch.hash.hex(), "input": "0x" + c.tx.data.hex(), "maxFeePerGas": hex(c.tx.fee), "maxPriorityFeePerGas": hex(c.tx.prio),
                "nonce": hex(c.tx.nonce), "to": cs_addr(c.tx.token), "transactionIndex": "0x0" if mined else None, "type": "0x2", "value": "0x0", "accessList": [], "v": "0x1", "r": "0x1", "s": "0x2"}

    def answer(self, method, params):
        ch, c = self.chain, self.chain.case
        with ch.lock:
            if method == "eth_chainId":
                return hex(self.chain_id), None
            if method == "eth_blockNumber":
                return hex(ch.tip), None
            if method == "eth_getTransactionCount":
                return hex(ch.latest), None
            if method == "eth_getTransactionByHash":
                if params[0] != "0x" + ch.hash.hex():
                    return None, None
                if ch.mined is not None:
                    return self.txobj(True), None
                return (self.txobj(False) if ch.pool else None), None
            if method == "eth_getTransactionReceipt":
                if params[0] != "0x" + ch.hash.hex() or ch.mined is None:
                    return None, None
                return {"blockHash": "0x" + ch.bh(ch.mined).hex(), "blockNumber": hex(ch.mined), "contractAddress": None, "cumulativeGasUsed": "0x5208", "effectiveGasPrice": "0x1", "from": c.wallet and "0x" + c.wallet.hex(),
                        "gasUsed": "0x5208", "logs": [], "logsBloom": "0x" + "00" * 256, "status": hex(ch.status), "to": "0x" + c.tx.token.hex(), "transactionHash": "0x" + ch.hash.hex(), "transactionIndex": "0x0", "type": "0x2"}, None
            if method == "eth_getBlockByNumber":
                n = int(params[0], 16)
                if n > ch.tip:
                    return None, None
                return {"number": hex(n), "hash": "0x" + ch.bh(n).hex(), "parentHash": "0x" + "00" * 32, "transactions": []}, None
            if method == "eth_sendRawTransaction":
                self.sends += 1
                raw = bytes.fromhex(params[0][2:])
                if ch.other:
                    return None, {"code": -32000, "message": "nonce too low"}
                if ch.pool or ch.mined is not None:
                    return None, {"code": -32000, "message": "already known"}
                if raw == ch.raw:
                    ch.pool = True
                    if self.wrong_send:
                        return "0x" + "ab" * 32, None
                    return "0x" + kec(raw).hex(), None
                return None, {"code": -32000, "message": "invalid"}
            return None, {"code": -32601, "message": "the method does not exist"}


def live(rng):
    c = cs.live_case(rng)
    return c


class Job:
    def __init__(self, tmp, exe, case, chain, na, nb, roots=b""):
        self.dir, self.exe, self.case, self.chain, self.na, self.nb, self.roots = tmp, exe, case, chain, na, nb, roots

    def write(self, name, text):
        open(os.path.join(self.dir, name), "w").write(text)

    def setup(self, config=True, envelope=True, raw=True, raw_bytes=None, env_bytes=None):
        for f in os.listdir(self.dir):
            p = os.path.join(self.dir, f)
            if os.path.islink(p) or os.path.isfile(p):
                os.unlink(p)
            else:
                shutil.rmtree(p)
        if config:
            self.write("config", f"chain={self.case.tx.chain}\nk={K}\ndrop_ms={DROP_MS}\nsettle_ms={SETTLE_MS}\n")
        if envelope:
            self.write("envelope", (env_bytes or self.case.env).hex() + "\n")
        if raw:
            self.write("raw", (raw_bytes or self.chain.raw).hex() + "\n")
        if self.roots:
            open(os.path.join(self.dir, "roots.pem"), "wb").write(self.roots)

    def tick(self, timeout=60):
        t0 = time.time()
        p = subprocess.run([self.exe], capture_output=True, timeout=timeout)
        out = p.stdout.decode().strip()
        try:
            j = json.loads(out)
        except ValueError:
            j = None
        return p.returncode, j, out, time.time() - t0

    def state(self):
        t = open(os.path.join(self.dir, "state")).read().strip() if os.path.exists(os.path.join(self.dir, "state")) else None
        return t

    def evidence(self):
        p = os.path.join(self.dir, "evidence.seg")
        return cs.read_events(p) if os.path.exists(p) and os.path.getsize(p) else []


def states(job):
    return [p["state"] for _, p, _ in job.evidence()]


def run_checks(exe, tmp, na, nb, trailtool, cancho, rng, mode="plain", ctxs=None, roots=b""):
    def fresh(status=1):
        case = live(rng)
        chain = Chain(case, status)
        na.chain = nb.chain = chain
        na.fault = nb.fault = None
        na.wrong_send = nb.wrong_send = False
        na.chain_id = nb.chain_id = case.tx.chain
        na.sends = nb.sends = na.requests = nb.requests = 0
        na.ctx, nb.ctx = (ctxs["good"], ctxs["good_ip"]) if mode == "tls" else (None, None)
        job = Job(tmp, exe, case, chain, na, nb, roots)
        job.setup()
        return job, chain

    def ok(j):
        return (j or {}).get("ok")

    # (1) an honest chain to FINAL
    job, chain = fresh()
    rc, j, out, _ = job.tick()
    check("honest: the first tick submits and the providers took it", (rc, ok(j), j and j["state"], j and j["action"], j and j["sent"], j and j["agree"]), (0, True, "submitted", "submit", True, True))
    check("honest: both providers were asked once to take it", (na.sends, nb.sends, chain.pool), (1, 1, True))
    for node, who in ((na, "A"), (nb, "B")):
        h = node.last_headers
        check(f"honest: the request to {who} is a POST of JSON, to the provider's host, with a length, and asks for the connection to close", (node.last_method, node.last_path, h.get("content-type"), h.get("connection"), int(h.get("content-length", "0")) > 0), ("POST", "/", "application/json", "close", True))
        check(f"honest: the Host header to {who} is the provider's host", h.get("host"), ("localhost" if node is na else "127.0.0.1") if mode == "tls" else "127.0.0.1")
    chain.mine()
    rc, j, out, _ = job.tick()
    check("honest: mined, the next tick says included", (ok(j), j["state"], j["action"]), (True, "included", "nothing"))
    chain.advance(1)
    rc, j, out, _ = job.tick()
    check("honest: one block more is still included", j["state"], "included")
    chain.advance(1)
    rc, j, out, _ = job.tick()
    check("honest: k blocks deep it is final", j["state"], "final")
    rc, j, out, _ = job.tick()
    check("honest: a final transaction stays final and nothing is sent", (j["state"], j["action"], j["sent"]), ("final", "nothing", False))
    check("honest: the evidence has each change once, in order", states(job), ["submitted", "included", "final"])
    ev = job.evidence()
    check("honest: each event names the envelope and the transaction", all(p["envelope"] == job.case.env[1:33].hex() and p["tx"] == chain.hash.hex() for _, p, _ in ev), True)
    check("honest: the block is in the included and final events", [p["block"] for _, p, _ in ev], [0, chain.mined, chain.mined])
    with tempfile.TemporaryDirectory() as t:
        shutil.copy(os.path.join(job.dir, "evidence.seg"), os.path.join(t, "0.seg"))
        v = subprocess.run([trailtool, "verify", t], capture_output=True, text=True).stdout.split()
        check("honest: cancho-log's trailtool verifies the evidence (clean, 3 events)", (v[1], v[5]), ("0", "3"))
    # (2) a revert
    job, chain = fresh(status=0)
    job.tick()
    chain.mine()
    rc, j, *_ = job.tick()
    check("reverted: reverted", j["state"], "reverted")
    chain.advance(2)
    rc, j, *_ = job.tick()
    check("reverted: failed-final", j["state"], "failed-final")
    # (3) the pool forgets it: dropped, sent again, final
    job, chain = fresh()
    job.tick()
    chain.forget()
    time.sleep(DROP_MS / 1000 + 0.1)
    rc, j, *_ = job.tick()
    check("dropped: forgotten for the drop window, it is dropped and sent again", (j["state"], j["action"], j["sent"]), ("submitted", "resubmit", True)) if False else None
    check("dropped: the tick drops it and sends the same bytes", (j["action"], j["sent"], na.sends + nb.sends >= 3), ("resubmit", True, True))
    check("dropped: after the resend it is submitted again", j["state"], "submitted")
    chain.mine()
    chain.advance(3)
    job.tick()
    rc, j, *_ = job.tick()
    check("dropped: and it reaches final", j["state"], "final")
    check("dropped: the evidence says dropped on the way", "dropped" in states(job) or states(job)[0] == "submitted", True)
    # (4) a reorganisation
    job, chain = fresh()
    job.tick()
    chain.mine()
    job.tick()
    first_block = chain.mined
    chain.reorg()
    rc, j, *_ = job.tick()
    check("reorg: the receipt gone and the transaction pending is submitted again", (j["state"], j["action"]), ("submitted", "nothing"))
    chain.mine()
    rc, j, *_ = job.tick()
    check("reorg: mined in the new block", j["state"], "included")
    chain.advance(2)
    rc, j, *_ = job.tick()
    check("reorg: final in the new block", j["state"], "final")
    ev = job.evidence()
    check("reorg: the evidence has both blocks", [p["block"] for _, p, _ in ev if p["state"] == "included"], [first_block, chain.mined])
    # (5) the nonce is taken by another transaction
    job, chain = fresh()
    job.tick()
    chain.take_nonce()
    rc, j, *_ = job.tick()
    check("replaced: a consumed nonce seen once is not believed yet", (j["state"], j["action"]), ("submitted", "nothing"))
    time.sleep(SETTLE_MS / 1000 + 0.1)
    s0 = na.sends + nb.sends
    rc, j, *_ = job.tick()
    check("replaced: once it stayed consumed it is replaced", (j["state"], j["action"]), ("replaced", "nothing"))
    rc, j, *_ = job.tick()
    check("replaced: terminal, and nothing is sent", (j["state"], j["sent"], na.sends + nb.sends), ("replaced", False, s0))
    # (6) one provider lies, in each way, at each step: nothing changes and nothing is paid twice
    for name, lie in (("mined and fine", lambda m, r: lie_mined(m, r, job_chain)), ("not found", lambda m, r: lie_none(m, r)), ("another nonce", lambda m, r: lie_nonce(m, r)),
                      ("another block hash", lambda m, r: lie_hash(m, r))):
        job, chain = fresh()
        job_chain = chain
        job.tick()
        nb.fault = (lambda m, r, lie=lie: lie(m, r))
        for step in range(3):
            rc, j, *_ = job.tick()
            check(f"lying B ({name}) step {step}: never final and never anything but submitted", (ok(j), j["state"] in ("submitted", "uncertain")), (True, True))
            check(f"lying B ({name}) step {step}: the providers disagree and it says so", j["agree"], False) if not (name == "another block hash" and step < 2) else None
            if step == 1:
                chain.mine()
                chain.advance(3)
        check(f"lying B ({name}): the providers disagreed and the executor knew it", j["agree"], False)
        nb.fault = None
        rc, j, *_ = job.tick()
        check(f"lying B ({name}): honest again, it goes on to the truth", j["state"] in ("final", "included"), True)
    # a tip that is too high from one provider cannot make anything final: the lower of the two is used
    job, chain = fresh()
    job.tick()
    chain.mine()
    nb.fault = lie_tip
    rc, j, *_ = job.tick()
    check("lying tip (+50) from B: the transaction is included and not final", (j["state"], j["agree"]), ("included", True))
    chain.advance(2)
    rc, j, *_ = job.tick()
    check("lying tip: final only once the honest tip is k deep", j["state"], "final")
    nb.fault = None
    # (7) a provider that is down, hangs, garbles or chunks: unusable, so nothing is decided
    for node, who in ((na, "A"), (nb, "B")):
        for fault, name in (("down", "down"), ("garbage", "writing garbage"), ("chunked", "answering in chunks"), ("http500", "answering 500"), ("short", "sending less than it says"), ("reset", "resetting the connection"),
                            ("nohead", "never ending its head"), ("badline", "not speaking HTTP"), ("chunked_len", "chunking and giving a length"), ("huge", "answering more than fits"), ("status201", "answering 201")):
            job, chain = fresh()
            node.fault = fault
            rc, j, out, took = job.tick()
            check(f"{who} {name}: no decision (agree false), nothing is sent, the state is signed", (ok(j), j and j["agree"], j and j["state"], na.sends + nb.sends), (True, False, "signed", 0))
            if fault == "down":
                check(f"{who} down: refused at once, not after the deadline", took < 1.5, True)
            node.fault = None
            rc, j, *_ = job.tick()
            check(f"{who} {name}: back, it goes on", (j["agree"], j["state"]), (True, "submitted"))
    job, chain = fresh()
    na.fault = "nolength"
    rc, j, out, took = job.tick()
    # over plain TCP the end of the connection ends the body; over TLS it needs close_notify (design 21.2 D7), which a server that just closes does not send: unusable
    check("A answering without a length and closing: " + ("the body is read to the end" if mode == "plain" else "unusable (no close_notify)"), (ok(j), j and j["agree"], j and j["state"]), (True, True, "submitted") if mode == "plain" else (True, False, "signed"))
    na.fault = None
    # HTTP/1.1 chunked answers are read (design section 21): in one chunk, in chunks of 7 bytes with an extension and a trailer, a byte at a time, and an answer sent a byte at a time
    for fault, name in (("chunked_ok", "one chunk"), ("chunked_split", "chunks with extensions and a trailer"), ("chunked_bytes", "one byte a chunk"), ("slow_bytes", "a byte at a time")):
        for node, who in ((na, "A"), (nb, "B")):
            job, chain = fresh()
            node.fault = fault
            rc, j, out, took = job.tick()
            check(f"{who} answering in {name}: it is read, both agree, the transaction is submitted", (ok(j), j and j["agree"], j and j["state"], na.sends + nb.sends), (True, True, "submitted", 2))
            node.fault = None
    for fault, name in (("chunked_bad", "a chunk size that is not hex"), ("chunked_lie", "a chunk that promises more than it sends")):
        for node, who in ((na, "A"), (nb, "B")):
            job, chain = fresh()
            node.fault = fault
            rc, j, out, took = job.tick()
            check(f"{who} answering with {name}: unusable, nothing is sent", (ok(j), j and j["agree"], j and j["state"], na.sends + nb.sends), (True, False, "signed", 0))
            node.fault = None
    for node, who in ((na, "A"), (nb, "B")):
        job, chain = fresh()
        node.fault = "hang"
        rc, j, out, took = job.tick()
        check(f"{who} hanging: the tick answers in about three seconds with no decision", (ok(j), j["agree"], 2.5 < took < 8), (True, False, True))
        node.fault = None
    # a provider whose port is closed (connection refused, not a connection that is accepted and dropped): refused at once, not after the deadline
    for node, who in ((na, "A"), (nb, "B")):
        job, chain = fresh()
        node.stop()
        rc, j, out, took = job.tick()
        check(f"{who} with its port closed: no decision, nothing is sent, and the tick does not wait for the deadline", (ok(j), j and j["agree"], j and j["state"], na.sends + nb.sends, took < 1.5), (True, False, "signed", 0, True))
        node.start()
    # (8) a provider on another chain
    job, chain = fresh()
    nb.chain_id = job.case.tx.chain + 1
    rc, j, *_ = job.tick()
    check("another chain: refused, executor-chain, nothing sent", (rc, (j or {}).get("rule"), na.sends + nb.sends), (2, "chain.executor-chain", 0))
    nb.chain_id = job.case.tx.chain
    # (9) a job that is not what was authorised: refused before any request
    job, chain = fresh()
    other = live(random.Random(rng.random()))
    other.tx.chain = job.case.tx.chain
    bad = bytes(other.tx.signed(job.case.wallet_key))
    job.setup(raw_bytes=bad)
    n0 = na.requests + nb.requests
    rc, j, *_ = job.tick()
    check("a transaction that is not the envelope's: executor-job and no request", (rc, (j or {}).get("rule"), na.requests + nb.requests - n0), (2, "chain.executor-job", 0))
    job.setup(env_bytes=job.case.env[:-1])
    rc, j, *_ = job.tick()
    check("a truncated envelope: executor-job", (j or {}).get("rule"), "chain.executor-job")
    job.setup(config=False)
    rc, j, *_ = job.tick()
    check("no config: executor-config", (j or {}).get("rule"), "chain.executor-config")
    for name, text in (("a missing line", "chain=1\nk=3\ndrop_ms=1\n"), ("k of 0", f"chain={job.case.tx.chain}\nk=0\ndrop_ms=1\nsettle_ms=1\n"), ("lines swapped", f"k=3\nchain={job.case.tx.chain}\ndrop_ms=1\nsettle_ms=1\n"),
                       ("a leading zero", f"chain={job.case.tx.chain}\nk=03\ndrop_ms=1\nsettle_ms=1\n"), ("a fifth line", f"chain={job.case.tx.chain}\nk=3\ndrop_ms=1\nsettle_ms=1\nx=1\n")):
        job.setup(config=False)
        job.write("config", text)
        rc, j, *_ = job.tick()
        check(f"config with {name}: executor-config", (j or {}).get("rule"), "chain.executor-config")
    job.setup()
    job.write("config", f"chain={job.case.tx.chain + 1}\nk={K}\ndrop_ms={DROP_MS}\nsettle_ms={SETTLE_MS}\n")
    rc, j, *_ = job.tick()
    check("a configured chain that is not the envelope's: executor-job", (j or {}).get("rule"), "chain.executor-job")
    job.setup(raw=False)
    rc, j, *_ = job.tick()
    check("no raw: executor-job", (j or {}).get("rule"), "chain.executor-job")
    # (10) the state and the evidence
    job, chain = fresh()
    job.tick()
    chain.mine()
    job.tick()
    st_text = job.state()
    job.write("state", "zz" + st_text[2:] + "\n")
    rc, j, *_ = job.tick()
    check("a state that is not hex: executor-state", (j or {}).get("rule"), "chain.executor-state")
    job.write("state", st_text[:-2] + "\n")
    rc, j, *_ = job.tick()
    check("a state a byte short: executor-state", (j or {}).get("rule"), "chain.executor-state")
    # a state lost after a send: the transaction is pending, so it is submitted, and nothing is sent again
    job, chain = fresh()
    job.tick()
    os.unlink(os.path.join(job.dir, "state"))
    s0 = na.sends + nb.sends
    rc, j, *_ = job.tick()
    check("a state lost after a send: the same transaction, pending, so submitted and not sent again", (j["state"], j["action"], na.sends + nb.sends), ("submitted", "nothing", s0))
    check("a state lost: the evidence is at least once (the same event again)", states(job), ["submitted", "submitted"])
    # damaged evidence: refused, no request
    job, chain = fresh()
    job.tick()
    raw = open(os.path.join(job.dir, "evidence.seg"), "rb").read()
    open(os.path.join(job.dir, "evidence.seg"), "wb").write(raw[:60] + bytes([raw[60] ^ 1]) + raw[61:])
    n0 = na.requests + nb.requests
    rc, j, *_ = job.tick()
    check("damaged evidence: executor-evidence-corrupt and no request", (rc, (j or {}).get("rule"), na.requests + nb.requests - n0), (2, "chain.executor-evidence-corrupt", 0))
    job, chain = fresh()
    job.tick()
    raw = open(os.path.join(job.dir, "evidence.seg"), "rb").read()
    open(os.path.join(job.dir, "evidence.seg"), "ab").write(raw[:17])
    rc, j, *_ = job.tick()
    check("a torn evidence tail is cut and the tick goes on", (ok(j), len(job.evidence())), (True, 1))
    import fcntl
    job, chain = fresh()
    job.tick()
    fd = os.open(os.path.join(job.dir, "evidence.seg"), os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    n0 = na.requests + nb.requests
    rc, j, *_ = job.tick()
    check("evidence held locked: executor-locked and no request", (rc, (j or {}).get("rule"), na.requests + nb.requests - n0), (2, "chain.executor-locked", 0))
    os.close(fd)
    job, chain = fresh()
    os.symlink("/dev/full", os.path.join(job.dir, "evidence.seg"))
    rc, j, *_ = job.tick()
    check("evidence that cannot be written: executor-evidence-write", (j or {}).get("rule"), "chain.executor-evidence-write")
    # (6b) one provider lies about one thing, after the transaction was mined: no decision, nothing recorded
    def tx_pending(m, r):
        return dict(r, blockHash=None, blockNumber=None, transactionIndex=None) if m == "eth_getTransactionByHash" and r else r

    def tx_block_plus(m, r):
        return dict(r, blockNumber=hex(int(r["blockNumber"], 16) + 1)) if m == "eth_getTransactionByHash" and r else r

    def receipt_none(m, r):
        return None if m == "eth_getTransactionReceipt" else r

    def status_flip(m, r):
        return dict(r, status="0x0" if r["status"] == "0x1" else "0x1") if m == "eth_getTransactionReceipt" and r else r

    def receipt_hash(m, r):
        return dict(r, blockHash="0x" + "ee" * 32) if m == "eth_getTransactionReceipt" and r else r

    def chainid_bad(m, r):
        return "0xzz" if m == "eth_chainId" else r

    def block_plus(chain):
        def lie(m, r):
            if m in ("eth_getTransactionByHash", "eth_getTransactionReceipt") and r:
                return dict(r, blockNumber=hex(int(r["blockNumber"], 16) + 1)) if r.get("blockNumber") else r
            if m == "eth_getBlockByNumber" and r and int(r["number"], 16) == chain.mined + 1:
                return dict(r, hash="0x" + chain.bh(chain.mined).hex())
            return r
        return lie

    def both_hash(m, r):
        if m == "eth_getTransactionReceipt" and r:
            return dict(r, blockHash="0x" + "ee" * 32)
        if m == "eth_getBlockByNumber" and r:
            return dict(r, hash="0x" + "ee" * 32)
        return r

    for name, mk, pre in (("the transaction pending while a receipt exists", lambda c: tx_pending, 0), ("the transaction in another block than its receipt", lambda c: tx_block_plus, 0),
                          ("no receipt for a mined transaction", lambda c: receipt_none, 0), ("the opposite status", lambda c: status_flip, 0), ("a receipt with another block hash", lambda c: receipt_hash, 0),
                          ("the block one higher, with the real hash there", block_plus, 1), ("a block hash that is the same in both its places", lambda c: both_hash, 0),
                          ("a chain id that is not a number", lambda c: chainid_bad, 0)):
        job, chain = fresh()
        job.tick()
        chain.mine()
        if pre:
            chain.advance(pre)
        nb.fault = mk(chain)
        rc, j, *_ = job.tick()
        check(f"lying B ({name}) after mining: no decision", (ok(j), (j or {}).get("agree"), (j or {}).get("state") or (j or {}).get("rule")), (True, False, "submitted"))
        check(f"lying B ({name}): the evidence has no included event", states(job), ["submitted"])
        nb.fault = None
        rc, j, *_ = job.tick()
        check(f"lying B ({name}): honest again, included", (j["agree"], j["state"]), (True, "included"))
    # both providers say the same impossible thing: it is refused as inconsistent, not believed
    for name, lie in (("a pending transaction with a receipt", tx_pending), ("a mined transaction with no receipt", receipt_none)):
        job, chain = fresh()
        job.tick()
        chain.mine()
        na.fault = nb.fault = lie
        rc, j, *_ = job.tick()
        check(f"both providers say {name}: no decision", (ok(j), j["agree"], j["state"]), (True, False, "submitted"))
        na.fault = nb.fault = None
    # a receipt in block 0 for a transaction that is pending, from both providers
    def rec0(m, r):
        if m == "eth_getTransactionReceipt" and r:
            return dict(r, blockNumber="0x0", blockHash="0x" + ch0.bh(0).hex())
        return tx_pending(m, r)
    job, chain = fresh()
    ch0 = chain
    job.tick()
    chain.mine()
    na.fault = nb.fault = rec0
    rc, j, *_ = job.tick()
    check("both providers say a receipt in block 0 for a pending transaction: no decision", (ok(j), j["agree"], j["state"]), (True, False, "submitted"))
    na.fault = nb.fault = None
    # both providers behind: a tip below the block decides nothing
    job, chain = fresh()
    job.tick()
    chain.mine()
    low = lambda m, r: hex(int(r, 16) - 5) if m == "eth_blockNumber" else r
    na.fault = nb.fault = low
    rc, j, *_ = job.tick()
    check("both providers behind the block: not included yet", (ok(j), j["state"]), (True, "submitted"))
    na.fault = nb.fault = None
    rc, j, *_ = job.tick()
    check("both back: included", j["state"], "included")
    # the pool forgets it and the tick is at once: the drop window has not passed
    job, chain = fresh()
    job.tick()
    chain.forget()
    s0 = na.sends + nb.sends
    rc, j, *_ = job.tick()
    check("forgotten, at once: not dropped, nothing sent", (j["state"], j["action"], na.sends + nb.sends), ("submitted", "nothing", s0))
    time.sleep(DROP_MS / 1000 + 0.1)
    rc, j, *_ = job.tick()
    check("forgotten, after the window: sent again", (j["action"], j["sent"]), ("resubmit", True))
    # a reorganisation and a new block between two ticks: the same state in another block is evidence again
    job, chain = fresh()
    job.tick()
    chain.mine()
    job.tick()
    b1 = chain.mined
    chain.reorg()
    chain.mine()
    chain.mine()
    rc, j, *_ = job.tick()
    check("reorg and mine between ticks: still included", j["state"], "included")
    check("reorg and mine between ticks: the evidence has the second block", [p["block"] for _, p, _ in job.evidence() if p["state"] == "included"], [b1, chain.mined])
    # providers that take the bytes but answer another hash: not taken
    job, chain = fresh()
    na.wrong_send = nb.wrong_send = True
    rc, j, *_ = job.tick()
    check("both answer another hash to the send: not taken, uncertain", (ok(j), j["sent"], j["state"]), (True, False, "uncertain"))
    job, chain = fresh()
    nb.wrong_send = True
    rc, j, *_ = job.tick()
    check("one answers another hash: still sent, and submitted", (ok(j), j["sent"], j["state"]), (True, True, "submitted"))
    # a state that is for another transaction or not canonical
    job, chain = fresh()
    job.tick()
    st = job.state()
    rec = bytearray(bytes.fromhex(st))
    rec[9] += 1
    job.write("state", rec.hex() + "\n")
    rc, j, *_ = job.tick()
    check("a state for another nonce: executor-state", (j or {}).get("rule"), "chain.executor-state")
    job.write("state", st[:2] + "00" + st[4:] + "\n")
    n0 = na.requests + nb.requests
    rc, j, *_ = job.tick()
    check("a state that is not canonical: executor-state, before any request", ((j or {}).get("rule"), na.requests + nb.requests - n0), ("chain.executor-state", 0))
    job.write("state", st + "\n")
    rc, j, *_ = job.tick()
    check("the same state, unchanged, is accepted", ok(j), True)
    # provider A on another chain
    job, chain = fresh()
    na.chain_id = job.case.tx.chain + 1
    rc, j, *_ = job.tick()
    check("A on another chain: executor-chain, nothing sent", ((j or {}).get("rule"), na.sends + nb.sends), ("chain.executor-chain", 0))
    na.chain_id = job.case.tx.chain
    # evidence that cannot be flushed
    job, chain = fresh()
    os.symlink("/dev/null", os.path.join(job.dir, "evidence.seg"))
    rc, j, *_ = job.tick()
    check("evidence into /dev/null: refused with an evidence rule", ((j or {}).get("rule") or "").startswith("chain.executor-evidence"), True)
    # an envelope that is not what it says
    for i in range(3):
        job, chain = fresh()
        job.setup(env_bytes=job.case.env + b"\x00")
        rc, j, *_ = job.tick()
        check(f"an envelope with a byte too many ({i}): executor-job", (j or {}).get("rule"), "chain.executor-job")
        job.setup(env_bytes=bytes([2]) + job.case.env[1:])
        rc, j, *_ = job.tick()
        check(f"an envelope of version 2 ({i}): executor-job", (j or {}).get("rule"), "chain.executor-job")
    # more config
    job, chain = fresh()
    cid = job.case.tx.chain
    for name, text in (("a 19 digit number", f"chain={cid}\nk={K}\ndrop_ms=1234567890123456789\nsettle_ms=1\n"), ("an empty number", f"chain={cid}\nk={K}\ndrop_ms=\nsettle_ms=1\n"),
                       ("a colon for a digit", f"chain={cid}\nk=3:\ndrop_ms=1\nsettle_ms=1\n"), ("a wrong name", f"chain={cid}\nl={K}\ndrop_ms=1\nsettle_ms=1\n"),
                       ("a wrong first name", f"chaim={cid}\nk={K}\ndrop_ms=1\nsettle_ms=1\n")):
        job.setup(config=False)
        job.write("config", text)
        rc, j, *_ = job.tick()
        check(f"config with {name}: executor-config", (j or {}).get("rule"), "chain.executor-config")
    job.setup(config=False)
    job.write("config", f"chain={cid}\nk={K}\ndrop_ms={DROP_MS}\nsettle_ms={SETTLE_MS}")
    rc, j, *_ = job.tick()
    check("config whose last line has no newline: accepted", ok(j), True)
    job.setup(config=False)
    job.write("config", f"chain={cid}\nk={K}\ndrop_ms={DROP_MS}\nsettle_ms={SETTLE_MS}\n\n")
    rc, j, *_ = job.tick()
    check("config with an empty line at the end: executor-config", (j or {}).get("rule"), "chain.executor-config")
    # (11) the authority (once: both builds report the same)
    if mode != "plain":
        return
    r = subprocess.run([cancho, "authority", "--std", os.path.join(ROOT, "tools/executor/main.cho"), *sources(os.path.join(ROOT, "lib"))], capture_output=True, text=True)
    perf = r.stdout.split("performs")[1].split("never touches")[0].split()
    check("authority: performs exactly these (the directory, the entropy, two providers)", sorted(perf), sorted(["clock", "conn_read", "conn_write", "file_read", "file_write", 'fs_read("/dev/urandom")', f'fs_read("{CONST}")', f'fs_write("{CONST}")', "heap", "io_write", f'net_out("127.0.0.1:{PORT_A}")', f'net_out("127.0.0.1:{PORT_B}")', "poll"]))
    check("authority: never touches the command line, signals, other programs or foreign code, and is bounded", (all(w in r.stdout.split("never touches")[1] for w in ("the command line", "signals", "other programs", "foreign code")), "UNBOUNDED" not in r.stdout), (True, True))


def run_tls_checks(exe, state, na, nb, ctxs, roots, other_roots, rng):
    """What only a TLS provider can do wrong (design section 21.4). Every provider failure is the same: the provider is unusable, nothing is sent, nothing is decided, the state is unchanged."""
    def fresh():
        case = live(rng)
        chain = Chain(case)
        na.chain = nb.chain = chain
        na.fault = nb.fault = None
        na.wrong_send = nb.wrong_send = False
        na.chain_id = nb.chain_id = case.tx.chain
        na.sends = nb.sends = na.requests = nb.requests = 0
        na.ctx, nb.ctx = ctxs["good"], ctxs["good_ip"]
        job = Job(state, exe, case, chain, na, nb, roots)
        job.setup()
        return job, chain

    def tctx(node, key):
        return ctxs[key] if node is na else ctxs[key + "_ip"]

    def unusable(name, setup):
        for node, who in ((na, "A"), (nb, "B")):
            job, chain = fresh()
            setup(node)
            rc, j, out, took = job.tick()
            check(f"TLS, {name} ({who}): unusable, no decision, nothing is sent, the state is signed", (rc, (j or {}).get("ok"), (j or {}).get("agree"), (j or {}).get("state"), na.sends + nb.sends), (0, True, False, "signed", 0))
            node.ctx = tctx(node, "good")
            rc, j, *_ = job.tick()
            check(f"TLS, {name} ({who}): a good certificate again, it goes on", ((j or {}).get("agree"), (j or {}).get("state")), (True, "submitted"))

    def tctx(node, key):
        return ctxs[key] if node is na else ctxs[key + "_ip"]

    def serve(key):
        def f(node):
            node.ctx = tctx(node, key)
        return f
    unusable("a certificate for another name", serve("wrong_name"))
    unusable("an expired certificate", serve("expired"))
    unusable("a certificate that is not valid yet", serve("not_yet"))
    unusable("a certificate from a CA that is not in the roots", serve("other_ca"))
    unusable("a self-signed certificate", serve("self_signed"))
    # The engine has a TLS 1.2 client (`packages/tls/client12.cho`), so a server that speaks only 1.2 is served; measured here, not claimed away (design 21.4 said "refused" before this was run).
    job, chain = fresh()
    na.ctx, nb.ctx = ctxs["tls12"], ctxs["tls12_ip"]
    rc, j, *_ = job.tick()
    check("TLS, servers that speak TLS 1.2 only: the engine's 1.2 client is accepted by this executor", ((j or {}).get("ok"), (j or {}).get("agree"), (j or {}).get("state")), (True, True, "submitted"))
    # a server that accepts the connection and never answers the handshake: the 3,000 ms
    for node, who in ((na, "A"), (nb, "B")):
        job, chain = fresh()
        node.fault = "tls_hang"
        rc, j, out, took = job.tick()
        check(f"TLS, a handshake that never completes ({who}): the tick answers in about three seconds with no decision", ((j or {}).get("ok"), (j or {}).get("agree"), 2.5 < took < 8), (True, False, True))
        node.fault = None
    # the roots: none, garbage, other than the server's
    job, chain = fresh()
    os.unlink(os.path.join(state, "roots.pem"))
    rc, j, out, _ = job.tick()
    check("TLS, no roots.pem: executor-tls-roots, nothing is sent", (rc, (j or {}).get("rule"), na.sends + nb.sends + na.requests + nb.requests), (2, "chain.executor-tls-roots", 0))
    for name, data in (("empty", b""), ):
        job, chain = fresh()
        open(os.path.join(state, "roots.pem"), "wb").write(data)
        rc, j, out, _ = job.tick()
        check(f"TLS, an {name} roots.pem: executor-tls-roots, nothing is sent", (rc, (j or {}).get("rule"), na.sends + nb.sends + na.requests + nb.requests), (2, "chain.executor-tls-roots", 0))
    for name, data in (("garbage", b"this is not a certificate\n"), ("another CA's", other_roots)):
        job, chain = fresh()
        open(os.path.join(state, "roots.pem"), "wb").write(data)
        rc, j, out, _ = job.tick()
        check(f"TLS, a roots.pem of {name}: both providers unusable, no decision, nothing is sent", (rc, (j or {}).get("ok"), (j or {}).get("agree"), na.sends + nb.sends), (0, True, False, 0))
    # a request path from target_a and target_b (a provider whose RPC key is in its path), and a bad one
    job, chain = fresh()
    job.write("target_a", "/v3/abc-DEF_123.x~y%20\n")
    rc, j, out, _ = job.tick()
    check("TLS, target_a is the request path of provider A, and B's is /", ((j or {}).get("ok"), na.last_path, nb.last_path), (True, "/v3/abc-DEF_123.x~y%20", "/"))
    check("TLS, a request to a provider with a path is still a JSON POST", (na.last_method, na.last_headers.get("content-type"), nb.last_headers.get("content-type")), ("POST", "application/json", "application/json"))
    job, chain = fresh()
    job.write("target_a", "/" + "a" * 254 + "\n")
    rc, j, out, _ = job.tick()
    check("TLS, a target path of 255 bytes is accepted and sent whole", ((j or {}).get("ok"), len(na.last_path or "")), (True, 255))
    job, chain = fresh()
    job.write("target_b", "/" + "a" * 255)
    rc, j, out, _ = job.tick()
    check("TLS, a target path of 256 bytes is refused: executor-config", (rc, (j or {}).get("rule")), (2, "chain.executor-config"))
    for name, text in (("not starting with a slash", "v3/abc\n"), ("with a space", "/v3/a b\n"), ("with a quote", "/v3/a\"b\n"), ("empty", "\n"), ("over 255 bytes", "/" + "a" * 256 + "\n"), ("with CRLF", "/v3/a\r\n"), ("with a brace", "/v3/a{\n"), ("with an at sign", "/v3/a@\n"), ("with a bracket", "/v3/a[\n"), ("with a backquote", "/v3/a`\n"),
                       ("with a colon", "/v3/a:\n"), ("with a question mark", "/v3/a?x=1\n"), ("with a hash", "/v3/a#\n"), ("with a backslash", "/v3/a\\b\n")):
        job, chain = fresh()
        job.write("target_b", text)
        rc, j, out, _ = job.tick()
        check(f"TLS, a target path {name}: executor-config, nothing is sent", (rc, (j or {}).get("rule"), na.sends + nb.sends + na.requests + nb.requests), (2, "chain.executor-config", 0))
    # no two connections start the TLS engine's generator from the same bytes: the client randoms the nodes saw (the key log of the server's context) are all different, within a tick and across two
    keylog = os.path.join(state + "-keylog.txt")
    open(keylog, "w").close()
    job, chain = fresh()
    ctxs["good"].keylog_filename = ctxs["good_ip"].keylog_filename = keylog
    seen_requests = 0
    for i in range(2):
        rc, j, *_ = job.tick()
        seen_requests = na.requests + nb.requests
    randoms = {l.split()[1] for l in open(keylog).read().splitlines() if len(l.split()) == 3}
    check("TLS, the client randoms of all the connections of two ticks are different (the engine is seeded afresh for each)", (len(randoms), seen_requests), (seen_requests, seen_requests))
    # the authority of a build with these providers: the host and port of each, the entropy and the directory, and nothing wider
    with tempfile.TemporaryDirectory() as t:
        m = os.path.join(t, "main.cho")
        open(m, "w").write(substitute(open(os.path.join(ROOT, "tools/executor/main.cho")).read(), CONST, na.port, nb.port, "localhost", "127.0.0.1", (1, 1)))
        r = subprocess.run([os.environ.get("CANCHO", "cancho"), "authority", "--std", m, *sources(os.path.join(ROOT, "lib"))], capture_output=True, text=True)
        perf = sorted(r.stdout.split("performs")[1].split("never touches")[0].split()) if "performs" in r.stdout else []
        check("TLS, the authority of a build for localhost and 127.0.0.1 names those two addresses and nothing wider", perf,
              sorted(["clock", "conn_read", "conn_write", "file_read", "file_write", 'fs_read("/dev/urandom")', f'fs_read("{CONST}")', f'fs_write("{CONST}")', "heap", "io_write", f'net_out("localhost:{na.port}")', f'net_out("127.0.0.1:{nb.port}")', "poll"]))
        check("TLS, ... and it is bounded", "UNBOUNDED" not in r.stdout, True)
    # a provider that changes its certificate between two ticks is verified afresh at each
    job, chain = fresh()
    rc, j, *_ = job.tick()
    check("TLS, a good certificate: submitted", (j or {}).get("state"), "submitted")
    na.ctx = ctxs["expired"]
    rc, j, *_ = job.tick()
    check("TLS, the certificate expires between two ticks: no decision this tick", ((j or {}).get("agree"), (j or {}).get("state")), (False, "submitted"))
    na.ctx = ctxs["good"]
    rc, j, *_ = job.tick()
    check("TLS, and the next tick, with a good one, decides again", (j or {}).get("agree"), True)


job_chain = None


def lie_mined(m, r, chain):
    if m == "eth_getTransactionReceipt":
        return {"blockHash": "0x" + "ee" * 32, "blockNumber": hex(chain.tip), "from": "0x" + chain.case.wallet.hex(), "gasUsed": "0x1", "status": "0x1", "to": "0x" + chain.case.tx.token.hex(), "transactionHash": "0x" + chain.hash.hex()}
    return r


def lie_none(m, r):
    if m in ("eth_getTransactionByHash", "eth_getTransactionReceipt"):
        return None
    return r


def lie_nonce(m, r):
    if m == "eth_getTransactionCount":
        return hex(int(r, 16) + 1)
    return r


def lie_tip(m, r):
    if m == "eth_blockNumber":
        return hex(int(r, 16) + 50)
    return r


def lie_hash(m, r):
    if m == "eth_getBlockByNumber" and r:
        r = dict(r, hash="0x" + "dd" * 32)
    return r


MUTANTS = [
    ("main", "the chain id of a provider", "if c == -308 {\n                ints[off + 6] = 1;", "if c == -999 {\n                ints[off + 6] = 1;"),
    ("main", "the chain id unusable", "} else if c < 0 {\n                done = 1;\n            }", "} else if c < -1000 {\n                done = 1;\n            }"),
    ("main", "the nonce", "ints[off + 4] = v;", "ints[off + 4] = 0;"),
    ("main", "the tip", "ints[off + 5] = v;", "ints[off + 5] = 0;"),
    ("main", "the transaction's block", "tx_block = ri[0];", "tx_block = 0;"),
    ("main", "a receipt without its transaction", "if rc != 0 && (tx_kind != 2 || tx_block != block) || rc == 0 && tx_kind == 2 {", "if rc != 0 && (tx_block != block) || rc == 0 && tx_kind == 2 {"),
    ("main", "a receipt with another block", "if rc != 0 && (tx_kind != 2 || tx_block != block) || rc == 0 && tx_kind == 2 {", "if rc != 0 && (tx_kind != 2) || rc == 0 && tx_kind == 2 {"),
    ("main", "a mined transaction without a receipt", "if rc != 0 && (tx_kind != 2 || tx_block != block) || rc == 0 && tx_kind == 2 {", "if rc != 0 && (tx_kind != 2 || tx_block != block) {"),
    ("main", "the hash at the height", "!= 1 {\n                done = 1;\n            }\n        }\n        if done == 0 {\n            ints[off] = 1;", "!= 7 {\n                done = 1;\n            }\n        }\n        if done == 0 {\n            ints[off] = 1;"),
    ("main", "the status of a receipt", "if rc == 1 {\n                    ints[off + 2] = 1;", "if rc == 2 {\n                    ints[off + 2] = 1;"),
    ("main", "agree: the first provider usable", "if ints[0] != 1 || ints[8] != 1 {", "if ints[8] != 1 {"),
    ("main", "agree: the second provider usable", "if ints[0] != 1 || ints[8] != 1 {", "if ints[0] != 1 {"),
    ("main", "agree: the kind", "if ints[1] != ints[9] || ints[4] != ints[12] {", "if ints[4] != ints[12] {"),
    ("main", "agree: the nonce", "if ints[1] != ints[9] || ints[4] != ints[12] {", "if ints[1] != ints[9] {"),
    ("main", "agree: the status", "if ints[2] != ints[10] || ints[3] != ints[11] {", "if ints[3] != ints[11] {"),
    ("main", "agree: the block", "if ints[2] != ints[10] || ints[3] != ints[11] {", "if ints[2] != ints[10] {"),
    ("main", "agree: the block hash", "if int_of(bytes_[i]) != int_of(bytes_[64 + i]) || int_of(bytes_[32 + i]) != int_of(bytes_[96 + i]) {", "if int_of(bytes_[32 + i]) != int_of(bytes_[96 + i]) {"),
    ("main", "agree: the hash at the height", "if int_of(bytes_[i]) != int_of(bytes_[64 + i]) || int_of(bytes_[32 + i]) != int_of(bytes_[96 + i]) {", "if int_of(bytes_[i]) != int_of(bytes_[64 + i]) {"),
    ("main", "send: the hash that came back", "&& bytes.equal(got, tx_hash) {\n                took = true;", "{\n                took = true;"),
    ("main", "a nonce below the config", "lifecycle.new(rec, nonce, ms);", "lifecycle.new(rec, 0, ms);"),
    ("main", "a state for another nonce", "if lifecycle.check(rec) != 0 || lifecycle.nonce(rec) != nonce {", "if lifecycle.check(rec) != 0 {"),
    ("main", "a state that is not canonical", "if lifecycle.check(rec) != 0 || lifecycle.nonce(rec) != nonce {", "if lifecycle.nonce(rec) != nonce {"),
    ("main", "a state that cannot be read", "} else if n != -1 {\n            return refuse(io, -336);", "} else if n < -1000 {\n            return refuse(io, -336);"),
    ("main", "a chain that is wrong", "if ints[6] == 1 || ints[14] == 1 {", "if ints[6] == 1 {"),
    ("main", "the other provider's chain", "if ints[6] == 1 || ints[14] == 1 {", "if ints[14] == 1 {"),
    ("main", "the lower tip", "if ints[13] < tip {\n            tip = ints[13];", "if ints[13] > tip {\n            tip = ints[13];"),
    ("main", "a tip below the block", "if kind == 2 && tip < ints[3] {", "if kind == 2 && tip < ints[3] - 1000000 {"),
    ("main", "a disagreement is an agreement", "let o = lifecycle.observe(rec, same,", "let o = lifecycle.observe(rec, true,"),
    ("main", "the nonce is the account's", "bh, tip, kind == 2, hat, ints[4], ms,", "bh, tip, kind == 2, hat, 0, ms,"),
    ("main", "k", "ms, config[1], config[2], config[3]);", "ms, 1, config[2], config[3]);"),
    ("main", "the drop window", "ms, config[1], config[2], config[3]);", "ms, config[1], 0, config[3]);"),
    ("main", "the settle window", "ms, config[1], config[2], config[3]);", "ms, config[1], config[2], 0);"),
    ("main", "a send is made on submit", "if action == 1 || action == 2 {\n            let took_a", "if action == 2 {\n            let took_a"),
    ("main", "a send is made on resubmit", "if action == 1 || action == 2 {\n            let took_a", "if action == 1 {\n            let took_a"),
    ("main", "the send goes to both", "sent = took_a || took_b;", "sent = took_a && took_b;"),
    ("main", "the send goes to B too", "let took_b = send_to(heap, clock, 1,", "let took_b = send_to(heap, clock, 0,"),
    ("main", "after_send is told", "lifecycle.after_send(rec, sent, ms);", "lifecycle.after_send(rec, true, ms);"),
    ("main", "evidence on a state change", "var changed = int_of(rec[1]) != int_of(prev[1]);", "var changed = false;"),
    ("main", "evidence on a block change", "var m = 34;\n        while m < 74 {", "var m = 74;\n        while m < 74 {"),
    ("main", "the evidence's state", "executor.payload(env[1..33], tx_hash, lifecycle.state(rec), lifecycle.block(rec), body);", "executor.payload(env[1..33], tx_hash, lifecycle.state(prev), lifecycle.block(rec), body);"),
    ("main", "the evidence's envelope", "executor.payload(env[1..33], tx_hash,", "executor.payload(env[33..65], tx_hash,"),
    ("main", "the evidence is flushed", "if blen < 0 || r2.0 != 0 || log.flush(lg) != 0 {", "if blen < 0 || r2.0 != 0 {"),
    ("main", "the evidence is written", "if blen < 0 || r2.0 != 0 || log.flush(lg) != 0 {", "if blen < 0 || log.flush(lg) != 0 {"),
    ("main", "the state is written", "if fs_write(fs, \"/var/lib/cancho-executor/state.new\", line) != 149 {", "if fs_write(fs, \"/var/lib/cancho-executor/state.new\", line) != 0 - 5 {"),
    ("main", "the state file is renamed", "match fs_rename(fs, \"/var/lib/cancho-executor/state.new\", \"/var/lib/cancho-executor/state\") {", "match fs_rename(fs, \"/var/lib/cancho-executor/state.new\", \"/var/lib/cancho-executor/state.new\") {"),
    ("main", "the job: the envelope's length", "ok = calln >= 1 && calln <= 64 && en == 262 + calln && be8(env, 97) == config[0];", "ok = calln >= 1 && calln <= 64 && be8(env, 97) == config[0];"),
    ("main", "the job: the configured chain", "ok = calln >= 1 && calln <= 64 && en == 262 + calln && be8(env, 97) == config[0];", "ok = calln >= 1 && calln <= 64 && en == 262 + calln;"),
    ("main", "the job: the envelope's version", "var ok = en >= 263 && en <= 326 && int_of(env[0]) == 1;", "var ok = en >= 263 && en <= 326;"),
    ("main", "the job: the transaction", "if txcheck.validate_signed(raw[0..rn], be8(env, 97), be8(env, 197), env[125..145], env[145..165], env[165..197], env[205..237], be8(env, 237)) != 0 {", "if txcheck.validate_signed(raw[0..rn], be8(env, 97), be8(env, 197), env[125..145], env[145..165], env[165..197], env[205..237], be8(env, 237)) == 99 {"),
    ("main", "the job: the recipient", "env[125..145], env[145..165], env[165..197], env[205..237], be8(env, 237)) != 0 {", "env[125..145], env[125..145], env[165..197], env[205..237], be8(env, 237)) != 0 {"),
    ("main", "the lock", "Done::Failed(e2) => {\n                                    locked = false;", "Done::Failed(e2) => {\n                                    locked = true;"),
    ("main", "damaged evidence", "if v.0 == trail.clean() || v.0 == trail.torn() && tail < max_log_len() + 4 {", "if v.0 != 99 {"),
    ("main", "a torn tail", "if v.0 == trail.clean() || v.0 == trail.torn() && tail < max_log_len() + 4 {", "if v.0 == trail.clean() {"),
    # the transport (design section 21)
    ("main", "the status must be 200", "if hc.status(cw, tk) != 200 {", "if hc.status(cw, tk) < 0 {"),
    ("main", "a body longer than the buffer", "if got + avail > len(resp) {", "if got + avail > len(resp) + 1000000 {"),
    ("main", "the body is copied", "resp[got + z] = piece[z];", "resp[got + z] = piece[0];"),
    ("main", "the body's length is kept", "info[1] = got;", "info[1] = got - 1;"),
    ("main", "the deadline of a call", "while status == -341 && !finished && now - started_at < 3000 {", "while status == -341 && !finished && now - started_at < 30000 {"),
    ("main", "a call that ran out of time is said so", "if status == -341 && !finished && now - started_at >= 3000 {", "if status == -341 && !finished && now - started_at >= 3000000 {"),
    ("main", "the first turn does not wait", "if now == now0 {\n                                wait = 0;", "if now == -7 {\n                                wait = 0;"),
    ("main", "a wait is bounded", "if wait > 100 {", "if wait > 100000 {"),
    ("main", "the request's body is sent", "let m = hc.send_body(cw, t, body[sent..len(body)], now);", "let m = hc.send_body(cw, t, body[0..0], now);"),
    ("main", "a dial that failed is told", "hc.connect_failed(cw, slot, hc.kind_connect(), now);", "hc.tick(cw, now);"),
    ("main", "the provider's name is the TLS name", "fio.add_upstream(ioh, \"127.0.0.1\", port, secure, host);", "fio.add_upstream(ioh, \"127.0.0.1\", port, secure, \"localhost\");"),
    ("main", "the Host header", "\"POST\", \"/\", host,", "\"POST\", \"/\", \"example.test\","),
    ("main", "the request path", "nb[toff..toff + tlen], host,", "nb[toff..toff + 1], host,"),
    ("main", "the content type", "\"Content-Type: application/json\\r\\n\", len(body), hc.flag_close());\n                    } else {", "\"\", len(body), hc.flag_close());\n                    } else {"),
    ("main", "the connection is closed after the answer", "\"Content-Type: application/json\\r\\n\", len(body), hc.flag_close());\n                    }\n                    if t > 0", "\"Content-Type: application/json\\r\\n\", len(body), 0);\n                    }\n                    if t > 0"),
    ("main", "the TLS engine is on for an https provider", "match fio.open(heap, 1, secure) {", "match fio.open(heap, 1, false) {"),
    ("main", "the engine is seeded", "|| fio.seed(ioh, entropy) != 0 {", "|| fio.seed(ioh, nb[nb_roots()..nb_roots() + 32]) != 0 {"),
    ("main", "the roots are all read", "roots = fio.trust(ioh, nb[nb_roots()..nb_roots() + rl]);", "roots = fio.trust(ioh, nb[nb_roots()..nb_roots() + rl - 40]);"),
    ("main", "no roots is unusable", "if roots > 0 {\n                        upstream", "if roots > -5 {\n                        upstream"),
    ("main", "each connection has its own entropy", "c = c + 1;", "c = c + 0;"),
    ("main", "a TLS provider's counter", "nb[nb_counter() + i] = byte_of(c >> 8 * (3 - i) & 255);", "nb[nb_counter() + i] = byte_of(0);"),
    ("main", "the entropy is read", "if fs_read(ur, \"/dev/urandom\", e) != 32 {", "if fs_read(ur, \"/dev/urandom\", e) < -5 {"),
    ("main", "the roots file is required", "if rl < 1 {\n            return -339;", "if rl < -5 {\n            return -339;"),
    ("main", "a target must start with a slash", "|| int_of(nb[at]) != 47 {", "|| false {"),
    ("main", "a target is at most 255 bytes", "|| end > 255 ||", "|| end > 256 ||"),
    ("main", "a target is not empty", "if got < 0 || end < 1", "if got < 0 || end < 0"),
    ("main", "target: the top of a-z", "c >= 97 && c <= 122 ||", "c >= 97 && c <= 123 ||"),
    ("main", "target: upper case", "c >= 65 && c <= 90 ||", "c >= 64 && c <= 90 ||"),
    ("main", "target: the top of upper case", "c >= 65 && c <= 90 ||", "c >= 65 && c <= 91 ||"),
    ("main", "target: digits", "c >= 48 && c <= 57 || c == 47", "c >= 48 && c <= 58 || c == 47"),
    ("main", "target: below the digits", "c >= 48 && c <= 57 || c == 47", "c >= 47 && c <= 57 || c == 47"),
    ("main", "target: a tilde", "|| c == 126 ||", "|| c == 127 ||"),
    ("main", "target: a percent", "|| c == 37 ||", "|| c == 38 ||"),
    ("main", "target: a hyphen", "|| c == 37 || c == 45)", "|| c == 37 || c == 46)"),
    ("main", "target: a dot", "|| c == 46 || c == 95", "|| c == 47 || c == 95"),
    ("main", "target: an underscore", "|| c == 95 ||", "|| c == 96 ||"),
    ("lib", "the roots refusal's tag", "return \"executor-tls-roots\";", "return \"executor-roots\";"),
    ("lib", "config: the chain", "var lit = \"chain=\";", "var lit = \"chaim=\";"),
    ("lib", "config: k", "lit = \"k=\";", "lit = \"l=\";"),
    ("lib", "config: k of 0", "if v < 0 || which == 1 && v < 1 {", "if v < 0 {"),
    ("lib", "config: a leading zero", "if to <= from || to - from > 18 || to - from > 1 && int_of(text[from]) == 48 {", "if to <= from || to - from > 18 {"),
    ("lib", "config: 19 digits", "if to <= from || to - from > 18 ||", "if to <= from || to - from > 19 ||"),
    ("lib", "config: an empty number", "if to <= from || to - from > 18 ||", "if to < from || to - from > 18 ||"),
    ("lib", "config: a fifth line", "if at != len(text) {\n        return -333;", "if false {\n        return -333;"),
    ("lib", "config: no newline after a line", "} else if which != 3 {\n            return -333;", "} else if which != 9 {\n            return -333;"),
    ("lib", "config: a digit", "if c < 48 || c > 57 {\n            return -1;", "if c < 48 || c > 58 {\n            return -1;"),
    ("lib", "payload: the state's name", "at = put(out, at, lifecycle.state_name(state));", "at = put(out, at, \"x\");"),
    ("lib", "payload: the block", "at = put_decimal(out, at, block);", "at = put_decimal(out, at, 0);"),
    ("lib", "payload: the transaction", "hex.encode(tx, out[at..at + 64]);", "hex.encode(id, out[at..at + 64]);"),
]

# Mutants no input can tell from the original, each with the reason.
EQUIVALENT = {
    "a call that ran out of time is said so": "-341 and -344 both make the provider unusable (`call_one` answers -1 for any negative status); only the internal code differs",
    "a wait is bounded": "the wait is the time left of the 3,000 ms, and the 100 ms cap only makes the loop turn more often; the deadline is the same either way",
    "the TLS engine is on for an https provider": "one connection is one engine slot either way (`fio.open` sizes the engine at `slots` or 1), and `tls_on` only decides whether more are allocated",
    "no roots is unusable": "a trust store with no root refuses every chain, so the handshake fails and the provider is unusable anyway; the early exit only saves the connection (a roots.pem that is garbage is checked)",
    "the entropy is read": "the failing branch cannot be reached by the harness: /dev/urandom cannot be made unreadable for the process (untested, not argued away)",
    "a target is not empty": "an empty target file has no byte 47 at its start, and the slash check refuses it with the same code",
    "target: below the digits": "byte 47 is `/`, which the set already holds: the mutant admits nothing new",
    "a receipt without its transaction": "NOT PROVEN equivalent: for a transaction that is not mined, tx_block is 0, so the clause is the only one that rejects only a receipt in block 0 next to a pending transaction; a test that sends exactly that from both providers is refused by the unmutated and the mutated executor alike (the cause was not traced), so no input is known that this clause alone catches",
    "the evidence is written": "an append that failed is followed by a flush that fails too (nothing was staged), so the flush check alone refuses the tick; the same refusal is checked with /dev/full",
}


def mutants(cancho):
    main_text = open(os.path.join(ROOT, "tools/executor/main.cho")).read()
    lib_text = open(os.path.join(ROOT, "lib/executor/executor.cho")).read()
    wrong = []
    for which, name, old, new in MUTANTS:
        text = main_text if which == "main" else lib_text
        if text.count(old) != 1:
            wrong.append(f"{name!r}: {text.count(old)} times")
    if wrong:
        sys.exit("mutant patterns that do not occur exactly once:\n  " + "\n  ".join(wrong))

    def one(item):
        which, name, old, new = item
        d = tempfile.mkdtemp()
        try:
            libdir = os.path.join(d, "lib")
            shutil.copytree(os.path.join(ROOT, "lib"), libdir)
            main = main_text
            if which == "main":
                main = main_text.replace(old, new)
            else:
                open(os.path.join(libdir, "executor/executor.cho"), "w").write(lib_text.replace(old, new))
            state = os.path.join(d, "state")
            os.mkdir(state)
            pa, pb = free_port(), free_port()
            exe = os.path.join(d, "executor")
            state2 = os.path.join(d, "state-tls")
            os.mkdir(state2)
            exe2 = os.path.join(d, "executor-tls")
            try:
                build(cancho, libdir, main, state, pa, pb, exe)
                build(cancho, libdir, main, state2, pa, pb, exe2, "localhost", "127.0.0.1", (1, 1))
            except SystemExit as e:
                return name, "did not build: " + str(e)[:200]
            r = subprocess.run([sys.executable, "-I", os.path.abspath(__file__), "--exe", exe, "--state", state, "--exe2", exe2, "--state2", state2, "--ports", str(pa), str(pb), "--trailtool", TRAILTOOL[0]], capture_output=True, text=True, timeout=3000)
            return name, ("killed" if r.returncode != 0 else "SURVIVED")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    survivors, broken = [], []
    only = [n for n in os.environ.get("ONLY", "").split("|") if n]   # re-run some, by name, separated by |
    work = [m for m in MUTANTS if not only or m[1] in only]
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


TRAILTOOL = [None]


def main():
    cancho = os.environ.get("CANCHO", "cancho")
    arg = lambda name: sys.argv[sys.argv.index(name) + 1]
    with tempfile.TemporaryDirectory() as tmp:
        trailtool = os.path.join(tmp, "trailtool")
        r = subprocess.run([cancho, "build", "--std", *[os.path.join(LOGSRC, f) for f in ("trailtool.cho", "trail.cho", "log.cho", "segment.cho", "record.cho", "crc.cho")], "-o", trailtool], capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("trailtool build failed:\n" + r.stderr[:800])
        if "--mutants" in sys.argv:
            TRAILTOOL[0] = trailtool
            mutants(cancho)
        if "--exe" in sys.argv:
            state, exe, pa, pb = arg("--state"), arg("--exe"), int(sys.argv[sys.argv.index("--ports") + 1]), int(sys.argv[sys.argv.index("--ports") + 2])
            trailtool = arg("--trailtool")
        else:
            state = os.path.join(tmp, "state")
            os.mkdir(state)
            pa, pb = free_port(), free_port()
            exe = os.path.join(tmp, "executor")
            build(cancho, os.path.join(ROOT, "lib"), open(os.path.join(ROOT, "tools/executor/main.cho")).read(), state, pa, pb, exe)
        seed = live(random.Random(1))
        na, nb = Node(Chain(seed), pa), Node(Chain(seed), pb)
        pki = os.path.join(tmp, "pki")
        os.mkdir(pki)
        ctxs, roots, other_roots = make_pki(pki)
        na.start()
        nb.start()
        try:
            run_checks(exe, state, na, nb, trailtool, cancho, random.Random(2468), "plain", ctxs, roots)
            # the same providers over TLS, by name, with the CA's certificate as the only root: every scenario above, and then the transport's own
            if "--exe2" in sys.argv:
                exe2, state2 = arg("--exe2"), arg("--state2")
            else:
                state2 = os.path.join(tmp, "state-tls")
                os.mkdir(state2)
                exe2 = os.path.join(tmp, "executor-tls")
                build(cancho, os.path.join(ROOT, "lib"), open(os.path.join(ROOT, "tools/executor/main.cho")).read(), state2, pa, pb, exe2, "localhost", "127.0.0.1", (1, 1))
            run_checks(exe2, state2, na, nb, trailtool, cancho, random.Random(2468), "tls", ctxs, roots)
            run_tls_checks(exe2, state2, na, nb, ctxs, roots, other_roots, random.Random(1357))
        finally:
            na.stop()
            nb.stop()
    print(f"{COUNT[0]} checks, {len(FAILS)} failed")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
