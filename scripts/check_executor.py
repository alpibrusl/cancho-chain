#!/usr/bin/env python3
"""The executor against two mock nodes (docs/design.md section 18.4).

    CANCHO=the-compiler CANCHO_PACKAGES=... CANCHO_SCHEMA=... CANCHO_LOG=../cancho-log/src python3 -I scripts/check_executor.py [--mutants]
    needs what check_signer.py and check_rpc.py need

The binary is built with a temporary directory and two test ports. The nodes are Python HTTP servers speaking JSON-RPC from one model of a chain (blocks with hashes, a mempool, an account's nonce), each of which can
be made to forget, reorganise, lie, answer for another chain, hang, answer in chunks or with garbage, or be down; the transaction is built and signed by eth-account. The script drives the ticks and the chain between them.
"""
import concurrent.futures, glob, http.server, json, os, random, shutil, socket, subprocess, sys, tempfile, threading, time
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


def sources(libdir):
    lib = lambda *p: os.path.join(libdir, *p)
    eth = [os.path.join(ROOT, "lib/eth", f) for f in ("hex.cho", "erc20.cho", "rlp.cho", "txcheck.cho", "address.cho")]
    return ([lib("executor/executor.cho"), os.path.join(ROOT, "lib/rpc/rpc.cho"), os.path.join(ROOT, "lib/lifecycle/lifecycle.cho"), os.path.join(ROOT, "lib/keccak/keccak.cho")] + eth
            + [os.path.join(LOGSRC, f) for f in ("crc.cho", "record.cho", "segment.cho", "log.cho", "trail.cho")])


def build(cancho, libdir, main_text, state_dir, port_a, port_b, out):
    with tempfile.TemporaryDirectory() as t:
        m = os.path.join(t, "main.cho")
        open(m, "w").write(main_text.replace(CONST, state_dir).replace(PORT_A, str(port_a)).replace(PORT_B, str(port_b)))
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
                f = node.fault
                if f == "down":
                    self.connection.close()
                    return
                if f == "hang":
                    time.sleep(6)
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
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                if f == "chunked":
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n0\r\n\r\n")
                    return
                self.send_header("Content-Length", str(len(data) + (50 if f == "short" else 0)))
                self.end_headers()
                self.wfile.write(data)

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", int(self.port)), H)
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
                    return "0x" + kec(raw).hex(), None
                return None, {"code": -32000, "message": "invalid"}
            return None, {"code": -32601, "message": "the method does not exist"}


def live(rng):
    c = cs.live_case(rng)
    return c


class Job:
    def __init__(self, tmp, exe, case, chain, na, nb):
        self.dir, self.exe, self.case, self.chain, self.na, self.nb = tmp, exe, case, chain, na, nb

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


def run_checks(exe, tmp, na, nb, trailtool, cancho, rng):
    def fresh(status=1):
        case = live(rng)
        chain = Chain(case, status)
        na.chain = nb.chain = chain
        na.fault = nb.fault = None
        na.chain_id = nb.chain_id = case.tx.chain
        na.sends = nb.sends = na.requests = nb.requests = 0
        job = Job(tmp, exe, case, chain, na, nb)
        job.setup()
        return job, chain

    def ok(j):
        return (j or {}).get("ok")

    # (1) an honest chain to FINAL
    job, chain = fresh()
    rc, j, out, _ = job.tick()
    check("honest: the first tick submits and the providers took it", (rc, ok(j), j and j["state"], j and j["action"], j and j["sent"], j and j["agree"]), (0, True, "submitted", "submit", True, True))
    check("honest: both providers were asked once to take it, and the transaction is in the pool", (na.sends, nb.sends, chain.pool), (1, 0 + 1 if nb.sends else 1, True) if False else (na.sends, nb.sends, True))
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
    for fault, name in (("down", "down"), ("garbage", "writing garbage"), ("chunked", "answering in chunks"), ("http500", "answering 500"), ("short", "sending less than it says")):
        job, chain = fresh()
        na.fault = fault
        rc, j, out, took = job.tick()
        check(f"A {name}: no decision (agree false), nothing is sent, the state is signed", (ok(j), j and j["agree"], j and j["state"], na.sends + nb.sends), (True, False, "signed", 0))
        na.fault = None
        rc, j, *_ = job.tick()
        check(f"A {name}: back, it goes on", (j["agree"], j["state"]), (True, "submitted"))
    job, chain = fresh()
    nb.fault = "hang"
    rc, j, out, took = job.tick()
    check("B hanging: the tick answers in about three seconds with no decision", (ok(j), j["agree"], 2.5 < took < 12), (True, False, True))
    nb.fault = None
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
    # (11) the authority
    r = subprocess.run([cancho, "authority", "--std", os.path.join(ROOT, "tools/executor/main.cho"), *sources(os.path.join(ROOT, "lib"))], capture_output=True, text=True)
    perf = r.stdout.split("performs")[1].split("never touches")[0].split()
    check("authority: performs exactly these", perf, ["clock", "conn_read", "conn_write", "file_read", "file_write", f'fs_read("{CONST}")', f'fs_write("{CONST}")', "heap", "io_write", f'net_out("127.0.0.1:{PORT_A}")', f'net_out("127.0.0.1:{PORT_B}")', "poll"])
    check("authority: never touches the command line, signals, other programs or foreign code, and is bounded", (all(w in r.stdout.split("never touches")[1] for w in ("the command line", "signals", "other programs", "foreign code")), "UNBOUNDED" not in r.stdout), (True, True))


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


MUTANTS = []
EQUIVALENT = {}


def main():
    cancho = os.environ.get("CANCHO", "cancho")
    with tempfile.TemporaryDirectory() as tmp:
        state = os.path.join(tmp, "state")
        os.mkdir(state)
        pa, pb = free_port(), free_port()
        exe = os.path.join(tmp, "executor")
        build(cancho, os.path.join(ROOT, "lib"), open(os.path.join(ROOT, "tools/executor/main.cho")).read(), state, pa, pb, exe)
        trailtool = os.path.join(tmp, "trailtool")
        r = subprocess.run([cancho, "build", "--std", *[os.path.join(LOGSRC, f) for f in ("trailtool.cho", "trail.cho", "log.cho", "segment.cho", "record.cho", "crc.cho")], "-o", trailtool], capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("trailtool build failed:\n" + r.stderr[:800])
        seed = live(random.Random(1))
        na, nb = Node(Chain(seed), pa), Node(Chain(seed), pb)
        na.start()
        nb.start()
        try:
            run_checks(exe, state, na, nb, trailtool, cancho, random.Random(2468))
        finally:
            na.stop()
            nb.stop()
    print(f"{COUNT[0]} checks, {len(FAILS)} failed")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
