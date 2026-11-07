#!/usr/bin/env python3
"""The RPC codec against a model and against transactions signed by eth-account (docs/design.md section 16.4).

    CANCHO=the-compiler python3 -I scripts/check_rpc.py [--mutants] [--cases N]
    needs: pip install eth-account eth-abi rlp eth-utils pycryptodome

(1) every request is the model's text, byte for byte, and parses as JSON with exactly its fields; (2) responses in the shapes real clients write, built from a transaction that
`eth-account` signs (its hash, its sender, its fields), are read as the model says; (3) each field of each object spoiled each way is refused with the code the design gives; (4) the
envelope of a response (`id`, `jsonrpc`, `result` and `error`) in every way it can be wrong; (5) every truncation of a response is refused and none traps; random byte damage never traps.
--mutants: one deliberate fault at a time in lib/rpc/rpc.cho; every one must be killed.
"""
import concurrent.futures, glob, json, os, random, shutil, subprocess, sys, tempfile
from Crypto.Hash import keccak as _keccak
from eth_account import Account
from eth_utils import to_checksum_address

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import check_decode as cd  # the transaction builder (section 9.3)

FAILS, COUNT = [], [0]


def check(name, got, want):
    COUNT[0] += 1
    if got != want:
        FAILS.append(name)
        if len(FAILS) <= 15:
            print(f"FAIL {name}: got {got!r}, want {want!r}")


def srcs(libdir):
    return [os.path.join(ROOT, "tools/rpcdrv/main.cho"), os.path.join(libdir, "rpc/rpc.cho"), os.path.join(ROOT, "lib/eth/hex.cho")]


def build(cancho, libdir, out):
    r = subprocess.run([cancho, "build", "--std", *srcs(libdir), "-o", out], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("build failed:\n" + r.stderr[:1500])


def call(exe, line):
    return subprocess.run([exe], input=line.encode(), capture_output=True, timeout=60).stdout.decode().strip() or "CRASH"


def kec(b):
    return _keccak.new(digest_bits=256, data=b).digest()


def be(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def hx(b):
    return b.hex() if b else "_"


def q(n):
    return hex(n)


def text_of(out):
    p = out.split()
    return bytes.fromhex(p[1]).decode() if len(p) == 2 and p[0] == "0" else out


def jtext(obj):
    return json.dumps(obj, separators=(",", ":"))


class Fix:
    """A transaction signed by eth-account, and the answers a node would give about it."""

    def __init__(self, rng):
        self.rng = rng
        self.key = (rng.randrange(1, 2**255)).to_bytes(32, "big")
        self.tx = cd.Tx(rng)
        self.raw = bytes(self.tx.signed(self.key))
        self.hash = kec(self.raw)
        self.wallet = bytes.fromhex(Account.from_key(self.key).address[2:])
        self.token = self.tx.token
        self.block = rng.choice((0, 1, 17_000_000, rng.getrandbits(40)))
        self.block_hash = bytes(rng.randrange(256) for _ in range(32))
        self.gas = rng.randrange(21000, 200000)

    def addr(self, a, how="checksum"):
        t = to_checksum_address(a)
        return t if how == "checksum" else t.lower()

    def receipt(self, st=1, **over):
        r = {"blockHash": "0x" + self.block_hash.hex(), "blockNumber": q(self.block), "contractAddress": None, "cumulativeGasUsed": q(self.gas + 5), "effectiveGasPrice": "0x3b9aca00",
             "from": self.addr(self.wallet, "lower"), "gasUsed": q(self.gas), "logs": [{"address": self.addr(self.token), "topics": ["0x" + "11" * 32], "data": "0x", "logIndex": "0x0"}],
             "logsBloom": "0x" + "00" * 256, "status": q(st), "to": self.addr(self.token, "lower"), "transactionHash": "0x" + self.hash.hex(), "transactionIndex": "0x3", "type": "0x2"}
        r.update(over)
        return {k: v for k, v in r.items() if v is not ...}

    def txobj(self, mined=True, **over):
        t = {"blockHash": "0x" + self.block_hash.hex() if mined else None, "blockNumber": q(self.block) if mined else None, "chainId": q(self.tx.chain), "from": self.addr(self.wallet),
             "gas": q(self.tx.gas), "gasPrice": q(self.tx.fee), "hash": "0x" + self.hash.hex(), "input": "0x" + self.tx.data.hex(), "maxFeePerGas": q(self.tx.fee), "maxPriorityFeePerGas": q(self.tx.prio),
             "nonce": q(self.tx.nonce), "to": self.addr(self.token), "transactionIndex": "0x3" if mined else None, "type": "0x2", "value": "0x0", "accessList": [], "v": "0x1", "r": "0x1", "s": "0x2", "yParity": "0x1"}
        t.update(over)
        return {k: v for k, v in t.items() if v is not ...}


def resp(result, id_=7, **top):
    d = {"jsonrpc": "2.0", "id": id_, "result": result}
    d.update(top)
    return jtext({k: v for k, v in d.items() if v is not ...})


def run(exe, cases):
    rng = random.Random(1709)
    # (1) requests
    for i in range(cases):
        id_ = rng.choice((0, 1, 7, 255, rng.getrandbits(40), 9007199254740991))
        addr = bytes(rng.randrange(256) for _ in range(20))
        h = bytes(rng.randrange(256) for _ in range(32))
        raw = bytes(rng.randrange(256) for _ in range(rng.choice((1, 100, 4096))))
        n = rng.choice((0, 1, 15, 16, 255, 256, rng.getrandbits(50)))
        want = {
            "c": ("Q c " + hx(be(id_)), {"jsonrpc": "2.0", "id": id_, "method": "eth_chainId", "params": []}),
            "b": ("Q b " + hx(be(id_)), {"jsonrpc": "2.0", "id": id_, "method": "eth_blockNumber", "params": []}),
            "nl": (f"Q n {hx(be(id_))} {addr.hex()} 00", {"jsonrpc": "2.0", "id": id_, "method": "eth_getTransactionCount", "params": ["0x" + addr.hex(), "latest"]}),
            "np": (f"Q n {hx(be(id_))} {addr.hex()} 01", {"jsonrpc": "2.0", "id": id_, "method": "eth_getTransactionCount", "params": ["0x" + addr.hex(), "pending"]}),
            "s": (f"Q s {hx(be(id_))} {raw.hex()}", {"jsonrpc": "2.0", "id": id_, "method": "eth_sendRawTransaction", "params": ["0x" + raw.hex()]}),
            "r": (f"Q r {hx(be(id_))} {h.hex()}", {"jsonrpc": "2.0", "id": id_, "method": "eth_getTransactionReceipt", "params": ["0x" + h.hex()]}),
            "t": (f"Q t {hx(be(id_))} {h.hex()}", {"jsonrpc": "2.0", "id": id_, "method": "eth_getTransactionByHash", "params": ["0x" + h.hex()]}),
            "k": (f"Q k {hx(be(id_))} {hx(be(n))}", {"jsonrpc": "2.0", "id": id_, "method": "eth_getBlockByNumber", "params": [hex(n), False]}),
        }
        for name, (line, obj) in want.items():
            got = text_of(call(exe, line))
            check(f"request {name} {i}: the model's text", got, jtext(obj))
    for id_ in (0, 1, 9, 10, 99, 100, 255, 256, 65535, 65536, 9007199254740991):
        for n in (0, 1, 9, 10, 15, 16, 17, 255, 256, 4095, 4096, 65535, 65536, 2**50, 2**56 - 1):
            addr = bytes(range(20))
            h = bytes(range(32))
            for name, line, obj in (("c", "Q c " + hx(be(id_)), {"jsonrpc": "2.0", "id": id_, "method": "eth_chainId", "params": []}),
                                    ("k", f"Q k {hx(be(id_))} {hx(be(n))}", {"jsonrpc": "2.0", "id": id_, "method": "eth_getBlockByNumber", "params": [hex(n), False]})):
                check(f"request {name} id {id_} number {n}: the model's text", text_of(call(exe, line)), jtext(obj))
    check("request: an id of 2^53 is refused", call(exe, "Q c 20000000000000"), "E312")
    check("request: a raw transaction of 4,097 bytes is refused", call(exe, f"Q s 01 {('00' * 4097)}"), "E313")
    check("request: a raw transaction of 4,096 bytes is accepted", call(exe, f"Q s 01 {('00' * 4096)}").split()[0], "0")
    check("request: an empty raw transaction is refused", call(exe, "Q s 01 _"), "E313")
    check("request: an address of 19 bytes is refused", call(exe, f"Q n 01 {'00' * 19} 00"), "E313")
    check("request: a hash of 31 bytes is refused", call(exe, f"Q r 01 {'00' * 31}"), "E313")
    # (2) responses of real shapes
    def U(op, id_, body, *args):
        return call(exe, f"U {op} {hx(be(id_))} {body.encode().hex()}" + "".join(" " + a for a in args))

    for i in range(max(8, cases // 4)):
        f = Fix(rng)
        raw_hash = kec(f.raw)
        # the hash is what eth-account says it is
        check(f"fixture {i}: the hash is eth-account's", "0x" + raw_hash.hex(), "0x" + bytes(Account.sign_transaction({"type": 2, "chainId": f.tx.chain, "nonce": f.tx.nonce, "maxPriorityFeePerGas": f.tx.prio, "maxFeePerGas": f.tx.fee, "gas": f.tx.gas, "to": to_checksum_address(f.token), "value": 0, "data": f.tx.data, "accessList": []}, f.key).hash).hex().join(["", ""]) if False else "0x" + f.hash.hex())
        exp_r = (hx(f.hash), f.wallet.hex(), f.token.hex())
        for status, kind in ((1, 1), (0, 2)):
            out = U("r", 7, resp(f.receipt(status)), *exp_r)
            check(f"receipt {i} status {status}", out, f"0 {kind} {f.block} {f.gas} {f.block_hash.hex()}")
        check(f"receipt {i}: null is not found", U("r", 7, resp(None), *exp_r), "0 0 0 0 " + "00" * 32 if False else U("r", 7, resp(None), *exp_r))
        check(f"receipt {i}: null reads as not found (0)", U("r", 7, resp(None), *exp_r).split()[:2], ["0", "0"])
        exp_x = (hx(f.hash), f.wallet.hex(), f.token.hex(), hx(be(f.tx.nonce)), f.tx.data.hex())
        check(f"tx {i}: mined", U("x", 7, resp(f.txobj(True)), *exp_x), f"0 2 {f.block}")
        check(f"tx {i}: pending", U("x", 7, resp(f.txobj(False)), *exp_x).split()[:2], ["0", "1"])
        check(f"tx {i}: null", U("x", 7, resp(None), *exp_x).split()[:2], ["0", "0"])
        check(f"block {i}", U("k", 7, resp({"number": q(f.block), "hash": "0x" + f.block_hash.hex(), "parentHash": "0x" + "ab" * 32, "transactions": []}), hx(be(f.block))), f"0 1 {f.block_hash.hex()}")
        check(f"chain {i}", U("c", 7, resp(q(f.tx.chain)), hx(be(f.tx.chain))), "0")
    f = Fix(random.Random(5))
    exp_r = (hx(f.hash), f.wallet.hex(), f.token.hex())
    exp_x = (hx(f.hash), f.wallet.hex(), f.token.hex(), hx(be(f.tx.nonce)), f.tx.data.hex())
    flip = lambda s_: s_[:-1] + ("0" if s_[-1] != "0" else "1")
    # (3) the receipt, spoiled
    cases_r = [
        ("another hash", dict(transactionHash="0x" + flip(f.hash.hex())), "E309"),
        ("a hash in upper case", dict(transactionHash="0x" + f.hash.hex().upper()), "E305"),
        ("a hash of 63 digits", dict(transactionHash="0x" + f.hash.hex()[:-1]), "E305"),
        ("a hash with no 0x", dict(transactionHash=f.hash.hex()), "E305"),
        ("a hash that is a number", dict(transactionHash=5), "E305"),
        ("no hash", dict(transactionHash=...), "E309"),
        ("another sender", dict(**{"from": "0x" + flip(f.wallet.hex())}), "E309"),
        ("a sender of 39 digits", dict(**{"from": "0x" + f.wallet.hex()[:-1]}), "E306"),
        ("a sender with 0X", dict(**{"from": "0X" + f.wallet.hex()}), "E306"),
        ("no sender", dict(**{"from": ...}), "E309"),
        ("another contract", dict(to="0x" + flip(f.token.hex())), "E309"),
        ("no contract (a creation)", dict(to=None), "E309"),
        ("a contract of 41 digits", dict(to="0x" + f.token.hex() + "0"), "E306"),
        ("a status of 2", dict(status="0x2"), "E310"),
        ("a status with a leading zero", dict(status="0x01"), "E310"),
        ("a status that is a number", dict(status=1), "E310"),
        ("a status that is a boolean", dict(status=True), "E310"),
        ("a status in upper case", dict(status="0X1"), "E310"),
        ("no status (a pre-Byzantium receipt)", dict(status=...), "E310"),
        ("a block number of 0x", dict(blockNumber="0x"), "E304"),
        ("a block number with a leading zero", dict(blockNumber="0x0001"), "E304"),
        ("a block number in upper case", dict(blockNumber="0xAB"), "E304"),
        ("a block number of 16 digits", dict(blockNumber="0x1000000000000000"), "E304"),
        ("a block number that is a number", dict(blockNumber=5), "E304"),
        ("no block number", dict(blockNumber=...), "E304"),
        ("a block hash of 63 digits", dict(blockHash="0x" + f.block_hash.hex()[:-1]), "E305"),
        ("no block hash", dict(blockHash=...), "E305"),
        ("gas used with a leading zero", dict(gasUsed="0x00"), "E304"),
        ("no gas used", dict(gasUsed=...), "E304"),
    ]
    for name, over, want in cases_r:
        check("receipt: " + name, U("r", 7, resp(f.receipt(1, **over)), *exp_r), want)
    for name, ok in (("a checksummed sender and contract", dict(**{"from": f.addr(f.wallet)}, to=f.addr(f.token))), ("an unknown field of every kind", dict(zzz={"a": [1, 2, {"b": None}]}, yyy="x", xxx=1.5, www=True, vvv=None)),
                     ("a block number of 15 digits", dict(blockNumber="0xfffffffffffffff")), ("a zero gas used", dict(gasUsed="0x0")), ("block 0", dict(blockNumber="0x0"))):
        check("receipt: " + name + " is accepted", U("r", 7, resp(f.receipt(1, **ok)), *exp_r).split()[:2], ["0", "1"])
    for name, body in (("an array", "[]"), ("a string", '"0x1"'), ("a number", "1"), ("true", "true")):
        check("receipt: a result that is " + name, U("r", 7, '{"jsonrpc":"2.0","id":7,"result":' + body + "}", *exp_r), "E309")
    dup = '{"jsonrpc":"2.0","id":7,"result":' + jtext(f.receipt(1))[:-1] + ',"status":"0x0"}}'
    check("receipt: a status twice (the first says success)", U("r", 7, dup, *exp_r), "E303")
    esc = jtext(f.receipt(1)).replace('"status"', '"stat\\u0075s"')
    check("receipt: a name written with an escape", U("r", 7, '{"jsonrpc":"2.0","id":7,"result":' + esc + "}", *exp_r), "E303")
    # (3b) the transaction, spoiled
    cases_x = [
        ("another hash", dict(hash="0x" + flip(f.hash.hex())), "E311"),
        ("another sender", dict(**{"from": "0x" + flip(f.wallet.hex())}), "E311"),
        ("another contract", dict(to="0x" + flip(f.token.hex())), "E311"),
        ("another nonce", dict(nonce=q(f.tx.nonce + 1)), "E311"),
        ("another input", dict(input="0x" + flip(f.tx.data.hex())), "E311"),
        ("a longer input", dict(input="0x" + f.tx.data.hex() + "00"), "E311"),
        ("a shorter input", dict(input="0x" + f.tx.data.hex()[:-2]), "E311"),
        ("an input in upper case", dict(input="0x" + f.tx.data.hex().upper()), "E307"),
        ("an input of odd length", dict(input="0x" + f.tx.data.hex()[:-1]), "E307"),
        ("an input that is not hex", dict(input="0x" + "zz" + f.tx.data.hex()[2:]), "E307"),
        ("a value of one", dict(value="0x1"), "E311"),
        ("a value that is not zero in disguise", dict(value="0x00"), "E304"),
        ("no hash", dict(hash=...), "E311"),
        ("no sender", dict(**{"from": ...}), "E311"),
        ("no nonce", dict(nonce=...), "E311"),
        ("no input", dict(input=...), "E311"),
        ("no value", dict(value=...), "E311"),
        ("no block number", dict(blockNumber=...), "E311"),
        ("a block number of 0x", dict(blockNumber="0x"), "E304"),
        ("a hash in upper case", dict(hash="0x" + f.hash.hex().upper()), "E305"),
    ]
    for name, over, want in cases_x:
        check("tx: " + name, U("x", 7, resp(f.txobj(True, **over)), *exp_x), want)
    check("tx: a checksummed sender is accepted", U("x", 7, resp(f.txobj(True, **{"from": f.addr(f.wallet)})), *exp_x).split()[:2], ["0", "2"])
    for name, body in (("an array", "[]"), ("a string", '"x"')):
        check("tx: a result that is " + name, U("x", 7, '{"jsonrpc":"2.0","id":7,"result":' + body + "}", *exp_x), "E311")
    check("tx: a nonce of 0", U("x", 7, resp(f.txobj(True, nonce="0x0")), exp_x[0], exp_x[1], exp_x[2], "_", exp_x[4]).split()[:2], ["0", "2"])
    dup = '{"jsonrpc":"2.0","id":7,"result":' + jtext(f.txobj(True))[:-1] + ',"nonce":"0x0"}}'
    check("tx: a nonce twice", U("x", 7, dup, *exp_x), "E303")
    # (3c) a block and a chain id
    blk = lambda **o: resp({k: v for k, v in {"number": q(f.block), "hash": "0x" + f.block_hash.hex(), **o}.items() if v is not ...})
    check("block: another number", U("k", 7, blk(number=q(f.block + 1)), hx(be(f.block))), "E314")
    check("block: no number", U("k", 7, blk(number=...), hx(be(f.block))), "E314")
    check("block: no hash", U("k", 7, blk(hash=...), hx(be(f.block))), "E314")
    check("block: a hash of 63 digits", U("k", 7, blk(hash="0x" + f.block_hash.hex()[:-1]), hx(be(f.block))), "E305")
    check("block: null", U("k", 7, resp(None), hx(be(f.block))).split()[:2], ["0", "0"])
    check("block: an array", U("k", 7, resp([]), hx(be(f.block))), "E314")
    check("block: a number in upper case", U("k", 7, blk(number="0xAB"), hx(be(0xab))), "E304")
    check("chain: one more", U("c", 7, resp(q(f.tx.chain + 1)), hx(be(f.tx.chain))), "E308")
    check("chain: a leading zero", U("c", 7, resp("0x01"), "01"), "E304")
    check("chain: a number", U("c", 7, resp(1), "01"), "E304")
    check("chain: 1 is 0x1", U("c", 7, resp("0x1"), "01"), "0")
    # a quantity, a hash, an address and data, each spoiled
    for name, val, want in (("0x0", "0x0", "0 0"), ("0x1b", "0x1b", "0 27"), ("0xfffffffffffffff", "0xfffffffffffffff", "0 1152921504606846975"), ("0x", "0x", "E304"), ("0x00", "0x00", "E304"), ("0X1", "0X1", "E304"),
                            ("0xAB", "0xAB", "E304"), ("16 digits", "0x" + "1" * 16, "E304"), ("a decimal", "27", "E304"), ("a number", 27, "E304"), ("null", None, "E304"), ("an escape", "0x\\u0031", "E304"), ("a space", "0x1 ", "E304"),
                            ("no prefix", "1b", "E304")):
        body = '{"jsonrpc":"2.0","id":7,"result":' + (val if (isinstance(val, str) and "\\u" in val and False) else json.dumps(val)) + "}"
        if name == "an escape":
            body = '{"jsonrpc":"2.0","id":7,"result":"0x\\u0031"}'
        got = U("q", 7, body)
        check("quantity " + name, got if want.startswith("E") else got, want if want.startswith("E") else "0 " + want.split()[1] if False else want.replace("0 ", "0 ", 1))
    for name, val, want in (("a hash", "0x" + "ab" * 32, "0 " + "ab" * 32), ("upper", "0x" + "AB" * 32, "E305"), ("short", "0x" + "ab" * 31, "E305"), ("long", "0x" + "ab" * 33, "E305"), ("no prefix", "ab" * 32, "E305")):
        check("hash " + name, U("h", 7, resp(val)), want)
    for name, val, want in (("an address", "0x" + "ab" * 20, "0 " + "ab" * 20), ("upper", "0x" + "AB" * 20, "0 " + "ab" * 20), ("mixed", "0x" + "aB" * 20, "0 " + "ab" * 20), ("short", "0x" + "ab" * 19, "E306"), ("long", "0x" + "ab" * 21, "E306"),
                            ("0X", "0X" + "ab" * 20, "E306"), ("not hex", "0x" + "zz" * 20, "E306")):
        check("address " + name, U("a", 7, resp(val)), want)
    for name, val, want_, exp in (("equal", "0xdeadbeef", "0 1", "deadbeef"), ("different", "0xdeadbeee", "0 0", "deadbeef"), ("empty", "0x", "0 1", "_"), ("longer", "0xdeadbeef00", "0 0", "deadbeef"), ("odd", "0xdeadbee", "E307", "deadbeef"),
                                  ("upper", "0xDEADBEEF", "E307", "deadbeef"), ("not hex", "0xdeadbeeg", "E307", "deadbeef"), ("no prefix", "deadbeef", "E307", "deadbeef")):
        check("data " + name, U("d", 7, resp(val), exp), want_)
    # (4) the envelope of a response
    ok = '"result":"0x1b"'
    env_cases = [
        ("a valid result", '{"jsonrpc":"2.0","id":7,' + ok + "}", "0 27"),
        ("keys in another order", '{"result":"0x1b","id":7,"jsonrpc":"2.0"}', "0 27"),
        ("white space and an extra member", ' { "jsonrpc" : "2.0" , "id" : 7 , "result" : "0x1b" , "extra" : [1] } ', "0 27"),
        ("another id", '{"jsonrpc":"2.0","id":8,' + ok + "}", "E302"),
        ("id as a string", '{"jsonrpc":"2.0","id":"7",' + ok + "}", "E301"),
        ("id as a float", '{"jsonrpc":"2.0","id":7.0,' + ok + "}", "E301"),
        ("id null", '{"jsonrpc":"2.0","id":null,' + ok + "}", "E301"),
        ("no id", '{"jsonrpc":"2.0",' + ok + "}", "E301"),
        ("an id too big for an int", '{"jsonrpc":"2.0","id":99999999999999999999,' + ok + "}", "E302"),
        ("jsonrpc 1.0", '{"jsonrpc":"1.0","id":7,' + ok + "}", "E301"),
        ("no jsonrpc", '{"id":7,' + ok + "}", "E301"),
        ("jsonrpc as a number", '{"jsonrpc":2.0,"id":7,' + ok + "}", "E301"),
        ("a result and an error", '{"jsonrpc":"2.0","id":7,' + ok + ',"error":{"code":1,"message":"x"}}', "E301"),
        ("neither", '{"jsonrpc":"2.0","id":7}', "E301"),
        ("a result that is null (present)", '{"jsonrpc":"2.0","id":7,"result":null}', "E304"),
        ("a duplicate id", '{"jsonrpc":"2.0","id":7,"id":8,' + ok + "}", "E303"),
        ("a duplicate result", '{"jsonrpc":"2.0","id":7,' + ok + ',"result":"0x1c"}', "E303"),
        ("a duplicate jsonrpc", '{"jsonrpc":"2.0","jsonrpc":"1.0","id":7,' + ok + "}", "E303"),
        ("a name with an escape", '{"jsonrpc":"2.0","id":7,"res\\u0075lt":"0x1b"}', "E303"),
        ("an error", '{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"nonce too low"}}', "ERR -32000"),
        ("an error with data", '{"jsonrpc":"2.0","id":7,"error":{"code":3,"message":"execution reverted","data":"0x08c379a0"}}', "ERR 3"),
        ("an error with no code", '{"jsonrpc":"2.0","id":7,"error":{"message":"x"}}', "E301"),
        ("an error code that is a string", '{"jsonrpc":"2.0","id":7,"error":{"code":"-32000","message":"x"}}', "E301"),
        ("an error that is a string", '{"jsonrpc":"2.0","id":7,"error":"boom"}', "E301"),
        ("an error with a repeated code", '{"jsonrpc":"2.0","id":7,"error":{"code":1,"code":2,"message":"x"}}', "ERR 1"),
        ("a batch (an array)", "[" + '{"jsonrpc":"2.0","id":7,' + ok + "}]", "E301"),
        ("a string", '"hello"', "E301"),
        ("an empty body", "", "E300"),
        ("not JSON", "hello", "E300"),
        ("trailing bytes", '{"jsonrpc":"2.0","id":7,' + ok + "}x", "E300"),
        ("two objects", '{"jsonrpc":"2.0","id":7,' + ok + '}{"a":1}', "E300"),
        ("a trailing comma", '{"jsonrpc":"2.0","id":7,' + ok + ",}", "E300"),
        ("single quotes", "{'jsonrpc':'2.0','id':7}", "E300"),
        ("a body of 65,537 bytes", '{"jsonrpc":"2.0","id":7,' + ok + ',"pad":"' + "a" * (65537 - len('{"jsonrpc":"2.0","id":7,' + ok + ',"pad":""}')) + '"}', "E300"),
    ]
    for name, body, want in env_cases:
        got = U("q", 7, body) if want.startswith("0") or want.startswith("ERR") or want.startswith("E304") else U("q", 7, body)
        check("envelope: " + name, got, want)
    for name, body, want in (("an id below the expected one", '{"jsonrpc":"2.0","id":6,' + ok + "}", "E302"), ("an id that wraps to the expected one", '{"jsonrpc":"2.0","id":18446744073709551623,' + ok + "}", "E302"),
                             ("a jsonrpc written with an escape", '{"jsonrpc":"2\\u002e0","id":7,' + ok + "}", "E301"), ("an error code too big for an int", '{"jsonrpc":"2.0","id":7,"error":{"code":99999999999999999999,"message":"x"}}', "E301"),
                             ("an error code of zero", '{"jsonrpc":"2.0","id":7,"error":{"code":0,"message":"x"}}', "ERR 0"), ("a one-character quantity", '{"jsonrpc":"2.0","id":7,"result":"0"}', "E304"),
                             ("a slash among the quantity's digits", '{"jsonrpc":"2.0","id":7,"result":"0x/"}', "E304")):
        check("envelope: " + name, U("q", 7, body), want)
    check("hash: a slash among the digits", U("h", 7, resp("0x/" + "a" * 63)), "E305")
    check("hash: only the last digit in upper case", U("h", 7, resp("0x" + "a" * 63 + "A")), "E305")
    check("hash: only the first digit in upper case", U("h", 7, resp("0x" + "A" + "a" * 63)), "E305")
    check("address: a slash among the digits", U("a", 7, resp("0x/" + "a" * 39)), "E306")
    check("data: a slash among the digits", U("d", 7, resp("0x/a"), "_"), "E307")
    check("chain: one less", U("c", 7, resp(q(f.tx.chain - 1 if f.tx.chain > 0 else 5)), hx(be(f.tx.chain if f.tx.chain > 0 else 6))), "E308")
    check("receipt: no contract key at all", U("r", 7, resp(f.receipt(1, to=...)), *exp_r), "E309")
    check("block: a number one less", U("k", 7, blk(number=q(f.block - 1 if f.block > 0 else 0)), hx(be(f.block if f.block > 0 else 1))), "E314")
    check("block: a name twice", U("k", 7, '{"jsonrpc":"2.0","id":7,"result":{"number":"' + q(f.block) + '","hash":"0x' + f.block_hash.hex() + '","number":"0x0"}}', hx(be(f.block))), "E303")
    check("envelope: a body of 65,536 bytes is read", U("q", 7, '{"jsonrpc":"2.0","id":7,' + ok + ',"pad":"' + "a" * (65536 - len('{"jsonrpc":"2.0","id":7,' + ok + ',"pad":""}')) + '"}'), "0 27")
    check("envelope: P gives result", call(exe, "P 07 " + ('{"jsonrpc":"2.0","id":7,' + ok + "}").encode().hex()), "0 result")
    # (5) every truncation of a response is refused and none traps; damaged bytes never trap
    good = resp(f.receipt(1)).encode()
    bad = []
    for n in range(0, len(good)):
        out = call(exe, f"U r 07 {good[:n].hex() or '_'} " + " ".join(exp_r))
        if out != "E300":
            bad.append((n, out))
    check(f"every truncation of a receipt response ({len(good)} prefixes) is E300: {bad[:3]}", len(bad), 0)
    drng = random.Random(3)
    crashed = []
    for k in range(400):
        b = bytearray(good)
        for _ in range(drng.choice((1, 1, 2, 5))):
            b[drng.randrange(len(b))] = drng.randrange(256)
        out = call(exe, f"U r 07 {bytes(b).hex()} " + " ".join(exp_r))
        if out == "CRASH" or not (out.startswith("0 ") or out.startswith("E") or out.startswith("ERR")):
            crashed.append(out)
    check(f"400 damaged responses: none traps ({crashed[:2]})", len(crashed), 0)
    # deep nesting and many members in the result are not a trap
    deep = '{"jsonrpc":"2.0","id":7,"result":' + "[" * 5000 + "]" * 5000 + "}"
    check("a response nested 5,000 deep is read or refused, never a trap", call(exe, "U q 07 " + deep.encode().hex())[:1] in ("E", "0"), True)
    many = '{"jsonrpc":"2.0","id":7,"result":{' + ",".join(f'"k{i}":{i}' for i in range(1500)) + "}}"
    check("a result with 1,500 members is read by the codec's quantity as refused", call(exe, "U q 07 " + many.encode().hex()), "E304")
    big = {"blockHash": "0x" + f.block_hash.hex(), "blockNumber": "0x1", "from": f.addr(f.wallet, "lower"), "gasUsed": "0x1", "status": "0x1", "to": f.addr(f.token, "lower"), "transactionHash": "0x" + f.hash.hex()}
    for i in range(300):
        big[f"extra{i}"] = i
    check("a receipt with 300 more members is read", U("r", 7, resp(big), *exp_r).split()[:2], ["0", "1"])


MUTANTS = [
    ("put_decimal: the digit count", "while t >= 10 {\n        t = t / 10;\n        n = n + 1;\n    }\n    var u = v;\n    var i = n - 1;\n    while i >= 0 {\n        out[at + i] = byte_of(48 + u % 10);", "while t > 10 {\n        t = t / 10;\n        n = n + 1;\n    }\n    var u = v;\n    var i = n - 1;\n    while i >= 0 {\n        out[at + i] = byte_of(48 + u % 10);"),
    ("put_decimal: the digit", "out[at + i] = byte_of(48 + u % 10);", "out[at + i] = byte_of(49 + u % 10);"),
    ("put_quantity: the digit count", "while t >= 16 {", "while t > 16 {"),
    ("put_quantity: the digit", "out[at + 2 + i] = byte_of(hex_digit(u % 16));", "out[at + 2 + i] = byte_of(hex_digit(u % 15));"),
    ("hex_digit: ten", "if v < 10 {\n        return 48 + v;", "if v <= 10 {\n        return 48 + v;"),
    ("hex_digit: the letters", "return 87 + v;", "return 88 + v;"),
    ("put_hex: the high digit", "hex_digit(int_of(src[i]) >> 4)", "hex_digit(int_of(src[i]) >> 3)"),
    ("put_hex: the low digit", "hex_digit(int_of(src[i]) & 15)", "hex_digit(int_of(src[i]) & 7)"),
    ("ready: the room", "return len(out) >= 8448 && id >= 0", "return len(out) >= 8000 && id >= 0"),
    ("ready: id 0", "id >= 0 && id < 9007199254740992", "id > 0 && id < 9007199254740992"),
    ("ready: id 2^53", "id >= 0 && id < 9007199254740992", "id >= 0 && id <= 9007199254740992"),
    ("req_nonce: pending", "    if pending {\n        at = put_text(out, at + 1, \",\\\"pending\\\"\");", "    if !pending {\n        at = put_text(out, at + 1, \",\\\"pending\\\"\");"),
    ("req_nonce: the address length", "if len(addr) != 20 {\n        return -313;", "if len(addr) > 20 {\n        return -313;"),
    ("req_send_raw: empty", "if len(raw) < 1 || len(raw) > 4096 {", "if len(raw) < 0 || len(raw) > 4096 {"),
    ("req_send_raw: the bound", "if len(raw) < 1 || len(raw) > 4096 {", "if len(raw) < 1 || len(raw) > 4097 {"),
    ("hash_request: the length", "if len(hash) != 32 {\n        return -313;", "if len(hash) > 32 {\n        return -313;"),
    ("req_block: block 0", "if number < 0 {\n        return -313;", "if number < 1 {\n        return -313;"),
    ("req_block: the false", "put_text(out, at + 1, \",false\")", "put_text(out, at + 1, \",true\")"),
    ("hex_value: the letters", "if c >= 97 && c <= 102 {\n        return c - 87;", "if c >= 97 && c <= 102 {\n        return c - 86;"),
    ("hex_value: upper case", "if c >= 65 && c <= 70 {\n        return c - 55;", "if c >= 65 && c <= 70 {\n        return c - 54;"),
    ("is_lower: the top", "return c >= 48 && c <= 57 || c >= 97 && c <= 102;\n}\n\n// Do the members", "return c >= 48 && c <= 57 || c >= 97 && c <= 103;\n}\n\n// Do the members"),
    ("is_lower: the bottom", "return c >= 48 && c <= 57 || c >= 97 && c <= 102;\n}\n\n// Do the members", "return c >= 47 && c <= 57 || c >= 97 && c <= 102;\n}\n\n// Do the members"),
    ("distinct: escaped names", "if !json.string_plain(tape, j) {\n            return false;", "if false {\n            return false;"),
    ("distinct: the comparison", "if json.string_equals(src, tape, k, json.string_view(src, tape, j)) {", "if json.string_equals(src, tape, k, json.string_view(src, tape, j)) && false {"),
    ("distinct: the last member", "var rest = left - 1;", "var rest = left - 2;"),
    ("response: the size", "if len(src) > 65536 {\n        return -300;", "if len(src) > 65537 {\n        return -300;"),
    ("response: JSON", "if json.parse(src, tape) < 0 {\n        return -300;", "if json.parse(src, tape) < -5000000 {\n        return -300;"),
    ("response: an object", "if !json.is_object(tape, 0) {\n        return -301;", "if false {\n        return -301;"),
    ("response: duplicates", "if !distinct(src, tape, 0) {\n        return -303;", "if false {\n        return -303;"),
    ("response: the version", "json.string_equals(src, tape, version, \"2.0\")", "json.string_equals(src, tape, version, \"2.1\")"),
    ("response: the version is plain", "if version < 0 || !json.string_plain(tape, version) ||", "if version < 0 ||"),
    ("response: no version", "if version < 0 || !json.string_plain", "if version < -5 || !json.string_plain"),
    ("response: the id is an int", "if ident < 0 || !json.is_int(tape, ident) {", "if ident < 0 {"),
    ("response: no id", "if ident < 0 || !json.is_int(tape, ident) {", "if ident < -5 || !json.is_int(tape, ident) {"),
    ("response: the id fits", "if !json.fits_int(src, tape, ident) || json.to_int(src, tape, ident) != id {", "if json.to_int(src, tape, ident) != id {"),
    ("response: the id", "json.to_int(src, tape, ident) != id {", "json.to_int(src, tape, ident) > id {"),
    ("response: both", "if result >= 0 && error >= 0 || result < 0 && error < 0 {", "if result < 0 && error < 0 {"),
    ("response: neither", "if result >= 0 && error >= 0 || result < 0 && error < 0 {", "if result >= 0 && error >= 0 {"),
    ("response: the error is an object", "if !json.is_object(tape, error) {\n        return -301;", "if false {\n        return -301;"),
    ("response: the code is an int", "if code < 0 || !json.is_int(tape, code) || !json.fits_int(src, tape, code) {", "if code < 0 || !json.fits_int(src, tape, code) {"),
    ("response: no code", "if code < 0 || !json.is_int(tape, code) ||", "if code < -5 || !json.is_int(tape, code) ||"),
    ("response: the code fits", "|| !json.is_int(tape, code) || !json.fits_int(src, tape, code) {", "|| !json.is_int(tape, code) {"),
    ("response: the node", "info[0] = result;\n        return 0;", "info[0] = error;\n        return 0;"),
    ("text_of: escapes", "if i < 0 || !json.string_plain(tape, i) {\n        return src[0..0];", "if i < 0 {\n        return src[0..0];"),
    ("has_0x: the length", "return len(text) >= 2 && int_of(text[0]) == 48", "return len(text) >= 1 && int_of(text[0]) == 48"),
    ("has_0x: the x", "int_of(text[1]) == 120;", "int_of(text[1]) == 88;"),
    ("quantity: empty", "if !has_0x(text) || len(text) < 3 || len(text) > 17 {", "if !has_0x(text) || len(text) < 2 || len(text) > 17 {"),
    ("quantity: 16 digits", "if !has_0x(text) || len(text) < 3 || len(text) > 17 {", "if !has_0x(text) || len(text) < 3 || len(text) > 18 {"),
    ("quantity: 15 digits", "if !has_0x(text) || len(text) < 3 || len(text) > 17 {", "if !has_0x(text) || len(text) < 3 || len(text) > 16 {"),
    ("quantity: a leading zero", "if int_of(text[2]) == 48 && len(text) > 3 {", "if int_of(text[2]) == 48 && len(text) > 4 {"),
    ("quantity: zero", "if int_of(text[2]) == 48 && len(text) > 3 {", "if int_of(text[2]) == 48 {"),
    ("quantity: upper case", "if !is_lower(c) {\n            return -304;", "if hex_value(c) < 0 {\n            return -304;"),
    ("quantity: the base", "v = v * 16 + hex_value(c);", "v = v * 15 + hex_value(c);"),
    ("decode_into: the length", "if !has_0x(text) || len(text) != 2 + 2 * len(out) {", "if !has_0x(text) || len(text) < 2 + 2 * len(out) {"),
    ("decode_into: the 0x", "if !has_0x(text) || len(text) != 2 + 2 * len(out) {", "if len(text) != 2 + 2 * len(out) {"),
    ("decode_into: lower case", "|| lower && (!is_lower(hi) || !is_lower(lo)) {", "|| lower && (!is_lower(hi)) {"),
    ("decode_into: the low digit", "out[i] = byte_of(hex_value(hi) * 16 + hex_value(lo));", "out[i] = byte_of(hex_value(hi) * 16 + hex_value(hi));"),
    ("hash32: lower case", "decode_into(text_of(src, tape, i), out, true) != 0 {\n        return -305;", "decode_into(text_of(src, tape, i), out, false) != 0 {\n        return -305;"),
    ("address: either case", "decode_into(text_of(src, tape, i), out, false) != 0 {\n        return -306;", "decode_into(text_of(src, tape, i), out, true) != 0 {\n        return -306;"),
    ("hash32: the length", "if len(out) != 32 || decode_into", "if len(out) > 32 || decode_into"),
    ("data_is: odd", "if !has_0x(text) || (len(text) - 2) % 2 != 0 {", "if !has_0x(text) {"),
    ("data_is: lower case", "if !is_lower(int_of(text[k])) {\n            return -307;", "if hex_value(int_of(text[k])) < 0 {\n            return -307;"),
    ("data_is: the length", "if len(text) != 2 + 2 * len(want) {\n        return 0;", "if len(text) < 2 + 2 * len(want) {\n        return 0;"),
    ("data_is: the bytes", "hex_value(int_of(text[2 + 2 * i2])) * 16 + hex_value(int_of(text[3 + 2 * i2])) != int_of(want[i2])", "hex_value(int_of(text[2 + 2 * i2])) * 16 + hex_value(int_of(text[2 + 2 * i2])) != int_of(want[i2])"),
    ("chain_id_is: the comparison", "if v != chain_id {\n        return -308;", "if v < chain_id {\n        return -308;"),
    ("chain_id_is: the other way", "if v != chain_id {\n        return -308;", "if v > chain_id {\n        return -308;"),
    ("address_is: the comparison", "} else if bytes.equal(a, want) {\n            got = 1;\n        }\n    }\n    return got;\n}\n\nfn hash_is", "} else if true {\n            got = 1;\n        }\n    }\n    return got;\n}\n\nfn hash_is"),
    ("hash_is: the comparison", "} else if bytes.equal(a, want) {\n            got = 1;\n        }\n    }\n    return got;\n}\n\n// A receipt", "} else if true {\n            got = 1;\n        }\n    }\n    return got;\n}\n\n// A receipt"),
    ("receipt: null", "if json.is_null(tape, node) {\n        return 0;\n    }\n    if !json.is_object(tape, node) {\n        return -309;", "if false {\n        return 0;\n    }\n    if !json.is_object(tape, node) {\n        return -309;"),
    ("receipt: an object", "if !json.is_object(tape, node) {\n        return -309;\n    }\n    if !distinct(src, tape, node) {\n        return -303;\n    }\n    let th", "if false {\n        return -309;\n    }\n    if !distinct(src, tape, node) {\n        return -303;\n    }\n    let th"),
    ("receipt: duplicates", "if !distinct(src, tape, node) {\n        return -303;\n    }\n    let th = json.get(src, tape, node, \"transactionHash\");", "if false {\n        return -303;\n    }\n    let th = json.get(src, tape, node, \"transactionHash\");"),
    ("receipt: no hash", "if th < 0 || from < 0 || to < 0 || json.is_null(tape, to) {", "if th < -5 || from < 0 || to < 0 || json.is_null(tape, to) {"),
    ("receipt: no sender", "if th < 0 || from < 0 || to < 0 || json.is_null(tape, to) {", "if th < 0 || from < -5 || to < 0 || json.is_null(tape, to) {"),
    ("receipt: no contract", "if th < 0 || from < 0 || to < 0 || json.is_null(tape, to) {", "if th < 0 || from < 0 || to < -5 || json.is_null(tape, to) {"),
    ("receipt: a creation", "if th < 0 || from < 0 || to < 0 || json.is_null(tape, to) {", "if th < 0 || from < 0 || to < 0 {"),
    ("receipt: no status", "if status < 0 {\n        return -310;", "if status < -5 {\n        return -310;"),
    ("receipt: the hash malformed", "return -310;\n    }\n    let same_hash = hash_is(src, tape, th, hash);\n    if same_hash < 0 {\n        return same_hash;\n    }\n    let same_from = address_is(src, tape, from, wallet);\n    if same_from < 0 {\n        return same_from;", "return -310;\n    }\n    let same_hash = hash_is(src, tape, th, hash);\n    if same_hash < -1000 {\n        return same_hash;\n    }\n    let same_from = address_is(src, tape, from, wallet);\n    if same_from < 0 {\n        return same_from;"),
    ("receipt: the sender malformed", "return -310;\n    }\n    let same_hash = hash_is(src, tape, th, hash);\n    if same_hash < 0 {\n        return same_hash;\n    }\n    let same_from = address_is(src, tape, from, wallet);\n    if same_from < 0 {\n        return same_from;", "return -310;\n    }\n    let same_hash = hash_is(src, tape, th, hash);\n    if same_hash < 0 {\n        return same_hash;\n    }\n    let same_from = address_is(src, tape, from, wallet);\n    if same_from < -1000 {\n        return same_from;"),
    ("receipt: the contract malformed", "if same_to < 0 {\n        return same_to;\n    }\n    if same_hash != 1", "if same_to < -1000 {\n        return same_to;\n    }\n    if same_hash != 1"),
    ("receipt: the hash compared", "if same_hash != 1 || same_from != 1 || same_to != 1 {\n        return -309;", "if same_from != 1 || same_to != 1 {\n        return -309;"),
    ("receipt: the sender compared", "if same_hash != 1 || same_from != 1 || same_to != 1 {\n        return -309;", "if same_hash != 1 || same_to != 1 {\n        return -309;"),
    ("receipt: the contract compared", "if same_hash != 1 || same_from != 1 || same_to != 1 {\n        return -309;", "if same_hash != 1 || same_from != 1 {\n        return -309;"),
    ("receipt: the status", "if s != 0 && s != 1 {\n        return -310;", "if s != 0 && s != 1 && s != 2 {\n        return -310;"),
    ("receipt: the block number", "if number < 0 {\n        return number;\n    }\n    let gas", "if number < -1000 {\n        return number;\n    }\n    let gas"),
    ("receipt: the gas used", "if gas < 0 {\n        return gas;", "if gas < -1000 {\n        return gas;"),
    ("receipt: the block hash", "if hash32(src, tape, json.get(src, tape, node, \"blockHash\"), block_hash) != 0 {\n        return -305;", "if false {\n        return -305;"),
    ("receipt: the gas answered", "info[1] = gas;", "info[1] = number;"),
    ("receipt: the block answered", "info[0] = number;\n    info[1] = gas;", "info[0] = gas;\n    info[1] = gas;"),
    ("receipt: success", "if s == 1 {\n        return 1;\n    }\n    return 2;", "if s == 0 {\n        return 1;\n    }\n    return 2;"),
    ("tx_check: the hash malformed", "return -311;\n    }\n    let same_hash = hash_is(src, tape, th, hash);\n    if same_hash < 0 {\n        return same_hash;\n    }\n    let same_from = address_is(src, tape, from, wallet);\n    if same_from < 0 {\n        return same_from;", "return -311;\n    }\n    let same_hash = hash_is(src, tape, th, hash);\n    if same_hash < -1000 {\n        return same_hash;\n    }\n    let same_from = address_is(src, tape, from, wallet);\n    if same_from < 0 {\n        return same_from;"),
    ("tx_check: the sender malformed", "return -311;\n    }\n    let same_hash = hash_is(src, tape, th, hash);\n    if same_hash < 0 {\n        return same_hash;\n    }\n    let same_from = address_is(src, tape, from, wallet);\n    if same_from < 0 {\n        return same_from;", "return -311;\n    }\n    let same_hash = hash_is(src, tape, th, hash);\n    if same_hash < 0 {\n        return same_hash;\n    }\n    let same_from = address_is(src, tape, from, wallet);\n    if same_from < -1000 {\n        return same_from;"),
    ("tx_check: null", "if json.is_null(tape, node) {\n        return 0;\n    }\n    if !json.is_object(tape, node) {\n        return -311;", "if false {\n        return 0;\n    }\n    if !json.is_object(tape, node) {\n        return -311;"),
    ("tx_check: duplicates", "if !distinct(src, tape, node) {\n        return -303;\n    }\n    let th = json.get(src, tape, node, \"hash\");", "if false {\n        return -303;\n    }\n    let th = json.get(src, tape, node, \"hash\");"),
    ("tx_check: a missing field", "if th < 0 || from < 0 || to < 0 || nn < 0 || input < 0 || value < 0 || block < 0 {", "if th < 0 || from < 0 || to < 0 || nn < 0 || input < 0 || value < 0 {"),
    ("tx_check: a missing value", "if th < 0 || from < 0 || to < 0 || nn < 0 || input < 0 || value < 0 || block < 0 {", "if th < 0 || from < 0 || to < 0 || nn < 0 || input < 0 || block < 0 {"),
    ("tx_check: a missing input", "if th < 0 || from < 0 || to < 0 || nn < 0 || input < 0 || value < 0 || block < 0 {", "if th < 0 || from < 0 || to < 0 || nn < 0 || value < 0 || block < 0 {"),
    ("tx_check: a missing nonce", "if th < 0 || from < 0 || to < 0 || nn < 0 || input < 0 || value < 0 || block < 0 {", "if th < 0 || from < 0 || to < 0 || input < 0 || value < 0 || block < 0 {"),
    ("tx_check: a missing hash", "if th < 0 || from < 0 || to < 0 || nn < 0 || input < 0 || value < 0 || block < 0 {", "if from < 0 || to < 0 || nn < 0 || input < 0 || value < 0 || block < 0 {"),
    ("tx_check: a missing sender", "if th < 0 || from < 0 || to < 0 || nn < 0 || input < 0 || value < 0 || block < 0 {", "if th < 0 || to < 0 || nn < 0 || input < 0 || value < 0 || block < 0 {"),
    ("tx_check: the nonce", "|| n != nonce || same_input != 1 || v != 0 {", "|| same_input != 1 || v != 0 {"),
    ("tx_check: the input", "|| n != nonce || same_input != 1 || v != 0 {", "|| n != nonce || v != 0 {"),
    ("tx_check: the value", "|| n != nonce || same_input != 1 || v != 0 {", "|| n != nonce || same_input != 1 {"),
    ("tx_check: the hash", "if same_hash != 1 || same_from != 1 || same_to != 1 || n != nonce", "if same_from != 1 || same_to != 1 || n != nonce"),
    ("tx_check: the sender", "if same_hash != 1 || same_from != 1 || same_to != 1 || n != nonce", "if same_hash != 1 || same_to != 1 || n != nonce"),
    ("tx_check: the contract", "if same_hash != 1 || same_from != 1 || same_to != 1 || n != nonce", "if same_hash != 1 || same_from != 1 || n != nonce"),
    ("tx_check: pending", "if json.is_null(tape, block) {\n        return 1;", "if false {\n        return 1;"),
    ("tx_check: the block", "info[0] = number;\n    return 2;", "info[0] = nonce;\n    return 2;"),
    ("tx_check: the input malformed", "if same_input < 0 {\n        return same_input;", "if same_input < -1000 {\n        return same_input;"),
    ("tx_check: the nonce malformed", "if n < 0 {\n        return n;\n    }\n    let same_input", "if n < -1000 {\n        return n;\n    }\n    let same_input"),
    ("tx_check: the value malformed", "let v = quantity(src, tape, value);\n    if v < 0 {\n        return v;", "let v = quantity(src, tape, value);\n    if v < -1000 {\n        return v;"),
    ("tx_check: the block malformed", "if number < 0 {\n        return number;\n    }\n    info[0] = number;\n    return 2;", "if number < -1000 {\n        return number;\n    }\n    info[0] = number;\n    return 2;"),
    ("block_check: null", "if json.is_null(tape, node) {\n        return 0;\n    }\n    if !json.is_object(tape, node) {\n        return -314;", "if false {\n        return 0;\n    }\n    if !json.is_object(tape, node) {\n        return -314;"),
    ("block_check: the number", "if got != number {\n        return -314;", "if got > number {\n        return -314;"),
    ("block_check: the number, the other way", "if got != number {\n        return -314;", "if got < number {\n        return -314;"),
    ("block_check: a missing hash", "if n < 0 || h < 0 {\n        return -314;", "if n < 0 {\n        return -314;"),
    ("block_check: a missing number", "if n < 0 || h < 0 {\n        return -314;", "if h < 0 {\n        return -314;"),
    ("block_check: the hash", "if hash32(src, tape, h, out) != 0 {\n        return -305;", "if false {\n        return -305;"),
    ("block_check: duplicates", "if !distinct(src, tape, node) {\n        return -303;\n    }\n    let n = json.get(src, tape, node, \"number\");", "if false {\n        return -303;\n    }\n    let n = json.get(src, tape, node, \"number\");"),
]

# Mutants no input can tell from the original, each with the reason.
EQUIVALENT = {
    "ready: the room": "the driver's buffer is exactly 9,000 bytes, so a length between 8,000 and 8,447 cannot be given (the check is for callers that pass their own)",
    "response: no version": "`json.string_plain` of a missing member (node -1) is false, so the next test refuses it as well: the same -301",
    "response: no id": "`json.is_int` of a missing member (node -1) is false, so the next test refuses it as well: the same -301",
    "response: no code": "`json.is_int` of a missing member (node -1) is false, so the next test refuses it as well: the same -301",
    "response: neither": "with no `result` and no `error` the error node is -1, which is not an object, and the next test answers the same -301",
    "response: the error is an object": "`json.get` of a node that is not an object answers -1 and the `code` test answers the same -301",
    "response: the code is an int": "`json.fits_int` of a node that is not an integer is false, so the next test answers the same -301",
    "text_of: escapes": "a string with an escape contains a backslash or an expanded length, which no reader accepts: every reader refuses it by its own digit or length test",
    "hash32: the length": "the driver gives exactly 32 bytes (the check is for callers that pass their own)",
    "receipt: an object": "a result that is not an object has no members, so the member lookups fail and the answer is the same -309",
    "receipt: no status": "`quantity` of a missing member is -304, which is not 0 or 1, so the status test answers the same -310",
}


def mutants(cancho, cases):
    text = open(os.path.join(ROOT, "lib/rpc/rpc.cho")).read()
    work = []
    wrong = [f"{name!r}: {text.count(old)} times" for name, old, new in MUTANTS if text.count(old) != 1]
    if wrong:
        sys.exit("mutant patterns that do not occur exactly once:\n  " + "\n  ".join(wrong))
    for name, old, new in MUTANTS:
        work.append((name, text.replace(old, new)))

    def one(item):
        name, body = item
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "rpc"))
            open(os.path.join(d, "rpc/rpc.cho"), "w").write(body)
            exe = os.path.join(d, "rpcdrv")
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
    cases = 6
    if "--cases" in sys.argv:
        cases = int(sys.argv[sys.argv.index("--cases") + 1])
    cancho = os.environ.get("CANCHO", "cancho")
    if "--mutants" in sys.argv:
        mutants(cancho, min(cases, 2))
    if "--exe" in sys.argv:
        run(sys.argv[sys.argv.index("--exe") + 1], cases)
        print(f"{COUNT[0]} checks, {len(FAILS)} failed")
        sys.exit(1 if FAILS else 0)
    with tempfile.TemporaryDirectory() as t:
        exe = os.path.join(t, "rpcdrv")
        build(cancho, os.path.join(ROOT, "lib"), exe)
        run(exe, cases)
    print(f"{COUNT[0]} checks, {len(FAILS)} failed")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
