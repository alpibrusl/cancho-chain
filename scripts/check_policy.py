#!/usr/bin/env python3
"""The policy and the decision function (lib/policy) against an independent model written from docs/design.md section 11 (section 11.5).

    CANCHO=the-compiler CANCHO_SCHEMA=../cancho-schema/src/schema.cho python3 -I scripts/check_policy.py [--mutants] [--cases N]
    needs: pip install eth-account jsonschema

Builds tools/policydrv/main.cho. Checks: (1) every policy the model accepts has its canonical bytes and digest, in any key order; (2) every damage to a policy is refused with exactly its code;
(3) for random and for hand-built scenarios the decision (outcome, reason, every byte of the record and its digest) is the model's; each of the 14 reasons alone and every combination of up to three
of them, so that the table's order is tested; every boundary of time, amount and history; (4) malformed inputs answer their negative code and no decision. --mutants: one deliberate fault at a time in
lib/policy/*.cho; every one must be killed.
"""
import itertools, json, os, random, shutil, subprocess, sys, tempfile
from eth_utils import keccak, to_checksum_address

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = os.environ.get("CANCHO_SCHEMA", os.path.join(ROOT, "../cancho-schema/src/schema.cho"))
U256 = 2**256
WORD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"


def srcs(libdir):
    return [os.path.join(ROOT, "tools/policydrv/main.cho"), os.path.join(ROOT, "lib/keccak/keccak.cho"), os.path.join(ROOT, "lib/eth/hex.cho"), os.path.join(ROOT, "lib/eth/address.cho"),
            os.path.join(ROOT, "lib/intent/intent.cho"), os.path.join(libdir, "policy/policy.cho"), os.path.join(libdir, "policy/decide.cho"), SCHEMA]


def build(cancho, libdir, out):
    r = subprocess.run([cancho, "build", "--std", *srcs(libdir), "-o", out], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("build failed:\n" + r.stderr)


def call(exe, line):
    return subprocess.run([exe], input=line.encode(), capture_output=True, timeout=60).stdout.decode().strip() or "CRASH"


def hx(b):
    return b.hex() if b else "_"


def tup(out):
    parts = out.split()
    return parts[0] if len(parts) == 1 else tuple(parts)


# ---- the model: the spec of section 11, written separately
class Pol:
    def __init__(self, rng=None):
        rng = rng or random.Random(1)
        self.pid = "procurement-usdc-v1"
        self.version = 3
        self.principal = "agent-procurement-01"
        self.chain = 11155111
        self.asset = bytes(rng.randrange(256) for _ in range(20))
        self.decimals = 6
        self.recips = [bytes(rng.randrange(256) for _ in range(20)) for _ in range(3)]
        self.per, self.daily, self.approval = 500, 2000, 250
        self.fee, self.gas = 30_000_000_000, 100_000
        self.nb, self.na = 1_730_000_000, 1_830_000_000
        self.ttl = 300
        self.ops = 1

    def canonical(self):
        appr = U256 - 1 if self.approval is None else self.approval
        return (bytes([1, len(self.pid)]) + self.pid.encode() + self.version.to_bytes(4, "big") + bytes([len(self.principal)]) + self.principal.encode() + self.chain.to_bytes(8, "big") + self.asset
                + bytes([self.decimals, self.ops]) + bytes([len(self.recips)]) + b"".join(self.recips) + self.per.to_bytes(32, "big") + self.daily.to_bytes(32, "big") + appr.to_bytes(32, "big")
                + self.fee.to_bytes(32, "big") + self.gas.to_bytes(8, "big") + self.nb.to_bytes(8, "big") + self.na.to_bytes(8, "big") + self.ttl.to_bytes(4, "big"))

    def digest(self):
        return keccak(b"cancho-chain/policy/v1" + self.canonical())

    def doc(self):
        limits = {"per_transaction": str(self.per), "daily_total": str(self.daily)}
        if self.approval is not None:
            limits["approval_required_above"] = str(self.approval)
        return {"policy_id": self.pid, "version": self.version, "principal": self.principal, "chain_id": self.chain, "asset": {"contract": to_checksum_address(self.asset), "decimals": self.decimals},
                "operations": ["erc20_transfer"], "recipients": [to_checksum_address(r) for r in self.recips], "limits": limits,
                "fees": {"max_fee_per_gas": str(self.fee), "gas_limit": self.gas}, "validity": {"not_before": self.nb, "not_after": self.na}, "decision_ttl_seconds": self.ttl}

    def json(self, doc=None):
        return json.dumps(doc or self.doc(), separators=(",", ":")).encode()


class Intent:
    def __init__(self, p):
        self.chain, self.asset, self.recipient = p.chain, p.asset, p.recips[0]
        self.amount, self.ref, self.req, self.kind = 100, "invoice-2026-0042", "2026-0042-a", 1

    def canonical(self):
        return (bytes([1, self.kind]) + self.chain.to_bytes(8, "big") + self.asset + self.recipient + self.amount.to_bytes(32, "big") + bytes([len(self.ref)]) + self.ref.encode()
                + bytes([len(self.req)]) + self.req.encode())

    def digest(self):
        return keccak(b"cancho-chain/intent/v1" + self.canonical())

    def json(self):
        return json.dumps({"kind": "erc20_transfer", "chain_id": self.chain, "asset": to_checksum_address(self.asset), "recipient": to_checksum_address(self.recipient), "amount": str(self.amount),
                           "reference": self.ref, "request_id": self.req}, separators=(",", ":")).encode()


def history_bytes(h):
    return b"".join(ts.to_bytes(8, "big") + dg + am.to_bytes(32, "big") for ts, dg, am in h)


def model_decide(P, I, caller, now, cur, revoked, hist):
    """The decision record and its digest, or a negative error code."""
    if now < 0 or now > 2**62:
        return -236
    if not (1 <= len(caller) <= 64) or any(chr(c) not in WORD for c in caller):
        return -232
    if any(ts > now or ts >= 2**63 for ts, _, _ in hist):
        return -233
    reason = 0
    window = [(ts, dg, am) for ts, dg, am in hist if ts > now - 86400]
    if cur < 0:
        reason = 1
    elif revoked:
        reason = 2
    elif P.version < cur:
        reason = 3
    elif now < P.nb:
        reason = 4
    elif now >= P.na:
        reason = 5
    elif P.principal.encode() != caller:
        reason = 6
    elif not (P.ops >> (I.kind - 1)) & 1:
        reason = 7
    elif P.chain != I.chain:
        reason = 8
    elif P.asset != I.asset:
        reason = 9
    elif I.recipient not in P.recips:
        reason = 10
    elif I.amount > P.per:
        reason = 11
    elif any(dg == I.digest() for _, dg, _ in hist):
        reason = 12
    elif I.amount + sum(am for _, _, am in window) > P.daily or I.amount + sum(am for _, _, am in window) >= U256:
        reason = 13
    elif I.amount > (U256 - 1 if P.approval is None else P.approval):
        reason = 14
    outcome = 1 if reason == 0 else 3 if reason == 14 else 2
    expires = now + P.ttl if outcome == 1 else now
    rec = (bytes([1, outcome]) + reason.to_bytes(2, "big") + I.digest() + P.digest() + now.to_bytes(8, "big") + expires.to_bytes(8, "big")
           + (I.amount if outcome == 1 else 0).to_bytes(32, "big") + bytes([len(caller)]) + caller)
    return rec, keccak(b"cancho-chain/decision/v1" + rec)


def decide(exe, P, I, caller, now, cur, revoked, hist, pol_canon=None, int_canon=None, hist_raw=None, op="C"):
    pc = P.canonical() if pol_canon is None else pol_canon
    ic = I.canonical() if int_canon is None else int_canon
    hb = history_bytes(hist) if hist_raw is None else hist_raw
    return tup(call(exe, f"{op} {hx(pc)} {hx(ic)} {hx(caller)} {now} {cur} {1 if revoked else 0} {hx(hb)}"))


def expect_decision(m):
    if isinstance(m, int):
        return f"E{-m}"
    return ("0", m[0].hex(), m[1].hex())


class Scenario:
    def __init__(self, rng):
        self.P = Pol(rng)
        self.I = Intent(self.P)
        self.caller = self.P.principal.encode()
        self.now = self.P.nb + 1000
        self.cur = self.P.version
        self.revoked = False
        self.hist = []

    def run(self, exe):
        return decide(exe, self.P, self.I, self.caller, self.now, self.cur, self.revoked, self.hist)

    def expected(self):
        return expect_decision(model_decide(self.P, self.I, self.caller, self.now, self.cur, self.revoked, self.hist))


def other(b):
    return bytes([b[0] ^ 1]) + b[1:]


BREAKERS = {
    1: lambda s: setattr(s, "cur", -1),
    2: lambda s: setattr(s, "revoked", True),
    3: lambda s: setattr(s, "cur", s.P.version + 1),
    4: lambda s: setattr(s, "now", s.P.nb - 1),
    5: lambda s: setattr(s, "now", s.P.na),
    6: lambda s: setattr(s, "caller", b"someone-else"),
    7: lambda s: setattr(s.P, "ops", 0),
    8: lambda s: setattr(s.I, "chain", s.I.chain + 1),
    9: lambda s: setattr(s.I, "asset", other(s.I.asset)),
    10: lambda s: setattr(s.I, "recipient", other(s.I.recipient)),
    11: lambda s: setattr(s.I, "amount", s.P.per + 1),
    12: lambda s: s.hist.append((s.now - 10, s.I.digest(), 1)),
    13: lambda s: s.hist.append((s.now - 10, keccak(b"another"), s.P.daily)),
    14: lambda s: setattr(s.I, "amount", s.P.approval + 1),
}


def run(exe, cases, quiet=False):
    bad = total = 0

    def check(name, got, want):
        nonlocal bad, total
        total += 1
        if got != want:
            bad += 1
            if bad <= 8 and not quiet:
                print(f"  MISMATCH {name}: got {got} want {want}")

    rng = random.Random(20261106)
    # ---- (1) the policy: canonical bytes and digest
    for k in range(cases):
        P = Pol(rng)
        P.pid = "".join(rng.choice(WORD) for _ in range(rng.choice((1, 2, 19, 64))))
        P.principal = "".join(rng.choice(WORD) for _ in range(rng.choice((1, 2, 20, 64))))
        P.version = rng.choice((1, 2, 3, 2**32 - 1, rng.randrange(1, 2**32)))
        P.chain = rng.choice((1, 11155111, 2**53 - 1, rng.randrange(1, 2**53)))
        P.decimals = rng.choice((0, 6, 18, 36))
        P.recips = [bytes(rng.randrange(256) for _ in range(20)) for _ in range(rng.choice((1, 2, 3, 31, 32)))]
        P.daily = rng.choice((1, 10**6, 10**30, U256 - 1))
        P.per = rng.randrange(1, P.daily + 1)
        P.approval = rng.choice((None, 1, P.per, rng.randrange(1, P.per + 1)))
        P.fee = rng.choice((1, 30_000_000_000, U256 - 1))
        P.gas = rng.choice((1, 21000, 2**53 - 1))
        P.nb = rng.choice((0, 1_730_000_000))
        P.na = P.nb + rng.choice((1, 86400, 2**52))
        P.ttl = rng.choice((1, 300, 3600))
        want = ("0", P.canonical().hex(), P.digest().hex())
        d = P.doc()
        check(f"policy #{k}", tup(call(exe, "P " + hx(P.json()))), want)
        keys = list(d)
        rng.shuffle(keys)
        check(f"policy #{k} with the keys shuffled", tup(call(exe, "P " + hx(json.dumps({key: d[key] for key in keys}, indent=rng.choice((None, 1))).encode()))), want)
        check(f"policy #{k} with its addresses in lowercase", tup(call(exe, "P " + hx(P.json({**d, "asset": {**d["asset"], "contract": d["asset"]["contract"].lower()}, "recipients": [r.lower() for r in d["recipients"]]})))), want)
    base = Pol(random.Random(7))
    bd = base.doc()

    def mut(f):
        d = json.loads(json.dumps(bd))
        f(d)
        return json.dumps(d, separators=(",", ":")).encode()

    def drop(*path):
        def f(d):
            for p in path[:-1]:
                d = d[p]
            del d[path[-1]]
        return f

    def setv(path, v):
        def f(d):
            for p in path[:-1]:
                d = d[p]
            d[path[-1]] = v
        return f

    def text_dup(old, new):
        t = json.dumps(bd, separators=(",", ":"))
        assert t.count(old) == 1, old
        return t.replace(old, new).encode()

    ck = to_checksum_address(base.asset)
    letters = [i for i, c in enumerate(ck) if i >= 2 and c.isalpha()]
    flip = ck[:letters[0]] + ck[letters[0]].swapcase() + ck[letters[0] + 1:]
    bad_ck = flip if any(c.isupper() for c in flip[2:] if c.isalpha()) and any(c.islower() for c in flip[2:] if c.isalpha()) else ck[:-1] + "g"
    many = [to_checksum_address(bytes([i + 1]) + b"\0" * 19) for i in range(33)]
    cases_ = []
    for path in (["policy_id"], ["version"], ["principal"], ["chain_id"], ["asset"], ["operations"], ["recipients"], ["limits"], ["fees"], ["validity"], ["decision_ttl_seconds"], ["asset", "contract"], ["asset", "decimals"],
                 ["limits", "per_transaction"], ["limits", "daily_total"], ["fees", "max_fee_per_gas"], ["fees", "gas_limit"], ["validity", "not_before"], ["validity", "not_after"]):
        cases_.append((f"missing {'.'.join(path)}", mut(drop(*path)), "E221"))
    for path in ([], ["asset"], ["limits"], ["fees"], ["validity"]):
        cases_.append((f"an unknown key in {'.'.join(path) or 'the policy'}", mut(setv(path + ["extra"], 1)), "E221"))
    for name, path, v in (("version as a string", ["version"], "1"), ("chain_id as a string", ["chain_id"], "1"), ("operations as a string", ["operations"], "erc20_transfer"), ("recipients as a string", ["recipients"], "x"),
                          ("limits as an array", ["limits"], []), ("decimals as a string", ["asset", "decimals"], "6"), ("version 0", ["version"], 0), ("version 2^32", ["version"], 2**32), ("decimals 37", ["asset", "decimals"], 37),
                          ("decimals -1", ["asset", "decimals"], -1), ("ttl 0", ["decision_ttl_seconds"], 0), ("ttl 3601", ["decision_ttl_seconds"], 3601), ("gas limit 0", ["fees", "gas_limit"], 0), ("chain id 0", ["chain_id"], 0),
                          ("not_before -1", ["validity", "not_before"], -1), ("operations empty", ["operations"], []), ("operations twice", ["operations"], ["erc20_transfer", "erc20_transfer"]),
                          ("operations other", ["operations"], ["erc20_approve"]), ("recipients empty", ["recipients"], []), ("33 recipients", ["recipients"], many), ("policy_id empty", ["policy_id"], ""),
                          ("policy_id of 65", ["policy_id"], "a" * 65), ("contract of 41", ["asset", "contract"], ck[:-1]), ("amount empty", ["limits", "per_transaction"], ""), ("amount of 79", ["limits", "daily_total"], "1" * 79),
                          ("a recipient that is a number", ["recipients"], [5])):
        cases_.append((name, mut(setv(path, v)), "E221"))
    cases_ += [("contract: bad checksum", mut(setv(["asset", "contract"], bad_ck)), "E222"), ("contract: all uppercase", mut(setv(["asset", "contract"], "0x" + ck[2:].upper())), "E222"),
               ("contract: no prefix", mut(setv(["asset", "contract"], "00" + ck[2:])), "E222"), ("first recipient: bad", mut(setv(["recipients"], [bad_ck] + bd["recipients"][1:])), "E222"),
               ("last recipient: bad", mut(setv(["recipients"], bd["recipients"][:-1] + [bad_ck])), "E222")]
    for field, path in (("per_transaction", ["limits", "per_transaction"]), ("daily_total", ["limits", "daily_total"]), ("approval_required_above", ["limits", "approval_required_above"]), ("max_fee_per_gas", ["fees", "max_fee_per_gas"])):
        for name, v in (("zero", "0"), ("leading zero", "007"), ("minus", "-5"), ("point", "1.5"), ("exponent", "1e6"), ("space", " 5"), ("2^256", str(U256))):
            cases_.append((f"{field}: {name}", mut(setv(path, v)), "E223"))
    for name, path, v in (("version 1.0", ["version"], "1.0"), ("chain_id 1e2", ["chain_id"], "1e2"), ("decimals 6.0", ["asset", "decimals"], "6.0"), ("gas_limit 1e5", ["fees", "gas_limit"], "1e5"), ("ttl 300.0", ["decision_ttl_seconds"], "300.0"),
                          ("not_before 1e9", ["validity", "not_before"], "1e9"), ("not_after 1730000001.0", ["validity", "not_after"], "1830000001.0")):
        t = json.dumps(bd, separators=(",", ":"))
        key = path[-1]
        old = f'"{key}":{json.dumps(__import__("functools").reduce(lambda a, b: a[b], path, bd))}'
        assert t.count(old) == 1, old
        cases_.append((name, t.replace(old, f'"{key}":{v}').encode(), "E223"))
    for field in ("policy_id", "principal"):
        for name, v in (("a space", "a b"), ("a slash", "a/b"), ("non-ASCII", "é"), ("an emoji", "😀"), ("a quote", 'a"b')):
            cases_.append((f"{field}: {name}", mut(setv([field], v)), "E224"))
        t = json.dumps(bd, separators=(",", ":"))
        cases_.append((f"{field}: an escaped letter", t.replace(f'"{field}":"{bd[field]}"', f'"{field}":"\\u0041"').encode(), "E224"))
    cases_ += [("a key twice", text_dup('"version":3', '"version":3,"version":4'), "E225"), ("a nested key twice", text_dup('"daily_total":"2000"', '"daily_total":"2000","daily_total":"1"'), "E225"),
               ("an escaped key", json.dumps(bd, separators=(",", ":")).replace('"policy_id"', '"polic\\u0079_id"').encode(), "E225"),
               ("an escaped nested key", json.dumps(bd, separators=(",", ":")).replace('"decimals"', '"d\\u0065cimals"').encode(), "E225"),
               ("a recipient twice (adjacent)", mut(setv(["recipients"], [bd["recipients"][0], bd["recipients"][0], bd["recipients"][1]])), "E225"),
               ("a recipient twice (apart)", mut(setv(["recipients"], [bd["recipients"][0], bd["recipients"][1], bd["recipients"][0]])), "E225"),
               ("the same recipient in lowercase", mut(setv(["recipients"], [bd["recipients"][0], bd["recipients"][0].lower()])), "E225"),
               ("per_transaction above daily_total", mut(setv(["limits", "per_transaction"], "2001")), "E226"), ("approval above per_transaction", mut(setv(["limits", "approval_required_above"], "501")), "E226"),
               ("not_after equal to not_before", mut(setv(["validity", "not_after"], bd["validity"]["not_before"])), "E226"), ("not_after before not_before", mut(setv(["validity", "not_after"], bd["validity"]["not_before"] - 1)), "E226"),
               ("per_transaction equal to daily_total", mut(setv(["limits", "per_transaction"], "2000")), "0"), ("approval equal to per_transaction", mut(setv(["limits", "approval_required_above"], "500")), "0"),
               ("no approval threshold", mut(drop("limits", "approval_required_above")), "0"), ("not_after one after not_before", mut(setv(["validity", "not_after"], bd["validity"]["not_before"] + 1)), "0"),
               ("a trailing comma", json.dumps(bd, separators=(",", ":"))[:-1].encode() + b",}", "E220"), ("an array", b"[]", "E220"), ("truncated", json.dumps(bd).encode()[:-5], "E220"), ("empty", b"", "E220"),
               ("an empty object", b"{}", "E221"), ("single quotes", json.dumps(bd).replace('"', "'").encode(), "E220")]
    pad = lambda n: json.dumps(bd, separators=(",", ":")).encode()[:-1] + b" " * (n - len(json.dumps(bd, separators=(",", ":"))) ) + b"}"
    cases_ += [("exactly 8192 bytes", pad(8192), "0"), ("8193 bytes", pad(8193), "E227")]
    for name, b, want in cases_:
        got = tup(call(exe, "P " + hx(b)))
        check(name, got[0] if isinstance(got, tuple) else got, want)
    check("a policy output slice that is too short", call(exe, "O " + hx(base.json())), "E228")
    check("a policy Keccak working space that is too short", call(exe, "W " + hx(base.json())), "E229")
    # the exported schema is there and the structure stage agrees with it
    import jsonschema
    sch = json.loads(call(exe, "S"))
    jsonschema.Draft202012Validator.check_schema(sch)
    v = jsonschema.Draft202012Validator(sch)
    for name, b, want in cases_:
        try:
            doc = json.loads(b)
        except Exception:
            continue
        if name.startswith(("a key twice", "a nested key twice", "an escaped")) or len(b) > 8192:
            continue
        check(f"policy structure stage vs JSON Schema: {name}", call(exe, "Q " + hx(b)) == "ok", v.is_valid(doc))

    # ---- (3) decisions: random
    for k in range(cases * 6):
        s = Scenario(rng)
        s.P.version = rng.choice((1, 3, 7))
        s.cur = rng.choice((-1, s.P.version, s.P.version, s.P.version, s.P.version + 1, 1, 0))
        s.revoked = rng.random() < 0.1
        s.now = rng.choice((s.P.nb - 1, s.P.nb, s.P.nb + 5, s.P.na - 1, s.P.na, s.P.na + 5, s.P.nb + rng.randrange(1, 10**6)))
        s.caller = rng.choice((s.P.principal.encode(), s.P.principal.encode(), s.P.principal.encode(), b"other-agent"))
        s.P.per = rng.choice((1, 100, 500, 10**18))
        s.P.daily = s.P.per * rng.choice((1, 2, 4))
        s.P.approval = rng.choice((None, 1, s.P.per, max(1, s.P.per // 2)))
        s.I.amount = rng.choice((1, max(1, s.P.per - 1), s.P.per, s.P.per + 1, rng.randrange(1, 2 * s.P.per + 2)))
        s.I.chain = rng.choice((s.P.chain, s.P.chain, s.P.chain, s.P.chain + 1))
        s.I.asset = rng.choice((s.P.asset, s.P.asset, s.P.asset, other(s.P.asset)))
        s.I.recipient = rng.choice(s.P.recips + [other(s.P.recips[0])])
        for _ in range(rng.choice((0, 0, 1, 2, 5))):
            ts = s.now - rng.choice((0, 1, 86399, 86400, 86401, 100000, rng.randrange(0, 200000)))
            ts = max(0, ts)
            dg = s.I.digest() if rng.random() < 0.08 else keccak(bytes([rng.randrange(256)]))
            s.hist.append((ts, dg, rng.choice((1, 50, s.P.per, s.P.daily // 2 if s.P.daily > 1 else 1))))
        check(f"random decision #{k}", s.run(exe), s.expected())
    # ---- each reason alone, and every combination of up to three: the table's order
    for size in (1, 2, 3):
        for combo in itertools.combinations(sorted(BREAKERS), size):
            s = Scenario(rng)
            s.P.approval = 250
            s.I.amount = 100
            for r in combo:
                BREAKERS[r](s)
            check(f"reasons {combo}", s.run(exe), s.expected())
    s = Scenario(rng)
    check("the base scenario is allowed", s.run(exe), s.expected())
    # ---- boundaries
    s = Scenario(rng)
    for name, now in (("now = not_before - 1", s.P.nb - 1), ("now = not_before", s.P.nb), ("now = not_after - 1", s.P.na - 1), ("now = not_after", s.P.na), ("now = not_after + 1", s.P.na + 1)):
        t = Scenario(rng)
        t.now = now
        check(name, t.run(exe), t.expected())
    for name, delta in (("amount = per - 1", -1), ("amount = per", 0), ("amount = per + 1", 1)):
        t = Scenario(rng)
        t.P.approval = None
        t.I.amount = t.P.per + delta
        check(name, t.run(exe), t.expected())
    for name, delta in (("amount = approval - 1", -1), ("amount = approval", 0), ("amount = approval + 1", 1)):
        t = Scenario(rng)
        t.I.amount = t.P.approval + delta
        check(name, t.run(exe), t.expected())
    for name, ts_off in (("history record at now - 86401", -86401), ("history record at now - 86400 (outside the window)", -86400), ("history record at now - 86399 (inside)", -86399), ("history record at now", 0)):
        t = Scenario(rng)
        t.hist = [(t.now + ts_off, keccak(b"x"), t.P.daily)]
        check(name, t.run(exe), t.expected())
    for name, amt in (("the daily total reached exactly", 0), ("the daily total exceeded by one", 1), ("one short of it", -1)):
        t = Scenario(rng)
        t.P.approval = None
        t.I.amount = 100
        t.hist = [(t.now - 5, keccak(b"x"), t.P.daily - 100 + amt)]
        check(name, t.run(exe), t.expected())
    t = Scenario(rng)
    t.P.approval = None
    t.P.per, t.P.daily = U256 - 1, U256 - 1
    t.I.amount = 2
    t.hist = [(t.now - 5, keccak(b"x"), U256 - 2)]
    check("the sum overflows 2^256", t.run(exe), t.expected())
    t.hist = [(t.now - 5, keccak(b"x"), U256 - 3)]
    check("the sum is 2^256 - 1", t.run(exe), t.expected())
    t = Scenario(rng)
    t.hist = [(t.now - 500000, t.I.digest(), 1)]
    check("a replay older than the window still counts", t.run(exe), t.expected())
    t = Scenario(rng)
    t.hist = [(t.now - 5, keccak(b"a"), 700), (t.now - 6, keccak(b"b"), 700), (t.now - 86400, keccak(b"c"), 10**9)]
    check("several records are summed, an old one is not", t.run(exe), t.expected())
    # the chain compared in both directions
    t = Scenario(rng)
    t.I.chain = t.P.chain - 1
    check("the intent's chain below the policy's", t.run(exe), t.expected())
    # replay anywhere in the history, not only first
    for pos in range(4):
        t = Scenario(rng)
        t.hist = [(t.now - 10 - k, keccak(bytes([k])), 1) for k in range(4)]
        t.hist[pos] = (t.now - 10 - pos, t.I.digest(), 1)
        check(f"a replay at position {pos} of 4", t.run(exe), t.expected())
    # an overflow in any record is not forgotten by a later one
    for name, hist in (("overflow in the first record, a small second", [(1, U256 - 1), (2, 1)]), ("a small first record, overflow in the second", [(1, 1), (2, U256 - 1)]),
                       ("overflow in the first of three", [(1, U256 - 1), (2, 1), (3, 1)])):
        t = Scenario(rng)
        t.P.per, t.P.daily, t.P.approval = U256 - 1, U256 - 1, None
        t.I.amount = 2
        t.hist = [(t.now - 5 - k, keccak(bytes([k + 9])), am) for k, (_, am) in enumerate(hist)]
        check(name, t.run(exe), t.expected())
    # the decision digest of any record the engine could write, and refusal of any other length
    for n in (117, 182, 0, 1, 300):
        check(f"decision digest of {n} bytes", tup(call(exe, f"G {hx(bytes(range(256))[:n] if n <= 256 else bytes(n))}")), "E234")
    for n in (118, 150, 181):
        rec = bytes((i * 7 + 3) & 255 for i in range(n))
        check(f"decision digest of {n} bytes", tup(call(exe, f"G {hx(rec)}")), ("0", keccak(b"cancho-chain/decision/v1" + rec).hex()))
    # D: from the JSON, end to end
    for k in range(cases):
        s = Scenario(rng)
        s.I.amount = rng.choice((1, 100, 250, 251, 500, 501))
        got = tup(call(exe, f"D {hx(s.P.json())} {hx(s.I.json())} {hx(s.caller)} {s.now} {s.cur} 0 {hx(history_bytes(s.hist))}"))
        check(f"decide from JSON #{k}", got, s.expected())
    # ---- (4) malformed inputs
    s = Scenario(rng)
    pc, ic = s.P.canonical(), s.I.canonical()
    for name, kw, want in (("policy truncated", dict(pol_canon=pc[:-1]), "E230"), ("policy extended", dict(pol_canon=pc + b"\0"), "E230"), ("policy with a bad version byte", dict(pol_canon=bytes([2]) + pc[1:]), "E230"),
                           ("policy with an id of length 0", dict(pol_canon=bytes([1, 0]) + pc[2:]), "E230"), ("policy with an id of length 65", dict(pol_canon=bytes([1, 65]) + pc[2:]), "E230"),
                           ("empty policy", dict(pol_canon=b""), "E230"), ("intent truncated", dict(int_canon=ic[:-1]), "E231"), ("intent extended", dict(int_canon=ic + b"\0"), "E231"),
                           ("intent with kind 2", dict(int_canon=ic[:1] + b"\x02" + ic[2:]), "E231"), ("intent with layout 2", dict(int_canon=b"\x02" + ic[1:]), "E231"), ("empty intent", dict(int_canon=b""), "E231"),
                           ("intent with an empty reference", dict(int_canon=ic[:82] + b"\0" + ic[83 + len(s.I.ref):]), "E231"), ("history of 71 bytes", dict(hist_raw=b"\0" * 71), "E233"),
                           ("history of 73 bytes", dict(hist_raw=b"\0" * 73), "E233"), ("history from the future", dict(hist_raw=(s.now + 1).to_bytes(8, "big") + b"\0" * 64), "E233"),
                           ("history with a timestamp of 2^63", dict(hist_raw=(2**63).to_bytes(8, "big") + b"\0" * 64), "E233"), ("history of 2^64 - 1", dict(hist_raw=(2**64 - 1).to_bytes(8, "big") + b"\0" * 64), "E233")):
        check(name, decide(exe, s.P, s.I, s.caller, s.now, s.cur, False, [], **kw), want)
    # a canonical policy that is consistent in length but out of range: the shape check is what refuses it
    for name, edit in (("a policy with no recipients", lambda q: setattr(q, "recips", [])), ("a policy with 33 recipients", lambda q: setattr(q, "recips", [bytes([i + 1]) * 20 for i in range(33)])),
                       ("a policy with an empty id", lambda q: setattr(q, "pid", "")), ("a policy with a 65-byte id", lambda q: setattr(q, "pid", "a" * 65)),
                       ("a policy with an empty principal", lambda q: setattr(q, "principal", "")), ("a policy with a 65-byte principal", lambda q: setattr(q, "principal", "a" * 65)),
                       ("a policy with a 64-byte id (accepted)", lambda q: setattr(q, "pid", "a" * 64)), ("a policy with 32 recipients (accepted)", lambda q: setattr(q, "recips", [bytes([i + 1]) * 20 for i in range(32)])),
                       ("a policy with a 1-byte id (accepted)", lambda q: setattr(q, "pid", "a"))):
        q = Pol(rng)
        edit(q)
        got = decide(exe, q, s.I, q.principal.encode() or b"x", s.now, q.version, False, [], pol_canon=q.canonical())
        check(name, got if isinstance(got, str) else "decision", "decision" if "accepted" in name else "E230")
    for name, caller in (("an empty caller", b""), ("a caller of 65 bytes", b"a" * 65), ("a caller with a space", b"a b"), ("a caller with a non-ASCII byte", b"a\xc3\xa9"), ("a caller with a slash", b"a/b"),
                         ("a caller of 64 bytes", b"a" * 64), ("a caller of one byte", b"a")):
        got = decide(exe, s.P, s.I, caller, s.now, s.cur, False, [])
        check(name, got if isinstance(got, str) else "decision", "E232" if name not in ("a caller of 64 bytes", "a caller of one byte") else "decision")
    for name, now in (("now = -1", -1), ("now = 2^62 + 1", 2**62 + 1)):
        check(name, decide(exe, s.P, s.I, s.caller, now, s.cur, False, []), "E236")
    check("now = 2^62 is accepted", decide(exe, s.P, s.I, s.caller, 2**62, s.cur, False, [])[0], "0")
    check("a decision output that is too short", decide(exe, s.P, s.I, s.caller, s.now, s.cur, False, [], op="E"), "E234")
    check("a decision working space that is too short", decide(exe, s.P, s.I, s.caller, s.now, s.cur, False, [], op="K"), "E235")
    return bad, total


# Mutants no input can kill, with the reason. Reported, not failed: a survivor outside this list fails the run.
EXPECTED_SURVIVORS = {
    "escaped later keys accepted": "equivalent: an escaped key and a duplicate key share the refusal code -225, and the outer loop reaches every escaped key on its own iteration, so the answer is the same",
    "the working space limit": "defence in depth: with 50 to 109 words the first check passes, the Keccak call that follows refuses the short working space, and `decide` answers the same decide-work code",
}

# (name, file, old, new)
MUTANTS = [
    ('registry state missing not checked', 'decide.cho', 'if current_version < 0 {\n        return 1;', 'if current_version < -5 {\n        return 1;'),
    ('revocation ignored', 'decide.cho', 'if revoked {\n        return 2;', 'if false {\n        return 2;'),
    ('a policy at the current version counts as superseded', 'decide.cho', 'if policy.version(pol) < current_version {', 'if policy.version(pol) <= current_version {'),
    ('supersession ignored', 'decide.cho', 'if policy.version(pol) < current_version {', 'if policy.version(pol) > current_version {'),
    ('not_before is exclusive', 'decide.cho', 'if now < policy.not_before(pol) {', 'if now <= policy.not_before(pol) {'),
    ('not_before ignored', 'decide.cho', 'if now < policy.not_before(pol) {', 'if now < 0 {'),
    ('not_after is inclusive', 'decide.cho', 'if now >= policy.not_after(pol) {', 'if now > policy.not_after(pol) {'),
    ('not_after ignored', 'decide.cho', 'if now >= policy.not_after(pol) {', 'if now < 0 {'),
    ('principal ignored', 'decide.cho', 'if !bytes.equal(policy.principal(pol), caller) {', 'if false {'),
    ('operation ignored', 'decide.cho', 'if !policy.allows_operation(pol, int_of(it[1])) {', 'if false {'),
    ('chain compared one way', 'decide.cho', 'if policy.chain_id(pol) != intent.chain_id(it) {', 'if policy.chain_id(pol) > intent.chain_id(it) {'),
    ('chain compared the other way', 'decide.cho', 'if policy.chain_id(pol) != intent.chain_id(it) {', 'if policy.chain_id(pol) < intent.chain_id(it) {'),
    ('asset ignored', 'decide.cho', 'if !bytes.equal(policy.asset(pol), intent.asset(it)) {', 'if false {'),
    ('recipient ignored', 'decide.cho', 'if !in_list(pol, intent.recipient(it)) {', 'if false {'),
    ('only the first recipient is allowed', 'decide.cho', 'while i < policy.recipient_count(c) {', 'while i < 1 {'),
    ('the last recipient is not allowed', 'decide.cho', 'while i < policy.recipient_count(c) {', 'while i < policy.recipient_count(c) - 1 {'),
    ('the per-transaction limit is exclusive', 'decide.cho', 'if policy.cmp32(amount, policy.per_transaction(pol)) > 0 {', 'if policy.cmp32(amount, policy.per_transaction(pol)) >= 0 {'),
    ('the per-transaction limit ignored', 'decide.cho', 'if policy.cmp32(amount, policy.per_transaction(pol)) > 0 {', 'if policy.cmp32(amount, policy.per_transaction(pol)) > 5 {'),
    ('replay ignored', 'decide.cho', 'if replayed {\n        return 12;', 'if false {\n        return 12;'),
    ('replay looks in the wrong bytes', 'decide.cho', 'history[72 * k + 8..72 * k + 40]', 'history[72 * k + 7..72 * k + 39]'),
    ('replay stops at the first record', 'decide.cho', '        if bytes.equal(history[72 * k + 8..72 * k + 40], idigest) {\n            replayed = true;\n        }\n        k = k + 1;', '        if bytes.equal(history[72 * k + 8..72 * k + 40], idigest) && k == 0 {\n            replayed = true;\n        }\n        k = k + 1;'),
    ('the daily window is inclusive of 86,400 s', 'decide.cho', 'if be8(history, 72 * k) > now - 86400 {', 'if be8(history, 72 * k) >= now - 86400 {'),
    ('the daily window is 86,401 s', 'decide.cho', 'if be8(history, 72 * k) > now - 86400 {', 'if be8(history, 72 * k) > now - 86401 {'),
    ('the daily window is 86,399 s', 'decide.cho', 'if be8(history, 72 * k) > now - 86400 {', 'if be8(history, 72 * k) > now - 86399 {'),
    ('the daily total ignores the history', 'decide.cho', 'if be8(history, 72 * k) > now - 86400 {', 'if be8(history, 72 * k) > now + 1 {'),
    ('the daily sum overflow ignored', 'decide.cho', 'if overflow == 1 || policy.cmp32(sum, policy.daily_total(pol)) > 0 {', 'if policy.cmp32(sum, policy.daily_total(pol)) > 0 {'),
    ('the daily total is exclusive', 'decide.cho', 'policy.cmp32(sum, policy.daily_total(pol)) > 0 {', 'policy.cmp32(sum, policy.daily_total(pol)) >= 0 {'),
    ("this intent's amount is not in the daily sum", 'decide.cho', 'sum[j] = amount[j];', 'sum[j] = byte_of(0);'),
    ('the overflow flag is overwritten', 'decide.cho', 'overflow = overflow | add32(', 'overflow = add32('),
    ('the approval threshold is exclusive', 'decide.cho', 'if policy.cmp32(amount, policy.approval_above(pol)) > 0 {', 'if policy.cmp32(amount, policy.approval_above(pol)) >= 0 {'),
    ('the approval threshold ignored', 'decide.cho', 'if policy.cmp32(amount, policy.approval_above(pol)) > 0 {', 'if policy.cmp32(amount, policy.approval_above(pol)) > 99 {'),
    ('approval required counts as a refusal', 'decide.cho', 'if reason == 14 {\n                outcome = 3;', 'if reason == 14 {\n                outcome = 2;'),
    ('a refusal counts as allowed', 'decide.cho', 'if reason == 0 {\n                outcome = 1;', 'if reason < 20 {\n                outcome = 1;'),
    ('record layout byte', 'decide.cho', 'out[0] = byte_of(1);\n            out[1] = byte_of(outcome);', 'out[0] = byte_of(2);\n            out[1] = byte_of(outcome);'),
    ('record reason high byte', 'decide.cho', 'out[2] = byte_of(reason >> 8 & 255);', 'out[2] = byte_of(reason & 255);'),
    ('record reason low byte', 'decide.cho', 'out[3] = byte_of(reason & 255);', 'out[3] = byte_of(reason >> 8 & 255);'),
    ('record intent digest swapped with policy digest', 'decide.cho', 'out[4 + j] = idigest[j];\n                out[36 + j] = pdigest[j];', 'out[4 + j] = pdigest[j];\n                out[36 + j] = idigest[j];'),
    ('record decided_at', 'decide.cho', 'put_be(out, 68, now, 8);', 'put_be(out, 68, now + 1, 8);'),
    ('record expires_at uses the wrong ttl', 'decide.cho', 'expires = now + policy.ttl(policy_c);', 'expires = now + 1;'),
    ('record expires_at for a refusal', 'decide.cho', 'var expires = now;', 'var expires = now + 1;'),
    ('record amount counted for a refusal', 'decide.cho', '                if outcome == 1 {\n                    out[84 + j] = intent.amount(intent_c)[j];', '                if outcome >= 1 {\n                    out[84 + j] = intent.amount(intent_c)[j];'),
    ('record amount counted never', 'decide.cho', '                if outcome == 1 {\n                    out[84 + j] = intent.amount(intent_c)[j];', '                if outcome == 7 {\n                    out[84 + j] = intent.amount(intent_c)[j];'),
    ('record caller length', 'decide.cho', 'out[116] = byte_of(len(caller));', 'out[116] = byte_of(len(caller) + 1);'),
    ('record length', 'decide.cho', 'code = 117 + len(caller);', 'code = 116 + len(caller);'),
    ('decision digest domain', 'decide.cho', 'let s = "cancho-chain/decision/v1";', 'let s = "cancho-chain/decision/v2";'),
    ('decision digest input altered', 'decide.cho', 'm[24 + i] = record[i];', 'm[24 + i] = byte_of(int_of(record[i]) ^ 1);'),
    ('decision digest accepts a short record', 'decide.cho', 'if len(record) < 118 || len(record) > 181 {', 'if len(record) < 10 || len(record) > 181 {'),
    ("the clock's lower bound", 'decide.cho', 'if now < 0 || now > 4611686018427387904 {', 'if now < -1 || now > 4611686018427387904 {'),
    ("the clock's upper bound", 'decide.cho', 'if now < 0 || now > 4611686018427387904 {', 'if now < 0 || now > 4611686018427387905 {'),
    ('the clock is not checked', 'decide.cho', 'if now < 0 || now > 4611686018427387904 {', 'if now < -10 || now > 4611686018427387999 {'),
    ('a history from the future is accepted', 'decide.cho', 'be8(h, 72 * k) > now {', 'be8(h, 72 * k) > now + 1 {'),
    ('a timestamp of 2^63 is accepted', 'decide.cho', 'if int_of(h[72 * k]) >= 128 ||', 'if int_of(h[72 * k]) >= 129 ||'),
    ('a partial history record is accepted', 'decide.cho', 'if len(h) % 72 != 0 {', 'if len(h) % 72 > 71 {'),
    ('an empty caller is accepted', 'decide.cho', 'if len(c) < 1 || len(c) > 64 {', 'if len(c) < 0 || len(c) > 64 {'),
    ('a 65-byte caller is accepted', 'decide.cho', 'if len(c) < 1 || len(c) > 64 {', 'if len(c) < 1 || len(c) > 65 {'),
    ('caller characters not checked', 'decide.cho', 'if !intent.word_char(int_of(c[i])) {', 'if false {'),
    ("the intent's layout byte not checked", 'decide.cho', 'int_of(c[0]) != 1 || int_of(c[1]) != 1 {', 'int_of(c[1]) != 1 {'),
    ("the intent's kind byte not checked", 'decide.cho', 'int_of(c[0]) != 1 || int_of(c[1]) != 1 {', 'int_of(c[0]) != 1 {'),
    ("the intent's lengths not checked", 'decide.cho', 'return ql >= 1 && ql <= 64 && 83 + rl + 1 + ql == len(c);', 'return ql >= 1 && ql <= 64;'),
    ('an empty reference is accepted', 'decide.cho', 'if rl < 1 || rl > 64 || 83 + rl + 1 > len(c) {', 'if rl < 0 || rl > 64 || 83 + rl + 1 > len(c) {'),
    ('the output limit', 'decide.cho', 'if len(out) < 181 {\n        return -234;', 'if len(out) < 100 {\n        return -234;'),
    ('the working space limit', 'decide.cho', 'if len(st) < 110 {\n        return -235;', 'if len(st) < 50 {\n        return -235;'),
    ('a malformed policy is accepted', 'decide.cho', 'if !policy.well_formed(policy_c) {', 'if false {'),
    ('a malformed intent is accepted', 'decide.cho', 'if !intent_ok(intent_c) {', 'if false {'),
    ('a bad history is accepted', 'decide.cho', 'if !history_ok(history, now) {', 'if false {'),
    ('the policy size limit', 'policy.cho', 'if len(body) > 8192 {\n        return -227;', 'if len(body) > 8193 {\n        return -227;'),
    ('the policy output limit', 'policy.cho', 'if len(out) < 1024 {\n        return -228;', 'if len(out) < 1000 {\n        return -228;'),
    ('the policy working space limit', 'policy.cho', 'if len(st) < 110 {\n        return -229;', 'if len(st) < 50 {\n        return -229;'),
    ('version lower bound', 'policy.cho', 'schema.new_int(heap, s7, 1, 4294967295)', 'schema.new_int(heap, s7, 0, 4294967295)'),
    ('version upper bound', 'policy.cho', 'schema.new_int(heap, s7, 1, 4294967295)', 'schema.new_int(heap, s7, 1, 4294967296)'),
    ('ttl lower bound', 'policy.cho', 'schema.new_int(heap, s6, 1, 3600)', 'schema.new_int(heap, s6, 0, 3600)'),
    ('ttl upper bound', 'policy.cho', 'schema.new_int(heap, s6, 1, 3600)', 'schema.new_int(heap, s6, 1, 3601)'),
    ('decimals upper bound', 'policy.cho', 'schema.new_int(heap, s3, 0, 36)', 'schema.new_int(heap, s3, 0, 37)'),
    ('gas limit may be zero', 'policy.cho', 'schema.new_int(heap, s4, 1, 9007199254740991)', 'schema.new_int(heap, s4, 0, 9007199254740991)'),
    ('not_before may be negative', 'policy.cho', 'schema.new_int(heap, s5, 0, 9007199254740991)', 'schema.new_int(heap, s5, -1, 9007199254740991)'),
    ('operations may be empty', 'policy.cho', 'schema.new_array(heap, s10, op, 1, 1)', 'schema.new_array(heap, s10, op, 0, 1)'),
    ('operations may be two', 'policy.cho', 'schema.new_array(heap, s10, op, 1, 1)', 'schema.new_array(heap, s10, op, 1, 2)'),
    ('recipients may be empty', 'policy.cho', 'schema.new_array(heap, s11, address, 1, 32)', 'schema.new_array(heap, s11, address, 0, 32)'),
    ('recipients up to 33', 'policy.cho', 'schema.new_array(heap, s11, address, 1, 32)', 'schema.new_array(heap, s11, address, 1, 33)'),
    ('the asset object is not strict', 'policy.cho', 'schema.new_object(heap, s12, true)', 'schema.new_object(heap, s12, false)'),
    ('the limits object is not strict', 'policy.cho', 'schema.new_object(heap, s13, true)', 'schema.new_object(heap, s13, false)'),
    ('the policy object is not strict', 'policy.cho', 'schema.new_object(heap, s16, true)', 'schema.new_object(heap, s16, false)'),
    ('the approval threshold is required', 'policy.cho', '"approval_required_above", amount, false)', '"approval_required_above", amount, true)'),
    ('the gas limit is not required', 'policy.cho', '"gas_limit", count, true)', '"gas_limit", count, false)'),
    ('the principal is not required', 'policy.cho', '"principal", text, true)', '"principal", text, false)'),
    ('duplicate recipients accepted', 'policy.cho', 'if bytes.equal(out[at..at + 20], out[at - 20 * (i - k)..at - 20 * (i - k) + 20]) {', 'if bytes.equal(out[at..at + 20], out[at - 20 * (i - k)..at - 20 * (i - k) + 20]) && false {'),
    ('only adjacent duplicate recipients are found', 'policy.cho', '        var k = 0;\n        while k < i {', '        var k = i - 1;\n        while k < i && k >= 0 {'),
    ('per-transaction above daily accepted', 'policy.cho', 'if cmp32(out[per..per + 32], out[daily..daily + 32]) > 0 {', 'if cmp32(out[per..per + 32], out[daily..daily + 32]) > 1 {'),
    ('per-transaction equal to daily refused', 'policy.cho', 'if cmp32(out[per..per + 32], out[daily..daily + 32]) > 0 {', 'if cmp32(out[per..per + 32], out[daily..daily + 32]) >= 0 {'),
    ('approval above per-transaction accepted', 'policy.cho', 'slots[4] >= 0 && cmp32(out[approval..approval + 32], out[per..per + 32]) > 0 {', 'slots[4] >= 0 && cmp32(out[approval..approval + 32], out[per..per + 32]) > 1 {'),
    ('approval equal to per-transaction refused', 'policy.cho', 'slots[4] >= 0 && cmp32(out[approval..approval + 32], out[per..per + 32]) > 0 {', 'slots[4] >= 0 && cmp32(out[approval..approval + 32], out[per..per + 32]) >= 0 {'),
    ('an absent approval threshold is compared', 'policy.cho', 'slots[4] >= 0 && cmp32(', 'cmp32('),
    ('an empty validity window accepted', 'policy.cho', 'if not_after <= not_before {', 'if not_after < not_before {'),
    ('a reversed validity window accepted', 'policy.cho', 'if not_after <= not_before {', 'if not_after < 0 {'),
    ('an absent approval threshold is not the maximum', 'policy.cho', 'out[at + i] = byte_of(255);', 'out[at + i] = byte_of(254);'),
    ('the operations byte', 'policy.cho', 'out[at + 1] = byte_of(1);', 'out[at + 1] = byte_of(2);'),
    ('the policy layout byte', 'policy.cho', 'out[0] = byte_of(1);\n    if !intent.is_word(body, tape, slots[9]) {', 'out[0] = byte_of(2);\n    if !intent.is_word(body, tape, slots[9]) {'),
    ('the policy id not checked', 'policy.cho', 'if !intent.is_word(body, tape, slots[9]) {', 'if false {'),
    ('the principal not checked', 'policy.cho', 'if !intent.is_word(body, tape, slots[11]) {', 'if false {'),
    ('a float version accepted', 'policy.cho', 'let version = int_field(body, tape, slots[10]);\n    if version < 0 {', 'let version = json.to_int(body, tape, slots[10]);\n    if version < 0 {'),
    ('a float chain id accepted', 'policy.cho', 'let chain = int_field(body, tape, slots[12]);', 'let chain = json.to_int(body, tape, slots[12]);'),
    ('a float ttl accepted', 'policy.cho', 'let ttl = int_field(body, tape, slots[19]);', 'let ttl = json.to_int(body, tape, slots[19]);'),
    ('a float gas limit accepted', 'policy.cho', 'let gas = int_field(body, tape, slots[6]);', 'let gas = json.to_int(body, tape, slots[6]);'),
    ('a float not_before accepted', 'policy.cho', 'let not_before = int_field(body, tape, slots[7]);', 'let not_before = json.to_int(body, tape, slots[7]);'),
    ('a float not_after accepted', 'policy.cho', 'let not_after = int_field(body, tape, slots[8]);', 'let not_after = json.to_int(body, tape, slots[8]);'),
    ('a float decimals accepted', 'policy.cho', 'let decimals = int_field(body, tape, slots[1]);', 'let decimals = json.to_int(body, tape, slots[1]);'),
    ('duplicate keys accepted', 'policy.cho', 'if bytes.equal(json.string_view(body, tape, j), json.string_view(body, tape, k)) {\n                return -225;', 'if bytes.equal(json.string_view(body, tape, j), json.string_view(body, tape, k)) && false {\n                return -225;'),
    ('nested objects are not scanned for keys', 'policy.cho', 'if json.is_object(tape, j + 1) {', 'if json.is_object(tape, j + 1) && false {'),
    ('escaped outer keys accepted', 'policy.cho', '        if !json.string_plain(tape, j) {\n            return -225;\n        }\n        var k', '        if !json.string_plain(tape, j) && false {\n            return -225;\n        }\n        var k'),
    ('escaped later keys accepted', 'policy.cho', '            if !json.string_plain(tape, k) {\n                return -225;', '            if !json.string_plain(tape, k) && false {\n                return -225;'),
    ('the version accessor', 'policy.cho', 'v = v * 256 + int_of(c[o_version(c) + i]);', 'v = v * 256 + int_of(c[o_version(c) + i + 1]);'),
    ('the operations offset', 'policy.cho', 'return o_asset(c) + 21;', 'return o_asset(c) + 20;'),
    ('the daily limit offset', 'policy.cho', 'let at = o_limits(c) + 32;\n    return c[at..at + 32];\n}\n\n// The amount above', 'let at = o_limits(c) + 31;\n    return c[at..at + 32];\n}\n\n// The amount above'),
    ('well_formed: the layout byte', 'policy.cho', 'int_of(c[0]) != 1 {\n        return false;', 'int_of(c[0]) != 9 {\n        return false;'),
    ('well_formed: recipients up to 33', 'policy.cho', 'if n < 1 || n > 32 {', 'if n < 1 || n > 33 {'),
    ('well_formed: no recipients', 'policy.cho', 'if n < 1 || n > 32 {', 'if n < 0 || n > 32 {'),
    ('well_formed: the total length', 'policy.cho', 'return o_end(c) == len(c);', 'return o_end(c) <= len(c);'),
    ('well_formed: an empty id', 'policy.cho', 'if pl < 1 || pl > 64 ||', 'if pl < 0 || pl > 64 ||'),
    ('well_formed: a 65-byte id', 'policy.cho', 'if pl < 1 || pl > 64 ||', 'if pl < 1 || pl > 65 ||'),
    ('the policy digest domain', 'policy.cho', 'let s = "cancho-chain/policy/v1";', 'let s = "cancho-chain/policy/v2";'),
    ('the policy digest input altered', 'policy.cho', 'm[22 + i] = canonical[i];', 'm[22 + i] = byte_of(int_of(canonical[i]) ^ 1);'),
]


def one_mutant(cancho, cases, entry):
    name, fname, old, new = entry
    d = tempfile.mkdtemp()
    try:
        os.makedirs(f"{d}/lib/policy")
        for f in ("policy.cho", "decide.cho"):
            shutil.copy(os.path.join(ROOT, "lib/policy", f), f"{d}/lib/policy/{f}")
        p = f"{d}/lib/policy/{fname}"
        text = open(p).read()
        if text.count(old) != 1:
            return name, "BAD", f"mutant pattern not unique ({text.count(old)})"
        open(p, "w").write(text.replace(old, new))
        exe = f"{d}/pol"
        r = subprocess.run([cancho, "build", "--std", *srcs(f"{d}/lib"), "-o", exe], capture_output=True, text=True)
        if r.returncode != 0:
            return name, "NOBUILD", r.stderr[:300]
        bad, total = run(exe, cases, quiet=True)
        return name, ("KILLED" if bad else "SURVIVED"), f"{bad}/{total}"
    finally:
        shutil.rmtree(d)


def mutants(cancho, cases):
    from concurrent.futures import ThreadPoolExecutor
    workers = int(os.environ.get("MUTANT_WORKERS", "4"))
    survived = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for name, status, detail in pool.map(lambda e: one_mutant(cancho, cases, e), MUTANTS):
            if status == "SURVIVED" and name in EXPECTED_SURVIVORS:
                print(f"mutant '{name}': SURVIVED, expected: {EXPECTED_SURVIVORS[name]}")
                continue
            print(f"mutant '{name}': {status} ({detail})")
            survived += 0 if status == "KILLED" else 1
    return survived


def main():
    cancho = os.environ.get("CANCHO", "cancho")
    cases = int(sys.argv[sys.argv.index("--cases") + 1]) if "--cases" in sys.argv else 20
    d = tempfile.mkdtemp()
    try:
        exe = os.path.join(d, "pol")
        build(cancho, os.path.join(ROOT, "lib"), exe)
        bad, total = run(exe, cases)
        print(f"policy: {total - bad}/{total} checks agree with the model and jsonschema")
        if bad:
            sys.exit(1)
        if "--mutants" in sys.argv:
            s = mutants(cancho, max(3, cases // 5))
            print(f"mutants: {len(MUTANTS) - s - len(EXPECTED_SURVIVORS)}/{len(MUTANTS)} killed, {len(EXPECTED_SURVIVORS)} equivalent (above), {s} unexpected survivors")
            if s:
                sys.exit(1)
    finally:
        shutil.rmtree(d)


main()
