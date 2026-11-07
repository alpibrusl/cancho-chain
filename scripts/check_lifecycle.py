#!/usr/bin/env python3
"""The lifecycle machine against a model, exhaustively, against its properties, and on random walks through a world with a lying provider (docs/design.md section 17.5).

    CANCHO=the-compiler python3 -I scripts/check_lifecycle.py [--mutants] [--walks N]

(1) `check` against a model of "canonical", on every state and on every single-byte spoiling of a record; (2) `after_send` on every state, outcome and time; (3) `observe` over the full product of every state,
every observation shape around the finality edge and both windows and every nonce relation: the result equals the model's, and **each property of section 17.4 holds of the result, written as a predicate**;
(4) random walks: a world with a chain that advances and reorganises, a mempool that forgets, an account whose nonce another transaction can take, and, at each step, at most one of two providers lying;
at every step every property holds, and the machine is never FINAL unless the truth says so; honest worlds reach their end. --mutants: one deliberate fault at a time in lib/lifecycle/lifecycle.cho.
"""
import concurrent.futures, itertools, os, random, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAILS, COUNT = [], [0]
NAMES = {1: "SIGNED", 2: "SUBMITTED", 3: "UNCERTAIN", 4: "INCLUDED", 5: "REVERTED", 6: "FINAL", 7: "FAILED_FINAL", 8: "REPLACED", 9: "DROPPED"}
TERMINAL = (6, 7, 8)
IN_BLOCK = (4, 5, 6, 7)


def check(name, got, want=True):
    COUNT[0] += 1
    if got != want:
        FAILS.append(name)
        if len(FAILS) <= 15:
            print(f"FAIL {name}: got {got!r}, want {want!r}")


def srcs(libdir):
    return [os.path.join(ROOT, "tools/lifedrv/main.cho"), os.path.join(libdir, "lifecycle/lifecycle.cho"), os.path.join(ROOT, "lib/eth/hex.cho")]


def build(cancho, libdir, out):
    r = subprocess.run([cancho, "build", "--std", *srcs(libdir), "-o", out], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("build failed:\n" + r.stderr[:1500])


def batch(exe, lines):
    p = subprocess.run([exe], input=("\n".join(lines) + "\n").encode(), capture_output=True, timeout=3000)
    out = p.stdout.decode().split("\n")[:-1]
    if len(out) != len(lines):
        raise SystemExit(f"the driver answered {len(out)} lines to {len(lines)} (it crashed: exit {p.returncode})")
    return out


def hx(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b.hex() if b else "_"


# ---- the model: records as dicts, and the rules as an ordered list evaluated on a dictionary of facts
def pack(r):
    return bytes([1, r["state"]]) + r["nonce"].to_bytes(8, "big") + r["sent"].to_bytes(8, "big") + r["changed"].to_bytes(8, "big") + r["consumed"].to_bytes(8, "big") + r["block"].to_bytes(8, "big") + r["bh"]


def unpack(b):
    return {"state": b[1], "nonce": int.from_bytes(b[2:10], "big"), "sent": int.from_bytes(b[10:18], "big"), "changed": int.from_bytes(b[18:26], "big"),
            "consumed": int.from_bytes(b[26:34], "big"), "block": int.from_bytes(b[34:42], "big"), "bh": b[42:74]}


def canonical(b):
    if len(b) != 74 or b[0] != 1 or not 1 <= b[1] <= 9:
        return False
    if any(b[2 + 8 * k] >= 128 for k in range(5)):
        return False
    r = unpack(b)
    zero = bytes(32)
    if r["state"] in IN_BLOCK:
        if r["bh"] == zero:
            return False
    elif r["block"] != 0 or r["bh"] != zero:
        return False
    if r["consumed"] != 0 and r["state"] not in (2, 3, 9):
        return False
    return True


class Refused(Exception):
    def __init__(self, code):
        self.code = code


def model_send(r, ok, now):
    if r["state"] not in (1, 2, 3, 9):
        raise Refused(322)
    r = dict(r, sent=now, consumed=0)
    new = 2 if ok else 3
    if r["state"] != new:
        r["state"], r["changed"] = new, now
    return r


def model_observe(r, o, cfg):
    """(record, action). A rule is (applies?, effect); the first that applies decides."""
    k, drop, settle = cfg
    if o["tx"] > 2 or o["tip"] < 0 or k < 1 or (o["tx"] == 2 and o["tip"] < o["block"]):
        raise Refused(321)
    now, n = o["now"], r["nonce"]
    facts = dict(terminal=r["state"] in TERMINAL, agree=o["agree"], state=r["state"], consumed=o["nonce_latest"] > n)

    def mined(r):
        want = 4 if o["status_ok"] else 5
        r = dict(r, consumed=0)
        if not (r["state"] == want and r["block"] == o["block"] and r["bh"] == o["bh"]):
            r.update(state=want, block=o["block"], bh=o["bh"], changed=now)
        if o["tip"] - o["block"] + 1 >= k and o["hash_known"] and o["hash_at"] == o["bh"]:
            fin = 6 if o["status_ok"] else 7
            if r["state"] != fin:
                r.update(state=fin, changed=now)
        return r, 0

    def pending(r):
        r = dict(r, consumed=0, block=0, bh=bytes(32))
        if r["state"] != 2:
            r.update(state=2, changed=now)
        return r, 0

    def absent(r):
        action = 0
        vanished = r["state"] in (4, 5)
        if vanished:
            r.update(block=0, bh=bytes(32), state=3, changed=now)
        if facts["consumed"]:
            if r["consumed"] == 0:
                r["consumed"] = now
            if now - r["consumed"] >= settle and not vanished:
                r.update(state=8, changed=now, consumed=0)
            return r, 0
        r["consumed"] = 0
        if vanished or r["state"] == 9:
            return r, 2
        if now - r["sent"] >= drop:
            r.update(state=9, changed=now)
            return r, 2
        return r, 0

    rules = [
        (lambda: not facts["agree"], lambda r: (r, 0)),
        (lambda: facts["terminal"], lambda r: (r, 0)),
        (lambda: o["tx"] == 2, mined),
        (lambda: o["tx"] == 1, pending),
        (lambda: o["tx"] == 0 and facts["state"] == 1, lambda r: (r, 1)),
        (lambda: o["tx"] == 0, absent),
    ]
    for applies, effect in rules:
        if applies():
            return effect(dict(r))
    raise AssertionError("no rule applies")


def properties(r, o, cfg, r2, action):
    """The properties of section 17.4, as predicates. Answers the names of those that fail."""
    k, drop, settle = cfg
    bad = []
    s, s2 = r["state"], r2["state"]
    if not canonical(pack(r2)):
        bad.append("P7 the record written is canonical")
    if s in TERMINAL and (r2 != r or action != 0):
        bad.append("P1 a terminal state is fixed")
    if not o["agree"] and (r2 != r or action != 0):
        bad.append("P2 a disagreement changes nothing")
    if s not in TERMINAL and o["agree"]:
        final_cond = o["tx"] == 2 and o["tip"] - o["block"] + 1 >= k and o["hash_known"] and o["hash_at"] == o["bh"]
        if (s2 in (6, 7)) != (final_cond or s2 in (6, 7) and s in (6, 7)):
            bad.append("P3 final iff mined, enough confirmations and the same block")
        if final_cond and s2 != (6 if o["status_ok"] else 7):
            bad.append("P3b final of the right kind")
    if s2 in IN_BLOCK and (s2 != s or r2["block"] != r["block"] or r2["bh"] != r["bh"]) and not (o["agree"] and o["tx"] == 2):
        bad.append("P4 in a block only from a mined observation")
    if s2 == 8 and s != 8:
        since = r["consumed"] if r["consumed"] != 0 else o["now"]  # the first sight counts only when `settle` is 0
        if not (o["agree"] and o["tx"] == 0 and o["nonce_latest"] > r["nonce"] and o["now"] - since >= settle and s in (2, 3, 9)):
            bad.append("P5 replaced only after a consumed nonce stayed consumed")
    if action == 1 and not (s == 1 and o["tx"] == 0 and o["agree"]):
        bad.append("P6a submit only from signed")
    if action == 2 and not (o["tx"] == 0 and o["agree"] and o["nonce_latest"] <= r["nonce"] and s != 1):
        bad.append("P6b resubmit only for an absent transaction and an unused nonce")
    if r2["consumed"] != 0 and (o["agree"] and s not in TERMINAL):
        if not (o["tx"] == 0 and o["nonce_latest"] > r["nonce"] and s2 in (2, 3, 9)):
            bad.append("P8a consumed only for a consumed nonce and an absent transaction")
        elif r2["consumed"] != (r["consumed"] if r["consumed"] != 0 and s in (2, 3, 9) else o["now"]):
            bad.append("P8b consumed_at is when it was first seen")
    moved = s2 != s or r2["block"] != r["block"] or r2["bh"] != r["bh"]
    if (r2["changed"] == o["now"] and r["changed"] != o["now"]) != moved and r2["changed"] != r["changed"]:
        bad.append("P9 changed_at moves with a change")
    if not moved and r2["changed"] != r["changed"]:
        bad.append("P9b changed_at is still when nothing changed")
    if r2["sent"] != r["sent"] or r2["nonce"] != r["nonce"]:
        bad.append("P10 sent_at and nonce are not touched by an observation")
    return bad


def obs_line(rec, o, cfg):
    return " ".join(["O", pack(rec).hex(), hx(int(o["agree"])), hx(o["tx"]), hx(int(o["status_ok"])), hx(o["block"]), o["bh"].hex(), hx(o["tip"]), hx(int(o["hash_known"])), o["hash_at"].hex(),
                     hx(o["nonce_latest"]), hx(o["now"]), hx(cfg[0]), hx(cfg[1]), hx(cfg[2])])


def parse_result(line):
    p = line.split()
    if p[0].startswith("E"):
        return ("refused", int(p[0][1:]))
    if len(p) == 2:
        return ("ok", 0, bytes.fromhex(p[1]))  # `S` answers no action
    return ("ok", int(p[1]), bytes.fromhex(p[2]))


H1, H2, H0 = bytes([1]) * 32, bytes([2]) * 32, bytes(32)
CFG = (3, 100, 50)


def records(nonce=7):
    out = []
    for s in range(1, 10):
        for consumed in ((0, 1100) if s in (2, 3, 9) else (0,)):
            r = {"state": s, "nonce": nonce, "sent": 1000, "changed": 1030, "consumed": consumed, "block": 5 if s in IN_BLOCK else 0, "bh": H1 if s in IN_BLOCK else H0}
            out.append(r)
    return out


def run(exe, walks):
    # (1) check: the model's canonical, on every record and every single-byte spoiling
    lines, want = [], []
    for r in records():
        b = pack(r)
        cands = [b]
        for at in range(74):
            for v in (0x00, 0x01, 0x80, 0xFF, 0x09, 0x0A):
                if b[at] != v:
                    cands.append(b[:at] + bytes([v]) + b[at + 1:])
        cands += [b[:-1], b + b"\0", b"", b[:42] + bytes(32), b[:34] + bytes(8) + b[42:]]
        for c in cands:
            lines.append("C " + (c.hex() if c else "_"))
            want.append(canonical(c))
    for line, w, in zip(batch(exe, lines), want):
        pass
    got = batch(exe, lines)
    bad = [(l[:30], g) for l, g, w in zip(lines, got, want) if (g == "0") != w]
    check(f"check: {len(lines)} records and spoilings agree with the model's canonical form: {bad[:3]}", len(bad), 0)
    # (2) after_send
    lines, want = [], []
    for r in records():
        for ok in (True, False):
            for now in (0, 1000, 1001, 5000):
                lines.append(f"S {pack(r).hex()} {hx(int(ok))} {hx(now)}")
                try:
                    want.append(("ok", pack(model_send(r, ok, now))))
                except Refused as e:
                    want.append(("refused", e.code))
    bad = []
    for line, w, g in zip(lines, want, batch(exe, lines)):
        p = parse_result(g)
        if (p[0], p[-1]) != (w[0], w[1]):
            bad.append((line[:20], g[:30], w[0]))
    check(f"after_send: {len(lines)} cases agree with the model: {bad[:3]}", len(bad), 0)
    for r in records():
        s = r["state"]
        if s in (1, 2, 3, 9):
            for ok in (True, False):
                res = model_send(r, ok, 5000)
                check(f"after_send from {NAMES[s]} is never into a block or an end", res["state"] in (2, 3), True)
        else:
            check(f"after_send from {NAMES[s]} is refused", batch(exe, [f"S {pack(r).hex()} 01 {hx(5000)}"])[0], "E322")
    check("after_send of a spoiled record is E320", batch(exe, ["S " + pack(records()[0])[:-1].hex() + " 01 07"])[0], "E320")
    check("new: the record is signed, at that time and nonce", batch(exe, ["N 07 64"])[0], "0 " + pack({"state": 1, "nonce": 7, "sent": 0, "changed": 100, "consumed": 0, "block": 0, "bh": H0}).hex())
    check("new: a nonce that is not given is 0", batch(exe, ["N _ 64"])[0].split()[0], "0")
    # (3) observe: the full product
    lines, cases = [], []
    for cfg, r in itertools.product(((3, 100, 50), (1, 0, 0)), records()):
        n = r["nonce"]
        for agree in (True, False):
            for tx in (0, 1, 2):
                if tx == 2:
                    shapes = [(st, blk, bh, tip, hk, hat) for st in (True, False) for blk in (4, 5, 6) for bh in (H1, H2) for tip in (blk - 1, blk, blk + cfg[0] - 2, blk + cfg[0] - 1, blk + cfg[0]) for hk in (True, False)
                              for hat in (H1, H2) if tip >= 0]
                else:
                    shapes = [(True, 0, H0, 5, False, H0)]
                for (st, blk, bh, tip, hk, hat) in shapes:
                    for nl in (n - 1, n, n + 1):
                        for now in (1000, 1099, 1100, 1149, 1150, 1200):
                            o = dict(agree=agree, tx=tx, status_ok=st, block=blk, bh=bh, tip=tip, hash_known=hk, hash_at=hat, nonce_latest=nl, now=now)
                            lines.append(obs_line(r, o, cfg))
                            cases.append((r, o, cfg))
    answers = batch(exe, lines)
    bad_model, bad_props = [], {}
    for (r, o, cfg), line, g in zip(cases, lines, answers):
        p = parse_result(g)
        try:
            r2, action = model_observe(r, o, cfg)
            w = ("ok", action, pack(r2))
        except Refused as e:
            w = ("refused", e.code)
            r2 = None
        if p != w:
            bad_model.append((NAMES[r["state"]], o["tx"], g[:40], w[:2]))
            continue
        if r2 is not None:
            for name in properties(r, o, cfg, r2, action):
                bad_props.setdefault(name, []).append((NAMES[r["state"]], o))
    print(f"  ({len(lines)} observations in the full product, {len(records())} records, {len(set(c[0]['state'] for c in cases))} states)")
    check(f"observe: {len(lines)} cases of the full product equal the model's answer: {bad_model[:3]}", len(bad_model), 0)
    check(f"observe: every property of section 17.4 holds on all of them: {[(k, v[0]) for k, v in list(bad_props.items())[:2]]}", len(bad_props), 0)
    # the refused observations
    r = records()[1]
    base = dict(agree=True, tx=1, status_ok=True, block=0, bh=H0, tip=0, hash_known=False, hash_at=H0, nonce_latest=7, now=2000)
    for name, over in (("tx 3", dict(tx=3)), ("a mined one below its block", dict(tx=2, block=5, tip=4, bh=H1)), ("a short block hash", dict(bh=b"\1" * 31)), ("a short hash at", dict(hash_at=b"\1" * 31))):
        o = dict(base, **over)
        line = obs_line(r, o, CFG)
        check("observe refuses " + name, batch(exe, [line])[0], "E321")
    for name, cfg in (("k of 0", (0, 100, 50)),):
        check("observe refuses " + name, batch(exe, [obs_line(r, base, cfg)])[0], "E321")
    check("observe refuses a spoiled record", batch(exe, [obs_line(r, base, CFG).replace(pack(r).hex(), pack(r)[:-1].hex() + "00" if False else "ff" + pack(r).hex()[2:], 1)])[0], "E320")
    # (4) random walks through a world
    wrng = random.Random(8080)
    for w in range(walks):
        walk(exe, wrng, honest=(w % 3 == 0), mode=("replaced" if w % 5 == 4 else "mined"))


class World:
    """The truth: a chain that advances and reorganises, a mempool, an account's nonce. Providers answer from it; at most one lies at a time."""

    def __init__(self, rng, nonce, mode, honest):
        self.rng, self.nonce, self.mode, self.honest = rng, nonce, mode, honest
        self.t = 1000
        self.tip = 100
        self.epoch = 0
        self.in_pool = False
        self.mined_at = None      # block number, or None
        self.status = 1 if rng.random() < 0.8 else 0
        self.other_took_nonce = False
        self.latest = nonce
        self.forgets = rng.random() < 0.3

    def bh(self, height):
        return bytes([(height * 7 + self.epoch * 13) % 251 + 1]) * 32

    def send(self):
        if self.mode != "replaced" and not self.other_took_nonce:
            self.in_pool = True
            return True
        return self.rng.random() < 0.3

    def tick(self):
        self.t += self.rng.choice((5, 10, 40, 60, 120))
        self.tip += self.rng.choice((0, 1, 1, 2))
        if self.mode == "replaced" and self.tip > 104:
            self.other_took_nonce = True
            self.latest = self.nonce + 1
            self.in_pool = False
            self.mined_at = None
            return
        if self.in_pool and self.mined_at is None and self.rng.random() < 0.4:
            self.mined_at = self.tip
            self.latest = self.nonce + 1
            self.in_pool = False
        elif self.mined_at is not None and self.rng.random() < 0.08 and self.tip - self.mined_at < CFG[0] - 1 and not self.honest_world_no_reorg():
            self.epoch += 1            # a reorganisation, shallower than k: the block is replaced, the transaction goes back to the pool (or is forgotten)
            self.mined_at = None
            self.latest = self.nonce
            self.in_pool = not self.forgets
        elif self.in_pool and self.forgets and self.rng.random() < 0.1:
            self.in_pool = False

    def honest_world_no_reorg(self):
        return False

    def view(self):
        """What an honest provider says."""
        tx = 2 if self.mined_at is not None else (1 if self.in_pool else 0)
        v = {"tx": tx, "status_ok": bool(self.status), "block": self.mined_at or 0, "bh": self.bh(self.mined_at) if self.mined_at else H0, "tip": self.tip,
             "nonce_latest": self.latest, "hash_known": self.mined_at is not None, "hash_at": self.bh(self.mined_at) if self.mined_at else H0}
        return v

    def lie(self, v):
        v = dict(v)
        kind = self.rng.choice(("none", "pending", "mined", "stale_tip", "nonce", "wrong_hash"))
        if kind == "none":
            v.update(tx=0, block=0, bh=H0, hash_known=False, hash_at=H0)
        elif kind == "pending":
            v.update(tx=1, block=0, bh=H0, hash_known=False, hash_at=H0)
        elif kind == "mined":
            b = max(1, v["tip"] - self.rng.randrange(0, 20))
            v.update(tx=2, block=b, bh=bytes([200]) * 32, hash_known=True, hash_at=bytes([200]) * 32, status_ok=True)
        elif kind == "stale_tip":
            v["tip"] = max(0, v["tip"] - self.rng.randrange(1, 30))
        elif kind == "nonce":
            v["nonce_latest"] = v["nonce_latest"] + self.rng.choice((-1, 1))
        else:
            v["hash_at"] = bytes([201]) * 32
        return v

    def observe(self):
        a = self.view()
        b = dict(a)
        if not self.honest and self.rng.random() < 0.35:
            if self.rng.random() < 0.5:
                a = self.lie(a)
            else:
                b = self.lie(b)
        keys = ("tx", "status_ok", "block", "bh", "nonce_latest", "hash_known", "hash_at")
        agree = all(a[k] == b[k] for k in keys)
        o = dict(a, agree=agree, tip=min(a["tip"], b["tip"]), now=self.t)
        if o["tx"] == 2 and o["tip"] < o["block"]:
            o["tip"] = o["block"]
        return o


def walk(exe, rng, honest, mode):
    w = World(rng, rng.randrange(0, 50), mode, honest)
    rec = bytes.fromhex(batch(exe, [f"N {hx(w.nonce)} {hx(w.t)}"])[0].split()[1])
    steps = 0
    sent = 0
    final_ok = False
    for step in range(120):
        steps += 1
        o = w.observe()
        line = obs_line(unpack(rec), o, CFG)
        g = parse_result(batch(exe, [line])[0])
        if g[0] != "ok":
            check(f"walk: an observation of the world is never refused ({g})", False, True)
            return
        r, r2 = unpack(rec), unpack(g[2])
        for name in properties(r, o, CFG, r2, g[1]):
            check(f"walk: {name}", False, True)
        COUNT[0] += 1
        s2 = r2["state"]
        # the safety claim: with at most one provider lying, FINAL is the truth
        if s2 in (6, 7) and r["state"] not in (6, 7):
            truth = w.view()
            if not (truth["tx"] == 2 and truth["tip"] - truth["block"] + 1 >= CFG[0] and bool(w.status) == (s2 == 6)):
                check("walk: FINAL while the truth says otherwise", False, True)
        if s2 == 8 and r["state"] != 8:
            if w.latest <= w.nonce or w.mined_at is not None or w.in_pool:
                check("walk: REPLACED while the truth says otherwise", False, True)
        rec = g[2]
        action = g[1]
        if action in (1, 2):
            ok = w.send()
            sent += 1
            res = batch(exe, [f"S {rec.hex()} {hx(int(ok))} {hx(w.t)}"])[0]
            p = parse_result(res)
            if p[0] != "ok":
                check(f"walk: a send of a signed or submitted transaction is accepted ({res})", False, True)
                return
            rec = p[2]
        if s2 in TERMINAL:
            break
        w.tick()
    state = unpack(rec)["state"]
    if honest and mode == "mined":
        final_ok = state in (6, 7)
        check("walk: an honest world's transaction reaches its end", final_ok, True)
    if honest and mode == "replaced":
        check("walk: a transaction whose nonce another took is REPLACED in an honest world", state, 8)
    check("walk: it is never submitted more than a handful of times in a world with no loss of it", sent <= 8 or w.forgets or mode == "replaced", True)


MUTANTS = [
    ("be8: the base", "v = v * 256 + int_of(c[at + i]);", "v = v * 255 + int_of(c[at + i]);"),
    ("put_be8: the shift", "out[at + i] = byte_of(v >> 8 * (7 - i) & 255);", "out[at + i] = byte_of(v >> 8 * i & 255);"),
    ("in_block: the top", "return s >= 4 && s <= 7;", "return s >= 4 && s <= 8;"),
    ("in_block: the bottom", "return s >= 4 && s <= 7;", "return s >= 3 && s <= 7;"),
    ("hash_zero: the last byte", "var i = 42;\n    while i < 74 {\n        if int_of(rec[i]) != 0 {", "var i = 42;\n    while i < 73 {\n        if int_of(rec[i]) != 0 {"),
    ("hash_zero: the first byte", "var i = 42;\n    while i < 74 {\n        if int_of(rec[i]) != 0 {", "var i = 43;\n    while i < 74 {\n        if int_of(rec[i]) != 0 {"),
    ("new: a nonce below zero", "if len(out) != 74 || nonce < 0 || now < 0 {", "if len(out) != 74 || now < 0 {"),
    ("new: the nonce's offset", "put_be8(out, 2, nonce);", "put_be8(out, 10, nonce);"),
    ("new: the time's offset", "put_be8(out, 18, now);\n    return 0;", "put_be8(out, 10, now);\n    return 0;"),
    ("new: the state", "out[1] = byte_of(1);", "out[1] = byte_of(2);"),
    ("check: the length", "if len(rec) != 74 || int_of(rec[0]) != 1 {", "if len(rec) < 74 || int_of(rec[0]) != 1 {"),
    ("check: the version", "if len(rec) != 74 || int_of(rec[0]) != 1 {", "if len(rec) != 74 {"),
    ("check: state 0", "if s < 1 || s > 9 {", "if s < 0 || s > 9 {"),
    ("check: state 10", "if s < 1 || s > 9 {", "if s < 1 || s > 10 {"),
    ("check: the last integer's top bit", "while k < 5 {", "while k < 4 {"),
    ("check: the top bit", "if int_of(rec[2 + 8 * k]) >= 128 {", "if int_of(rec[2 + 8 * k]) >= 129 {"),
    ("check: a hash on a state in a block", "if in_block(s) {\n        if hash_zero(rec) {", "if in_block(s) {\n        if false {"),
    ("check: a block on another state", "} else if be8(rec, 34) != 0 || !hash_zero(rec) {", "} else if !hash_zero(rec) {"),
    ("check: a hash on another state", "} else if be8(rec, 34) != 0 || !hash_zero(rec) {", "} else if be8(rec, 34) != 0 {"),
    ("check: consumed_at on a state that cannot", "if be8(rec, 26) != 0 && !(s == 2 || s == 3 || s == 9) {", "if be8(rec, 26) != 0 && !(s == 2 || s == 3 || s == 9 || s == 1) {"),
    ("check: consumed_at on dropped", "if be8(rec, 26) != 0 && !(s == 2 || s == 3 || s == 9) {", "if be8(rec, 26) != 0 && !(s == 2 || s == 3) {"),
    ("set_state: changed_at only on a change", "if int_of(rec[1]) != s {\n        rec[1] = byte_of(s);\n        put_be8(rec, 18, now);\n    }", "rec[1] = byte_of(s);\n    put_be8(rec, 18, now);"),
    ("after_send: signed", "if s != 1 && s != 2 && s != 3 && s != 9 {", "if s != 2 && s != 3 && s != 9 {"),
    ("after_send: dropped", "if s != 1 && s != 2 && s != 3 && s != 9 {", "if s != 1 && s != 2 && s != 3 {"),
    ("after_send: included", "if s != 1 && s != 2 && s != 3 && s != 9 {", "if s != 1 && s != 2 && s != 3 && s != 9 && s != 4 {"),
    ("after_send: sent_at", "put_be8(rec, 10, now);\n    // A send", "put_be8(rec, 18, now);\n    // A send"),
    ("after_send: consumed is cleared", "put_be8(rec, 26, 0);\n    if ok {", "if ok {"),
    ("after_send: the outcome", "if ok {\n        set_state(rec, 2, now);\n    } else {\n        set_state(rec, 3, now);", "if !ok {\n        set_state(rec, 2, now);\n    } else {\n        set_state(rec, 3, now);"),
    ("after_send: a negative time", "if now < 0 {\n        return -321;", "if now < -1000 {\n        return -321;"),
    ("observe: a tx of 3", "if tx < 0 || tx > 2 || block < 0", "if tx < 0 || tx > 3 || block < 0"),
    ("observe: a negative block", "|| block < 0 || tip < 0 ||", "|| tip < 0 ||"),
    ("observe: a negative tip", "|| block < 0 || tip < 0 ||", "|| block < 0 ||"),
    ("observe: a negative nonce", "|| tip < 0 || nonce_latest < 0 ||", "|| tip < 0 ||"),
    ("observe: k of 0", "|| now < 0 || k < 1 ||", "|| now < 0 || k < 0 ||"),
    ("observe: a negative drop", "|| k < 1 || drop_ms < 0 || settle_ms < 0 ||", "|| k < 1 || settle_ms < 0 ||"),
    ("observe: a negative settle", "|| k < 1 || drop_ms < 0 || settle_ms < 0 ||", "|| k < 1 || drop_ms < 0 ||"),
    ("observe: a short block hash", "|| len(block_hash) != 32 || len(hash_at) != 32 {", "|| len(hash_at) != 32 {"),
    ("observe: a short hash at", "|| len(block_hash) != 32 || len(hash_at) != 32 {", "|| len(block_hash) != 32 {"),
    ("observe: a tip below the block", "if tx == 2 && tip < block {", "if tx == 2 && tip < block - 1000 {"),
    ("observe: a disagreement", "if !agree {\n        return 0;", "if false {\n        return 0;"),
    ("observe: a terminal state", "if is_terminal(s) {\n        return 0;", "if false {\n        return 0;"),
    ("is_terminal: final", "return s == 6 || s == 7 || s == 8;", "return s == 7 || s == 8;"),
    ("is_terminal: failed final", "return s == 6 || s == 7 || s == 8;", "return s == 6 || s == 8;"),
    ("is_terminal: replaced", "return s == 6 || s == 7 || s == 8;", "return s == 6 || s == 7;"),
    ("is_terminal: dropped", "return s == 6 || s == 7 || s == 8;", "return s == 6 || s == 7 || s == 8 || s == 9;"),
    ("observe: the status of a block", "var next = 4;\n        if !status_ok {\n            next = 5;", "var next = 4;\n        if status_ok {\n            next = 5;"),
    ("observe: the same block", "var same = s == next && be8(rec, 34) == block;", "var same = s == next;"),
    ("observe: the same state", "var same = s == next && be8(rec, 34) == block;", "var same = be8(rec, 34) == block;"),
    ("observe: the block's hash is compared", "if int_of(rec[42 + i]) != int_of(block_hash[i]) {\n                same = false;", "if false {\n                same = false;"),
    ("observe: a change moves changed_at", "if !same {\n            put_be8(rec, 18, now);", "if !same {\n            put_be8(rec, 18, 0);"),
    ("observe: the block is stored", "put_be8(rec, 34, block);\n            i = 0;", "put_be8(rec, 34, tip);\n            i = 0;"),
    ("observe: the hash is stored", "rec[42 + i] = block_hash[i];", "rec[42 + i] = hash_at[i];"),
    ("observe: a block clears consumed", "put_be8(rec, 26, 0);\n        // Final:", "// Final:"),
    ("observe: confirmations", "if tip - block + 1 >= k && hash_known {", "if tip - block + 1 > k && hash_known {"),
    ("observe: one confirmation fewer", "if tip - block + 1 >= k && hash_known {", "if tip - block >= k && hash_known {"),
    ("observe: the hash must be known", "if tip - block + 1 >= k && hash_known {", "if tip - block + 1 >= k {"),
    ("observe: the hash must be the same", "if int_of(hash_at[i]) != int_of(block_hash[i]) {\n                    steady = false;", "if false {\n                    steady = false;"),
    ("observe: final is final", "if status_ok {\n                    set_state(rec, 6, now);\n                } else {\n                    set_state(rec, 7, now);", "if !status_ok {\n                    set_state(rec, 6, now);\n                } else {\n                    set_state(rec, 7, now);"),
    ("observe: pending clears the block", "if tx == 1 {\n        clear_block(rec);\n        put_be8(rec, 26, 0);", "if tx == 1 {\n        put_be8(rec, 26, 0);"),
    ("observe: pending clears consumed", "if tx == 1 {\n        clear_block(rec);\n        put_be8(rec, 26, 0);", "if tx == 1 {\n        clear_block(rec);"),
    ("observe: pending is submitted", "put_be8(rec, 26, 0);\n        set_state(rec, 2, now);\n        return 0;", "put_be8(rec, 26, 0);\n        set_state(rec, 3, now);\n        return 0;"),
    ("observe: signed and not found", "if s == 1 {\n        return 1;", "if s == 1 {\n        return 2;"),
    ("observe: a vanished receipt, included", "if s == 4 || s == 5 {", "if s == 5 {"),
    ("observe: a vanished receipt, reverted", "if s == 4 || s == 5 {", "if s == 4 {"),
    ("observe: a vanished receipt clears the block", "// A receipt that was and is not.\n        clear_block(rec);", "// A receipt that was and is not."),
    ("observe: a vanished receipt is uncertain", "clear_block(rec);\n        set_state(rec, 3, now);\n        vanished = true;", "clear_block(rec);\n        set_state(rec, 2, now);\n        vanished = true;"),
    ("observe: a vanished receipt is noted", "set_state(rec, 3, now);\n        vanished = true;", "set_state(rec, 3, now);"),
    ("observe: a consumed nonce", "if nonce_latest > n {", "if nonce_latest >= n {"),
    ("observe: a consumed nonce, the other way", "if nonce_latest > n {", "if nonce_latest > n + 1 {"),
    ("observe: consumed_at is set", "if at == 0 {\n            put_be8(rec, 26, now);\n            at = now;", "if at == 0 {\n            at = now;"),
    ("observe: consumed_at is kept", "var at = be8(rec, 26);\n        if at == 0 {", "var at = 0;\n        if at == 0 {"),
    ("observe: the settle window", "if now - at >= settle_ms && !vanished {", "if now - at > settle_ms && !vanished {"),
    ("observe: settled at once", "if now - at >= settle_ms && !vanished {", "if !vanished {"),
    ("observe: a vanished one is not replaced", "if now - at >= settle_ms && !vanished {", "if now - at >= settle_ms {"),
    ("observe: replaced", "set_state(rec, 8, now);\n            put_be8(rec, 26, 0);", "set_state(rec, 9, now);\n            put_be8(rec, 26, 0);"),
    ("observe: replaced clears consumed", "set_state(rec, 8, now);\n            put_be8(rec, 26, 0);", "set_state(rec, 8, now);"),
    ("observe: an unused nonce clears consumed", "put_be8(rec, 26, 0);\n    if vanished {\n        return 2;", "if vanished {\n        return 2;"),
    ("observe: a vanished one is resubmitted", "if vanished {\n        return 2;", "if vanished {\n        return 0;"),
    ("observe: dropped is resubmitted", "if cur == 9 {\n        return 2;", "if cur == 9 {\n        return 0;"),
    ("observe: the drop window", "if now - be8(rec, 10) >= drop_ms {", "if now - be8(rec, 10) > drop_ms {"),
    ("observe: the drop window starts at the change", "if now - be8(rec, 10) >= drop_ms {", "if now - be8(rec, 18) >= drop_ms {"),
    ("observe: dropped", "set_state(rec, 9, now);\n        return 2;", "set_state(rec, 3, now);\n        return 2;"),
    ("observe: dropped is resubmitted at once", "set_state(rec, 9, now);\n        return 2;", "set_state(rec, 9, now);\n        return 0;"),
]

# Mutants no input can tell from the original, each with the reason.
EQUIVALENT = {
    "new: a nonce below zero": "the driver's integers are unsigned (at most 2^56 - 1): a negative one cannot be given; the check is for callers that compute their own",
    "after_send: a negative time": "the same: the driver cannot give a negative time",
    "observe: a negative block": "the same",
    "observe: a negative tip": "the same",
    "observe: a negative nonce": "the same",
    "observe: a negative drop": "the same",
    "observe: a negative settle": "the same",
}


def mutants(cancho, walks):
    text = open(os.path.join(ROOT, "lib/lifecycle/lifecycle.cho")).read()
    wrong = [f"{name!r}: {text.count(old)} times" for name, old, new in MUTANTS if text.count(old) != 1]
    if wrong:
        sys.exit("mutant patterns that do not occur exactly once:\n  " + "\n  ".join(wrong))
    work = [(name, text.replace(old, new)) for name, old, new in MUTANTS]

    def one(item):
        name, body = item
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "lifecycle"))
            open(os.path.join(d, "lifecycle/lifecycle.cho"), "w").write(body)
            exe = os.path.join(d, "lifedrv")
            r = subprocess.run([cancho, "build", "--std", *srcs(d), "-o", exe], capture_output=True, text=True)
            if r.returncode != 0:
                return name, "did not build: " + r.stderr[:200]
            r = subprocess.run([sys.executable, "-I", os.path.abspath(__file__), "--exe", exe, "--walks", str(walks)], capture_output=True, text=True, timeout=1800)
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
    walks = 60
    if "--walks" in sys.argv:
        walks = int(sys.argv[sys.argv.index("--walks") + 1])
    cancho = os.environ.get("CANCHO", "cancho")
    if "--mutants" in sys.argv:
        mutants(cancho, min(walks, 15))
    if "--exe" in sys.argv:
        run(sys.argv[sys.argv.index("--exe") + 1], min(walks, 15))
        print(f"{COUNT[0]} checks, {len(FAILS)} failed")
        sys.exit(1 if FAILS else 0)
    with tempfile.TemporaryDirectory() as t:
        exe = os.path.join(t, "lifedrv")
        build(cancho, os.path.join(ROOT, "lib"), exe)
        run(exe, walks)
    print(f"{COUNT[0]} checks, {len(FAILS)} failed")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
