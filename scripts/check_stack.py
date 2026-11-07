#!/usr/bin/env python3
"""The whole stack: `cancho-gateway`, the front and the signer, with a client that has API keys (docs/design.md section 15.3).

    CANCHO=our-compiler CANCHO_GATEWAY_COMPILER=the-compiler-cancho-gateway-pins CANCHO_GATEWAY=../cancho-gateway CANCHO_PACKAGES=... CANCHO_SCHEMA=... CANCHO_LOG=... \
        python3 -I scripts/check_stack.py
    needs: what check_signer.py needs, and `cancho build` run once in the gateway checkout (it fills build/deps)

The gateway is the one `cancho-gateway` pins, built by its own test harness with an API key per principal and `auth_identity_header` on the route; the front and the signer are built with
ours. The signer is told who the caller is by nothing but the name of the key the gateway authenticated.
"""
import hashlib, json, os, random, subprocess, sys, tempfile, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
OURS = os.environ.get("CANCHO", "cancho")
GATEWAY = os.environ.get("CANCHO_GATEWAY", os.path.join(ROOT, "../cancho-gateway"))
os.environ["CANCHO"] = os.environ.get("CANCHO_GATEWAY_COMPILER", OURS)  # the gateway's harness reads the compiler from CANCHO when it is imported
sys.path.insert(0, os.path.join(GATEWAY, "tests"))
import proxy_test as pt          # the gateway's harness (a recording upstream, free ports, a built gateway)
import ratelimit_test as rt
os.environ["CANCHO"] = OURS
import check_envelope as ce
import check_signer as cs
import check_front as cf

KEYS = {"agent-procurement-01": "ck_stack_procurement_" + "P" * 22, "agent-other-02": "ck_stack_other-" + "O" * 28, "ops-readonly": "ck_stack_ops.readonly~" + "R" * 21}
WRONG = "ck_stack_procurement_" + "P" * 21 + "Q"
check = cs.check


def digest(k):
    return hashlib.sha256(k.encode()).hexdigest()


ROUTES = "".join('\n[[api_key]]\nname = "%s"\nsha256 = "%s"\n' % (n, digest(k)) for n, k in KEYS.items()) + """
[[route]]
name = "sign"
path_prefix = "/sign"
methods = ["POST"]
upstream = "up"
auth = "api-key"
auth_keys = ["agent-procurement-01", "agent-other-02"]
auth_identity_header = "X-Auth-Identity"
"""


def http(port, body, key=None, extra=b"", path=b"/sign", method=b"POST"):
    import socket
    raw = method + b" " + path + b" HTTP/1.1\r\nHost: api\r\n" + (b"Authorization: Bearer " + key.encode() + b"\r\n" if key else b"") + extra + b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    try:
        s.sendall(raw)
        return cf.read_response(s)
    finally:
        s.close()


def case_for(rng, caller):
    c = cs.live_case(rng)
    c.caller = caller.encode()
    c.decision = ce.decision_record(c.decision[4:36], c.decision[36:68], c.decided, c.expires, c.tx.amount, c.caller)
    c.env = ce.layout(c)
    return c


def main():
    rng = random.Random(777)
    with tempfile.TemporaryDirectory() as tmp:
        sk = cf.make_stack(OURS, open(os.path.join(ROOT, "tools/front/main.cho")).read(), open(os.path.join(ROOT, "tools/signer/main.cho")).read(), os.path.join(ROOT, "lib"), tmp, cf.free_port())
        gw_tmp = os.path.join(tmp, "gw")
        os.mkdir(gw_tmp)
        gw = rt.Gateway(gw_tmp, sk.port, pt.free_port(), ROUTES, tls=False, top="auth_allow_plain = true\n")
        try:
            run(sk, gw, rng)
        finally:
            gw.stop()
            sk.stop()
    print(f"{cs.COUNT[0]} checks, {len(cs.FAILS)} failed")
    sys.exit(1 if cs.FAILS else 0)


def run(sk, gw, rng):
    state = sk.state
    c = case_for(rng, "agent-procurement-01")
    state.reset(c)
    body = cf.sign_body(c)
    # a principal with its key: the signer's caller is the key's name, and it signs
    n0 = sk.starts()
    status, h, out = http(gw.port, body, KEYS["agent-procurement-01"])
    j = json.loads(out)
    check("the procurement key signs its own envelope", (status, j.get("ok"), j.get("entry"), sk.starts() - n0), (200, True, "fresh", 1))
    check("the signature is the model's", bytes.fromhex(j.get("signature", "")), ce.sign(ce.kec(c.tx.unsigned()), c.wallet_key))
    # a forged identity from the client is replaced by the gateway's
    status, h, out = http(gw.port, body, KEYS["agent-procurement-01"], extra=b"X-Auth-Identity: agent-other-02\r\n")
    check("a forged X-Auth-Identity does not change the caller (same envelope, same entry)", (status, json.loads(out).get("entry")), (200, "same"))
    status, h, out = http(gw.port, body, KEYS["agent-other-02"], extra=b"X-Auth-Identity: agent-procurement-01\r\nx-auth-identity: agent-procurement-01\r\n")
    check("another key forging the first's name is still the other caller: envelope-caller", (status, json.loads(out).get("rule")), (422, "chain.envelope-caller"))
    status, h, out = http(gw.port, body, KEYS["agent-other-02"])
    check("another key presenting the envelope is refused: envelope-caller", (status, json.loads(out).get("rule")), (422, "chain.envelope-caller"))
    # the other principal's own envelope
    c2 = case_for(rng, "agent-other-02")
    state.reset(c2)
    status, h, out = http(gw.port, cf.sign_body(c2), KEYS["agent-other-02"])
    check("the other key signs its own envelope", (status, json.loads(out).get("ok")), (200, True))
    # never reaching the front: no key, a wrong key, a key the route does not allow, a bad method, a forged header alone
    before = open(state.ledger(), "rb").read()
    n0 = sk.starts()
    for name, kw, want in (("no key", dict(), 401), ("no key and a forged identity", dict(extra=b"X-Auth-Identity: agent-other-02\r\n"), 401), ("a wrong key", dict(key=WRONG), 401),
                           ("a key the route does not allow", dict(key=KEYS["ops-readonly"]), 403), ("a GET", dict(key=KEYS["agent-other-02"], method=b"GET"), 405)):
        status, h, out = http(gw.port, cf.sign_body(c2), **kw)
        check(f"{name}: {want} from the gateway", status, want)
    check("none of them started the signer or changed the ledger", (sk.starts() - n0, open(state.ledger(), "rb").read()), (0, before))
    # the gateway's log names the key and never the key's value
    time.sleep(0.2)
    with gw.lock:
        everything = b"".join(gw.log)
    check("the gateway's log has the identity and no key", (b"agent-procurement-01" in everything, all(k.encode() not in everything for k in KEYS.values())), (True, True))
    # what the front does with a request that did not come through the gateway: it believes the header (the deployment must not let this happen)
    state.reset(c)
    status, h, out = cf.Stack.post(sk, cf.sign_body(c), identity="agent-procurement-01")
    check("a request straight to the front is believed: the front must be reachable only by the gateway", status, 200)
    # a refused request through the whole stack still carries a rule tag
    c3 = case_for(rng, "agent-procurement-01")
    state.reset(c3)
    status, h, out = http(gw.port, cf.sign_body(c3, sig=ce.sign(ce.env_digest(c3.env), bytes(31) + b"\x07")), KEYS["agent-procurement-01"])
    check("a refusal through the stack keeps its tag", (status, json.loads(out).get("rule")), (422, "chain.envelope-issuer"))


if __name__ == "__main__":
    main()
