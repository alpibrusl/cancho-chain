#!/usr/bin/env python3
"""The typed intent (lib/intent) against an independent model written from docs/design.md section 10, eth-utils and jsonschema (section 10.4).

    CANCHO=the-compiler CANCHO_SCHEMA=../cancho-schema/src/schema.cho python3 -I scripts/check_intent.py [--mutants] [--cases N]
    needs: pip install eth-account jsonschema

Builds tools/intentdrv/main.cho. Checks: (1) valid intents in every spelling give the model's canonical bytes and digest, and the same ones for the same intent;
(2) every damage the table of section 10.2 names is refused with exactly its code, in the table's order; (3) malformed JSON and bodies that are not one object are
`intent-json`; (4) the exported JSON Schema is a valid Draft 2020-12 schema and agrees with the structure stage (`explain`) on every document; (5) the size limit.
--mutants: one deliberate fault at a time in lib/intent/intent.cho; every one must be killed.
"""
import glob, json, os, random, shutil, subprocess, sys, tempfile
import jsonschema
from eth_utils import keccak, to_checksum_address

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = os.environ.get("CANCHO_SCHEMA", os.path.join(ROOT, "../cancho-schema/src/schema.cho"))
DOMAIN = b"cancho-chain/intent/v1"
U256 = 2**256


def srcs(libdir):
    return [os.path.join(ROOT, "tools/intentdrv/main.cho"), os.path.join(ROOT, "lib/keccak/keccak.cho"), os.path.join(ROOT, "lib/eth/hex.cho"), os.path.join(ROOT, "lib/eth/address.cho"),
            os.path.join(libdir, "intent/intent.cho"), SCHEMA]


def build(cancho, libdir, out):
    r = subprocess.run([cancho, "build", "--std", *srcs(libdir), "-o", out], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("build failed:\n" + r.stderr)


def call(exe, line):
    return subprocess.run([exe], input=line.encode(), capture_output=True, timeout=60).stdout.decode().strip() or "CRASH"


def intent(exe, body):
    out = call(exe, "I " + (body.hex() if body else "_"))
    parts = out.split()
    return parts[0] if len(parts) == 1 else tuple(parts)


# ---- the model: the spec of section 10, written separately
def canonical(chain, asset, recipient, amount, reference, request_id):
    return (bytes([1, 1]) + chain.to_bytes(8, "big") + asset + recipient + amount.to_bytes(32, "big") + bytes([len(reference)]) + reference + bytes([len(request_id)]) + request_id)


def digest(c):
    return keccak(DOMAIN + c)


def expected(c):
    return ("0", c.hex(), digest(c).hex())


class Intent:
    def __init__(self, rng):
        self.chain = rng.choice((1, 11155111, 137, 2**53 - 1, rng.randrange(1, 2**53)))
        self.asset = bytes(rng.randrange(256) for _ in range(20))
        self.recipient = bytes(rng.randrange(256) for _ in range(20))
        digits = rng.choice((1, 2, 6, 18, 30, 50, 77, 78))
        self.amount = max(1, min(U256 - 1, rng.randrange(10 ** (digits - 1), 10 ** digits)))
        word = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
        self.reference = "".join(rng.choice(word) for _ in range(rng.choice((1, 2, 17, 63, 64))))
        self.request_id = "".join(rng.choice(word) for _ in range(rng.choice((1, 2, 11, 63, 64))))

    def canonical(self):
        return canonical(self.chain, self.asset, self.recipient, self.amount, self.reference.encode(), self.request_id.encode())

    def raw(self, checksummed=True):
        a = to_checksum_address(self.asset) if checksummed else "0x" + self.asset.hex()
        r = to_checksum_address(self.recipient) if checksummed else "0x" + self.recipient.hex()
        return {"kind": '"erc20_transfer"', "chain_id": str(self.chain), "asset": json.dumps(a), "recipient": json.dumps(r), "amount": json.dumps(str(self.amount)),
                "reference": json.dumps(self.reference), "request_id": json.dumps(self.request_id)}


KEYS = ["kind", "chain_id", "asset", "recipient", "amount", "reference", "request_id"]


def body(raw, order=None, ws=("", ""), drop=(), extra=()):
    """The JSON text of `raw` (field -> JSON text), keys in `order`, `ws` the whitespace after a colon and after a comma."""
    order = order or KEYS
    pairs = [f'"{k}":{ws[0]}{raw[k]}' for k in order if k in raw and k not in drop] + [f'{k}:{ws[0]}{v}' if k.startswith('"') else f'"{k}":{ws[0]}{v}' for k, v in extra]
    return ("{" + ws[1] + ("," + ws[1]).join(pairs) + ws[1] + "}").encode()


def run(exe, cases):
    bad = total = 0

    def check(name, got, want):
        nonlocal bad, total
        total += 1
        if got != want:
            bad += 1
            if bad <= 8:
                print(f"  MISMATCH {name}: got {got} want {want}")

    rng = random.Random(20261106)
    # ---- (1) valid intents, in every spelling
    for _ in range(cases):
        it = Intent(rng)
        want = expected(it.canonical())
        spellings = [body(it.raw()), body(it.raw(False)), body(it.raw(), order=rng.sample(KEYS, 7)), body(it.raw(), ws=(" ", " ")), body(it.raw(), ws=("\n\t", "\r\n")), body(it.raw(), ws=("", "\n"))]
        for k, b in enumerate(spellings):
            check(f"valid spelling {k}", intent(exe, b), want)
        # a chain id spelled with a leading plus or zero, a fraction or an exponent is not the same text
    # the extremes
    edge = Intent(rng)
    edge.chain, edge.amount = 1, 1
    check("amount 1", intent(exe, body(edge.raw())), expected(edge.canonical()))
    edge.chain, edge.amount = 2**53 - 1, U256 - 1
    check("chain 2^53 - 1 and amount 2^256 - 1", intent(exe, body(edge.raw())), expected(edge.canonical()))
    check("exactly 4096 bytes", intent(exe, body(edge.raw())[:-1] + b" " * (4096 - len(body(edge.raw()))) + b"}") , expected(edge.canonical()))
    check("4097 bytes", intent(exe, body(edge.raw())[:-1] + b" " * (4097 - len(body(edge.raw()))) + b"}"), "E212")
    check("an empty body", intent(exe, b""), "E200")
    good = body(edge.raw()).hex()
    check("an output slice that is too short", call(exe, "O " + good), "E210")
    check("a Keccak working space that is too short", call(exe, "W " + good), "E211")

    # ---- (2) damage, each refused with exactly its code
    it = Intent(rng)
    it.chain = 11155111
    base = it.raw()
    ck = to_checksum_address(it.asset)

    def with_(field, text):
        r = dict(base)
        r[field] = text
        return body(r)

    def addr_cases(field, code):
        letters = [i for i, ch in enumerate(ck) if i >= 2 and ch.isalpha()]
        flip = ck[:letters[0]] + ck[letters[0]].swapcase() + ck[letters[0] + 1:]
        mixed_flip = any(c.isupper() for c in flip[2:] if c.isalpha()) and any(c.islower() for c in flip[2:] if c.isalpha())
        out = [("bad checksum", with_(field, json.dumps(flip)), code if mixed_flip else "0"),
               ("all uppercase letters", with_(field, json.dumps("0x" + ck[2:].upper())), code),
               ("no prefix", with_(field, json.dumps(ck[2:] + "00")), code), ("0X prefix", with_(field, json.dumps("0X" + ck[2:])), code),
               ("a non-hex character", with_(field, json.dumps(ck[:-1] + "g")), code), ("a space", with_(field, json.dumps(ck[:-1] + " ")), code),
               ("a non-ASCII character", with_(field, json.dumps(ck[:-1] + "é")), code), ("an escape that spells a hex digit", with_(field, '"' + ck[:-1] + '\\u0030"'), code),
               ("an escaped zero in the prefix", with_(field, '"\\u0030' + ck[1:] + '"'), code)]
        return out

    cases_ = []
    for field, code in (("asset", "E202"), ("recipient", "E203")):
        cases_ += [(f"{field}: {n}", b, w) for n, b, w in addr_cases(field, code)]
    cases_ += [("amount: leading zero", with_("amount", '"007"'), "E204"), ("amount: plus", with_("amount", '"+5"'), "E204"), ("amount: minus", with_("amount", '"-5"'), "E204"),
               ("amount: point", with_("amount", '"1.5"'), "E204"), ("amount: exponent", with_("amount", '"1e6"'), "E204"), ("amount: leading space", with_("amount", '" 5"'), "E204"),
               ("amount: trailing space", with_("amount", '"5 "'), "E204"), ("amount: hex", with_("amount", '"0x10"'), "E204"), ("amount: an Arabic-Indic digit", with_("amount", '"٣"'), "E204"),
               ("amount: a comma", with_("amount", '"1,000"'), "E204"), ("amount: 78 nines (above 2^256)", with_("amount", '"' + "9" * 78 + '"'), "E204"),
               ("amount: 2^256", with_("amount", f'"{U256}"'), "E204"), ("amount: 2^256 - 1", with_("amount", f'"{U256 - 1}"'), "0"), ("amount: zero", with_("amount", '"0"'), "E205"),
               ("amount: 00", with_("amount", '"00"'), "E204"), ("amount: an escaped digit", with_("amount", '"\\u0035"'), "E204"), ("amount: a JSON number", with_("amount", "5"), "E201"),
               ("amount: empty", with_("amount", '""'), "E201"), ("amount: 79 characters", with_("amount", '"' + "1" * 79 + '"'), "E201"), ("amount: null", with_("amount", "null"), "E201")]
    for field, code in (("reference", "E206"), ("request_id", "E207")):
        cases_ += [(f"{field}: a space", with_(field, '"a b"'), code), (f"{field}: a slash", with_(field, '"a/b"'), code), (f"{field}: a quote", with_(field, '"a\\"b"'), code),
                   (f"{field}: an escaped letter", with_(field, '"\\u0041"'), code), (f"{field}: non-ASCII", with_(field, '"é"'), code), (f"{field}: an emoji", with_(field, '"😀"'), code),
                   (f"{field}: a control character", with_(field, '"a\\u0001b"'), code), (f"{field}: a newline escape", with_(field, '"a\\nb"'), code),
                   (f"{field}: empty", with_(field, '""'), "E201"), (f"{field}: 65 characters", with_(field, '"' + "a" * 65 + '"'), "E201"), (f"{field}: 64 characters", with_(field, '"' + "a" * 64 + '"'), "0"),
                   (f"{field}: a number", with_(field, "5"), "E201"), (f"{field}: an object", with_(field, "{}"), "E201"), (f"{field}: an array", with_(field, '["a"]'), "E201"),
                   (f"{field}: each allowed punctuation", with_(field, '"a.b_c:d-e"'), "0")]
    cases_ += [("kind: another kind", with_("kind", '"erc20_approve"'), "E201"), ("kind: wrong case", with_("kind", '"ERC20_TRANSFER"'), "E201"), ("kind: empty", with_("kind", '""'), "E201"),
               ("kind: a number", with_("kind", "1"), "E201"), ("kind: a prefix of the kind", with_("kind", '"erc20"'), "E201"),
               ("chain id: zero", with_("chain_id", "0"), "E201"), ("chain id: negative", with_("chain_id", "-1"), "E201"), ("chain id: 2^53", with_("chain_id", str(2**53)), "E201"),
               ("chain id: a string", with_("chain_id", '"1"'), "E201"), ("chain id: true", with_("chain_id", "true"), "E201"), ("chain id: 1.5", with_("chain_id", "1.5"), "E201"),
               ("chain id: 1.0", with_("chain_id", "1.0"), "E213"), ("chain id: 1e2", with_("chain_id", "1e2"), "E213"), ("chain id: 1E0", with_("chain_id", "1E0"), "E213"),
               ("chain id: 100.0", with_("chain_id", "100.0"), "E213"), ("chain id: null", with_("chain_id", "null"), "E201"),
               ("asset: 41 characters", with_("asset", json.dumps(ck[:-1])), "E201"), ("asset: 43 characters", with_("asset", json.dumps(ck + "0")), "E201"), ("asset: a number", with_("asset", "5"), "E201"),
               ("recipient: empty", with_("recipient", '""'), "E201"), ("recipient: null", with_("recipient", "null"), "E201")]
    for k in KEYS:
        cases_.append((f"missing {k}", body(base, drop=(k,)), "E201"))
    for name, extra in (("an unknown key", [("from", '"0x0000000000000000000000000000000000000001"')]), ("a spender", [("spender", '"x"')]), ("data", [("data", '"0x"')]), ("gas_price", [("gas_price", "1")]),
                        ("value", [("value", "1")]), ("an empty key", [("", '"x"')]), ("a key differing in case", [("Amount", '"5"')])):
        cases_.append((f"{name}", body(base, extra=extra), "E201"))
    for k in KEYS:
        other = {"kind": '"erc20_transfer"', "chain_id": "7", "asset": '"0x0000000000000000000000000000000000000001"', "recipient": '"0x0000000000000000000000000000000000000002"', "amount": '"9"', "reference": '"zzz"', "request_id": '"yyy"'}
        cases_.append((f"duplicate {k} (same value)", body(base, extra=[(k, base[k])]), "E208"))
        cases_.append((f"duplicate {k} (other value)", body(base, extra=[(k, other[k])]), "E208"))
        cases_.append((f"duplicate {k} (first wins would pass)", body(base, order=[x for x in KEYS if x != k] + [k], extra=[(k, other[k])]), "E208"))
    cases_ += [("a key written with an escape", body({**{k: v for k, v in base.items() if k != "recipient"}}, extra=[('"reci\\u0070ient"', base["recipient"])]), "E209"),
               ("a key of the schema written with an escape and no plain twin", body(base, drop=("amount",), extra=[('"am\\u006funt"', base["amount"])]), "E209"),
               ("an unknown key written with an escape", body(base, extra=[('"fr\\u006fm"', '"x"')]), "E209"),
               ("17 members", body(base, extra=[(f"k{i}", "1") for i in range(10)]), "E201")]
    # keys: where the escaped key sits, and the member-count limit
    def obj(pairs):
        return ("{" + ",".join(f"{k}:{v}" for k, v in pairs) + "}").encode()

    bp = [(f'"{k}"', base[k]) for k in KEYS]
    cases_ += [("an escaped first key", obj([('"\\u006bind"', base["kind"])] + bp[1:]), "E209"),
               ("an escaped middle key", obj(bp[:3] + [('"rec\\u0069pient"', base["recipient"])] + bp[4:]), "E209"),
               ("a duplicate pair with an escaped key between them", obj([bp[0], ('"\\u0061"', "1"), bp[0]] + bp[1:]), "E209"),
               ("a single escaped key", b'{"\\u0061":1}', "E209"),
               ("17 members including a duplicate", obj(bp + [(f'"k{i}"', "1") for i in range(9)] + [bp[0]]), "E201"),
               ("16 members including a duplicate", obj(bp + [(f'"k{i}"', "1") for i in range(8)] + [bp[0]]), "E208"),
               ("16 members, all distinct (unknown keys)", obj(bp + [(f'"k{i}"', "1") for i in range(9)]), "E201"),
               ("amount: a colon", with_("amount", '"1:"'), "E204"), ("amount: a slash", with_("amount", '"1/"'), "E204"), ("amount: an at sign", with_("amount", '"@"'), "E204"),
               ("amount: a backtick", with_("amount", '"1`"'), "E204")]
    allchars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
    for field, code in (("reference", "E206"), ("request_id", "E207")):
        cases_ += [(f"{field}: every allowed character (first 64)", with_(field, json.dumps(allchars[:64])), "0"), (f"{field}: every allowed character (last 64)", with_(field, json.dumps(allchars[-64:])), "0")]
        for ch in "@[`{/;,+=<>!#$%&*()'|~?^ \u007f":
            cases_.append((f"{field}: the character {ch!r}", with_(field, json.dumps("a" + ch + "b")), code))
    # JSON-level
    ok = body(base).decode()
    cases_ += [("a trailing comma", (ok[:-1] + ",}").encode(), "E200"), ("single quotes", ok.replace('"', "'").encode(), "E200"), ("a comment", (ok + " // x").encode(), "E200"), ("NaN", ok.replace("11155111", "NaN").encode(), "E200"),
               ("Infinity", ok.replace("11155111", "Infinity").encode(), "E200"), ("a leading zero", ok.replace("11155111", "011155111").encode(), "E200"), ("a plus sign", ok.replace("11155111", "+11155111").encode(), "E200"),
               ("truncated", ok[:-3].encode(), "E200"), ("trailing garbage", (ok + "x").encode(), "E200"), ("a second object", (ok + ok).encode(), "E200"), ("a BOM", b"\xef\xbb\xbf" + ok.encode(), "E200"),
               ("invalid UTF-8", body({**base, "reference": '"a@@b"'}).replace(b"@@", b"\xff"), "E200"), ("an unescaped control character", ok.replace(base["reference"], '"a\tb"').encode(), "E200"),
               ("a lone surrogate escape", ok.replace(base["reference"], '"\\ud800"').encode(), "E200"), ("an array", b"[]", "E200"), ("a string", b'"x"', "E200"), ("a number", b"1", "E200"), ("null", b"null", "E200"),
               ("true", b"true", "E200"), ("an empty object", b"{}", "E201"), ("an array holding the object", ("[" + ok + "]").encode(), "E200"), ("an unclosed object", b"{", "E200"), ("whitespace only", b"  \n", "E200"),
               ("a nested object in the object", ok.replace(base["reference"], '{"a":1}').encode(), "E201"), ("surrounding whitespace is fine", (" \n" + ok + "\n ").encode(), "0")]
    for name, b, want in cases_:
        got = intent(exe, b)
        if want == "0":
            check(name, got[0] if isinstance(got, tuple) else got, "0")
        else:
            check(name, got, want)

    # ---- order of the checks: the first that fails answers
    two = lambda **kw: body({**base, **kw})
    check("order: duplicate key before schema", intent(exe, body(base, extra=[("junk", "1"), ("kind", '"x"')])), "E208")
    check("order: key escape before duplicate", intent(exe, body(base, extra=[('"k\\u0069nd"', '"x"')])), "E209")
    check("order: schema before address", intent(exe, two(asset='"0xzz"', amount="5")), "E201")
    check("order: asset before recipient", intent(exe, two(asset='"0X' + ck[2:] + '"', recipient='"0X' + ck[2:] + '"')), "E202")
    check("order: recipient before amount", intent(exe, two(recipient='"0X' + ck[2:] + '"', amount='"-1"')), "E203")
    check("order: amount before reference", intent(exe, two(amount='"-1"', reference='"a b"')), "E204")
    check("order: reference before request id", intent(exe, two(reference='"a b"', request_id='"a b"')), "E206")
    check("order: chain id spelling before asset (1.0, bad asset)", intent(exe, two(chain_id="1.0", asset='"0X' + ck[2:] + '"')), "E213")

    # ---- (4) the exported JSON Schema agrees with the structure stage
    schema_text = call(exe, "S")
    sch = json.loads(schema_text)
    jsonschema.Draft202012Validator.check_schema(sch)
    validator = jsonschema.Draft202012Validator(sch)
    structure = []
    for _ in range(cases):
        it = Intent(rng)
        r = it.raw()
        for k in KEYS:
            structure.append(body(r, drop=(k,)))
        for k, v in (("chain_id", "0"), ("chain_id", "2.5"), ("chain_id", '"1"'), ("chain_id", "true"), ("chain_id", "100.0"), ("asset", '"0x1"'), ("amount", "7"), ("amount", '""'), ("kind", '"x"'), ("reference", "[]"), ("request_id", '""'),
                     ("reference", '"' + "a" * 65 + '"'), ("asset", "null")):
            structure.append(body({**r, k: v}))
        structure.append(body(r, extra=[("extra", "1")]))
        structure.append(body(r))
    for b in structure:
        doc = json.loads(b)
        want = validator.is_valid(doc)
        got = call(exe, "X " + b.hex())
        check(f"structure stage vs JSON Schema on {b[:50]!r}", got == "ok", want)
    return bad, total


# Mutants no input can kill, with the reason. Reported, not failed: a survivor outside this list fails the run.
EXPECTED_SURVIVORS = {
    "asset escape accepted": "defence in depth: the raw text of an escaped string is longer than 42 characters and holds a backslash, so `address.parse` refuses it as it stands",
    "recipient escape accepted": "defence in depth: the same, for the recipient",
    "amount escape accepted": "defence in depth: the raw text of an escape holds a backslash, which is not a digit, so the digit loop refuses it as it stands",
    "escapes allowed in words": "defence in depth: a backslash is not a word character, so the character loop refuses the raw text as it stands",
}

# (name, old, new)
MUTANTS = [
    ("size limit 4096 -> 4097", "if len(body) > 4096 {\n        return -212;", "if len(body) > 4097 {\n        return -212;"),
    ("size limit not applied", "if len(body) > 4096 {\n        return -212;", "if len(body) > 40960 {\n        return -212;"),
    ("members limit 16 -> 17", "} else if t[1] > 16 {", "} else if t[1] > 17 {"),
    ("duplicate keys not looked for", "if bytes.equal(json.string_view(body, tape, j), json.string_view(body, tape, k)) {", "if bytes.equal(json.string_view(body, tape, j), json.string_view(body, tape, k)) && false {"),
    ("duplicate check skips the last key", "while c < n {\n            if !json.string_plain(tape, k) {", "while c < n - 1 {\n            if !json.string_plain(tape, k) {"),
    ("escaped keys accepted", "    var a = 0;\n    while a < n {\n        if !json.string_plain(tape, j) {\n            return -209;\n        }", "    var a = 0;\n    while a < n {\n        if !json.string_plain(tape, j) && false {\n            return -209;\n        }"),
    ("later keys' escapes accepted", "        while c < n {\n            if !json.string_plain(tape, k) {\n                return -209;", "        while c < n {\n            if !json.string_plain(tape, k) && false {\n                return -209;"),
    ("the schema is not strict", "schema.new_object(heap, s6, true)", "schema.new_object(heap, s6, false)"),
    ("kind choice changed", 'schema.add_choice(heap, s1, kind, "erc20_transfer")', 'schema.add_choice(heap, s1, kind, "erc20_transferx")'),
    ("chain id lower bound 1 -> 0", "schema.new_int(heap, s2, 1, 9007199254740991)", "schema.new_int(heap, s2, 0, 9007199254740991)"),
    ("chain id upper bound 2^53 - 1 -> 2^53", "schema.new_int(heap, s2, 1, 9007199254740991)", "schema.new_int(heap, s2, 1, 9007199254740992)"),
    ("address length 42 -> 41", "schema.new_string(heap, s3, 42, 42)", "schema.new_string(heap, s3, 41, 42)"),
    ("address length 42 -> 43", "schema.new_string(heap, s3, 42, 42)", "schema.new_string(heap, s3, 42, 43)"),
    ("amount length 78 -> 79", "schema.new_string(heap, s4, 1, 78)", "schema.new_string(heap, s4, 1, 79)"),
    ("amount may be empty", "schema.new_string(heap, s4, 1, 78)", "schema.new_string(heap, s4, 0, 78)"),
    ("text length 64 -> 65", "schema.new_string(heap, s5, 1, 64)", "schema.new_string(heap, s5, 1, 65)"),
    ("text may be empty", "schema.new_string(heap, s5, 1, 64)", "schema.new_string(heap, s5, 0, 64)"),
    ("recipient not required", 'object, "recipient", address, true)', 'object, "recipient", address, false)'),
    ("request_id not required", 'object, "request_id", text, true)', 'object, "request_id", text, false)'),
    ("chain id spelled as a float accepted", "if !json.is_int(tape, value_at(slots, 1)) {", "if json.is_int(tape, value_at(slots, 1)) && false {"),
    ("asset escape accepted", "if !json.string_plain(tape, asset) ||", "if false ||"),
    ("recipient escape accepted", "if !json.string_plain(tape, recipient) ||", "if false ||"),
    ("asset parsed into the recipient's place", "json.string_view(body, tape, asset), out[10..30]", "json.string_view(body, tape, asset), out[30..50]"),
    ("amount escape accepted", "if !json.string_plain(tape, amount) {\n        return -204;", "if false {\n        return -204;"),
    ("amount: leading zero accepted", "if len(v) == 0 || len(v) > 1 && int_of(v[0]) == 48 {", "if len(v) == 0 {"),
    ("amount: digit range", "if c < 48 || c > 57 {\n            return -204;", "if c < 48 || c > 58 {\n            return -204;"),
    ("amount: overflow ignored", "if carry != 0 {\n            return -204;", "if carry != 77 {\n            return -204;"),
    ("amount: times nine", "let x = int_of(out[j]) * 10 + carry;", "let x = int_of(out[j]) * 9 + carry;"),
    ("amount: zero accepted", "if any == 0 {\n        return -205;", "if any == 77 {\n        return -205;"),
    ("amount: carry shift", "carry = x >> 8;", "carry = x >> 7;"),
    ("word characters: digits", "c >= 48 && c <= 57 ||", "c >= 49 && c <= 57 ||"),
    ("word characters: capitals", "c >= 65 && c <= 90 ||", "c >= 65 && c <= 89 ||"),
    ("word characters: lowercase", "c >= 97 && c <= 122 ||", "c >= 97 && c <= 121 ||"),
    ("word characters: dot", "|| c == 46 ||", "|| c == 47 ||"),
    ("word characters: underscore", "|| c == 95 ||", "|| c == 96 ||"),
    ("word characters: colon", "|| c == 58 ||", "|| c == 59 ||"),
    ("word characters: hyphen", "|| c == 45;", "|| c == 44;"),
    ("word check skipped for the reference", "if !is_word(body, tape, reference) {", "if false {"),
    ("word check skipped for the request id", "if !is_word(body, tape, request) {", "if false {"),
    ("escapes allowed in words", "    if !json.string_plain(tape, at) {\n        return false;\n    }\n    let v = json.string_view(body, tape, at);\n    var i = 0;\n    while i < len(v) {\n        if !word_char", "    let v = json.string_view(body, tape, at);\n    var i = 0;\n    while i < len(v) {\n        if !word_char"),
    ("layout version byte", "out[0] = byte_of(1);", "out[0] = byte_of(2);"),
    ("kind byte", "out[1] = byte_of(1);", "out[1] = byte_of(2);"),
    ("chain id byte order", "out[2 + i] = byte_of(chain >> 8 * (7 - i) & 255);", "out[2 + i] = byte_of(chain >> 8 * i & 255);"),
    ("reference length byte", "out[82] = byte_of(len(rv));", "out[82] = byte_of(len(rv) + 1);"),
    ("request id placed at the wrong offset", "let at = 83 + len(rv);\n    out[at] = byte_of(len(qv));", "let at = 82 + len(rv);\n    out[at] = byte_of(len(qv));"),
    ("digest domain", 'let s = "cancho-chain/intent/v1";', 'let s = "cancho-chain/intent/v2";'),
    ("digest hashes altered bytes", "m[22 + i] = canonical[i];", "m[22 + i] = byte_of(int_of(canonical[i]) ^ 1);"),
    ("output limit", "if len(out) < 212 {\n        return -210;", "if len(out) < 100 {\n        return -210;"),
]


def mutants(cancho, cases):
    survived = 0
    for name, old, new in MUTANTS:
        d = tempfile.mkdtemp()
        try:
            os.makedirs(f"{d}/lib/intent")
            shutil.copy(os.path.join(ROOT, "lib/intent/intent.cho"), f"{d}/lib/intent/intent.cho")
            p = f"{d}/lib/intent/intent.cho"
            text = open(p).read()
            if text.count(old) != 1:
                raise SystemExit(f"mutant pattern not unique ({text.count(old)}): {name}")
            open(p, "w").write(text.replace(old, new))
            exe = f"{d}/intent"
            r = subprocess.run([cancho, "build", "--std", *srcs(f"{d}/lib"), "-o", exe], capture_output=True, text=True)
            if r.returncode != 0:
                print(f"mutant '{name}': did not build\n{r.stderr[:300]}")
                survived += 1
                continue
            bad, total = run(exe, cases)
            if not bad and name in EXPECTED_SURVIVORS:
                print(f"mutant '{name}': SURVIVED, expected: {EXPECTED_SURVIVORS[name]}")
                continue
            print(f"mutant '{name}': {'KILLED' if bad else 'SURVIVED'} ({bad}/{total})")
            survived += 0 if bad else 1
        finally:
            shutil.rmtree(d)
    return survived


def main():
    cancho = os.environ.get("CANCHO", "cancho")
    cases = int(sys.argv[sys.argv.index("--cases") + 1]) if "--cases" in sys.argv else 20
    d = tempfile.mkdtemp()
    try:
        exe = os.path.join(d, "intent")
        build(cancho, os.path.join(ROOT, "lib"), exe)
        bad, total = run(exe, cases)
        print(f"intent: {total - bad}/{total} checks agree with the model, eth-utils and jsonschema")
        if bad:
            sys.exit(1)
        if "--mutants" in sys.argv:
            s = mutants(cancho, max(4, cases // 4))
            print(f"mutants: {len(MUTANTS) - s - len(EXPECTED_SURVIVORS)}/{len(MUTANTS)} killed, {len(EXPECTED_SURVIVORS)} redundant (above), {s} unexpected survivors")
            if s:
                sys.exit(1)
    finally:
        shutil.rmtree(d)


main()
