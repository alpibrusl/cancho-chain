#!/usr/bin/env python3
"""A demonstration of the signer, with the real compiled binary (not a test: nothing here is judged, it is printed).

    CANCHO=the-compiler CANCHO_PACKAGES=... CANCHO_SCHEMA=... CANCHO_LOG=... python3 -I scripts/demo.py

One authorisation envelope (a decision bound to one exact unsigned transaction, signed by the issuer) is shown to the signer, and then it is shown the things that must not work.
It signs nothing real: the wallet key is made here and the chain is a number.
"""
import json, os, random, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import check_envelope as ce
import check_signer as cs
from eth_account import Account


def show(title, res):
    rc, j, out = res
    if j and j.get("ok"):
        print(f"  {title}\n    -> SIGNED  exit {rc}  entry={j.get('entry')}  ledger count={j.get('anchor', {}).get('count')}")
    elif j:
        print(f"  {title}\n    -> REFUSED exit {rc}  rule={j.get('rule')}\n       {str(j.get('repair', ''))[:150]}")
    else:
        print(f"  {title}\n    -> exit {rc}  {out[:200]}")
    return j


def main():
    cancho = os.environ.get("CANCHO", "cancho")
    rng = random.Random(7)
    with tempfile.TemporaryDirectory() as t:
        state = os.path.join(t, "state")
        os.mkdir(state)
        exe = os.path.join(t, "signer")
        cs.build(cancho, os.path.join(ROOT, "lib"), open(os.path.join(ROOT, "tools/signer/main.cho")).read(), state, exe)
        st = cs.State(state, exe)
        c = cs.live_case(rng)
        st.reset(c)
        addr = Account.from_key(c.wallet_key).address
        print(f"The signer holds a wallet key it made here (address {addr}); the agent holds none.")
        print(f"The transaction: chain {c.tx.chain}, nonce {c.tx.nonce}, amount {c.tx.amount} base units.\n")
        print("1. The envelope the issuer signed, with exactly that transaction:")
        j = show("valid envelope + the exact bytes it was issued for", st.run(c))
        if j and j.get("ok"):
            print(f"       signature {j['signature'][:40]}...")
        print("\n2. What must not work:")
        other = cs.live_case(random.Random(8))
        show("the same envelope, but the agent swaps in another transaction's bytes", st.run(c, msg=other.tx.unsigned()))
        show("an envelope signed by a key that is not the issuer's", st.run(c, sig=ce.sign(ce.env_digest(c.env), other.issuer_key)))
        show("the very same envelope and bytes again (idempotent: the same signature, no new ledger entry)", st.run(c))
        d = cs.with_nonce(c, c.tx.nonce + 1)
        show("the same envelope id used for a different transaction (nonce + 1): a replay", st.run(d))
        print("\n3. The ledger is evidence that cannot be quietly shortened:")
        os.unlink(st.ledger())
        print("  (the operator, or an attacker, deletes the ledger so the envelope looks unused)")
        show("the same envelope after the ledger was deleted", st.run(c))
        print("\nEvery refusal is a successful outcome: it has a stable rule tag and a repair, and no signature exists for it.")


if __name__ == "__main__":
    main()
