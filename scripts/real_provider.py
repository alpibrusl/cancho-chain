#!/usr/bin/env python3
"""The executor, once, against a real JSON-RPC provider over TLS (docs/design.md section 21.5). A manual check: it needs the network, so it is not in the gate.

    CANCHO=the-compiler CANCHO_PACKAGES=... CANCHO_SCHEMA=... CANCHO_LOG=... python3 -I scripts/real_provider.py [host] [roots-dir]
    needs what check_executor.py needs; `host` defaults to ethereum-rpc.publicnode.com, `roots-dir` to /etc/ssl/certs

It never sends a transaction: the job is a transfer from a key made here, for chain 1 and nonce 0, and its state is made first by a tick against a local mock (which takes it:
SUBMITTED), with a drop window so long that the executor cannot decide to send it again. The real provider is asked only the read questions of section 18.2. Both of the executor's providers
are the same host (B with a capital letter, see below), so this shows the TLS and the answers of one real provider (a real certificate chain, a real HTTP stack), **not** a quorum of two independent ones.
The roots are a handful of well known ones copied from `roots-dir`: the file is limited (24,576 bytes), so the whole system store does not fit.
"""
import os, random, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import check_executor as ce
import check_envelope as ce_env
import check_signer as cs

ROOTS = ["ISRG_Root_X1", "ISRG_Root_X2", "GTS_Root_R1", "GTS_Root_R3", "GTS_Root_R4", "DigiCert_Global_Root_G2", "DigiCert_Global_Root_G3", "GlobalSign_Root_CA_-_R3",
         "GlobalSign_Root_E46", "USERTrust_ECC_Certification_Authority", "USERTrust_RSA_Certification_Authority", "Amazon_Root_CA_1", "Amazon_Root_CA_3"]


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "ethereum-rpc.publicnode.com"
    rdir = sys.argv[2] if len(sys.argv) > 2 else "/etc/ssl/certs"
    cancho = os.environ.get("CANCHO", "cancho")
    pem = b""
    for n in ROOTS:
        p = os.path.join(rdir, n + ".pem")
        if os.path.exists(p) and len(pem) + os.path.getsize(p) <= 24000:
            pem += open(p, "rb").read()
    print(f"roots: {pem.count(b'BEGIN CERTIFICATE')} certificates, {len(pem)} bytes")
    with tempfile.TemporaryDirectory() as tmp:
        state = os.path.join(tmp, "state")
        os.mkdir(state)
        trailtool = os.path.join(tmp, "trailtool")
        lib = os.path.join(ROOT, "lib")
        main_text = open(os.path.join(ROOT, "tools/executor/main.cho")).read()
        # a case for chain 1, nonce 0, whose transaction no node knows
        case = cs.live_case(random.Random(2026))
        case.tx.chain, case.tx.nonce = 1, 0
        case.env = ce_env.layout(case)
        # 1. the state: one tick against a local mock, which takes the transaction
        pa, pb = ce.free_port(), ce.free_port()
        exe_mock = os.path.join(tmp, "mock")
        ce.build(cancho, lib, main_text, state, pa, pb, exe_mock)
        seed = ce.live(random.Random(1))
        na, nb = ce.Node(ce.Chain(seed), pa), ce.Node(ce.Chain(seed), pb)
        chain = ce.Chain(case)
        na.chain = nb.chain = chain
        na.chain_id = nb.chain_id = 1
        na.start()
        nb.start()
        job = ce.Job(state, exe_mock, case, chain, na, nb)
        job.setup()
        job.write("config", "chain=1\nk=12\ndrop_ms=999999999999\nsettle_ms=999999999999\n")
        rc, j, out, took = job.tick()
        na.stop()
        nb.stop()
        print("the mock tick:", out)
        # 2. the same job and state, the real provider, over TLS
        exe_real = os.path.join(tmp, "real")
        # `narrow` refuses two identical bounds, so provider B is the same host spelled with a capital (names are case-insensitive for DNS and for the certificate)
        ce.build(cancho, lib, main_text, state, 443, 443, exe_real, host, host[0].upper() + host[1:], (1, 1))
        open(os.path.join(state, "roots.pem"), "wb").write(pem)
        job.exe = exe_real
        rc, j, out, took = job.tick(timeout=60)
        print(f"the real tick ({took:.2f} s, exit {rc}):", out)


if __name__ == "__main__":
    main()
