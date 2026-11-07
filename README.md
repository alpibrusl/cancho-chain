# cancho-chain

**[Project page](https://alpibrusl.github.io/cancho-chain/)** (once GitHub Pages is enabled for the `main` branch, `/docs` folder; the source is [`docs/index.html`](docs/index.html)).

An auditable authority and execution layer for autonomous blockchain agents, in pure [cancho](https://github.com/alpibrusl/cancho).

An agent may *propose* a transaction. A separately enforced policy decides whether it is allowed. A signer, in its own process, signs only the exact
bytes that were approved. Every step leaves evidence. The agent never holds a key and cannot change its own policy.

**Status: research.** Thirteen slices are built: a development signer (with an anchored ledger and a witness kept by its front) behind a network front and `cancho-gateway`, a strict reader of what a chain provider says, the lifecycle of a signed transaction as a pure state machine, and an executor that asks two providers and sends the same bytes again when the lifecycle says so. The executor has only been run against mock nodes; it speaks plain HTTP (no TLS). Nothing has been submitted to a real chain: nothing moves value. What exists, and how it is checked:

| Piece | State | Check |
|---|---|---|
| `chain.keccak`, Keccak-256 (Ethereum's padding, not SHA-3's) | built | `scripts/check_keccak.py`: 425 inputs against pycryptodome, 12 of 12 mutants killed |
| `chain.hex`, `chain.address` (EIP-55), `chain.rlp`, `chain.erc20`, `chain.tx1559` (encoders and the signed type-2 transaction) | built | `scripts/check_eth.py`: 531 checks against eth-account, eth-abi and rlp (signed transactions byte for byte), 29 of 29 mutants killed |
| `chain.rlp` decoder (strict), `chain.txcheck` (the final-transaction validator, 16 stable reason codes) | built | `scripts/check_decode.py`: 1,423 checks against rlp (strict, and a header-level reference: §9.3), 50 of 51 mutants killed (1 equivalent) |
| `chain.intent` (the typed ERC-20 transfer intent on `cancho-schema`: canonical form, digest, 13 stable refusals) | built | `scripts/check_intent.py`: 795 checks against a separate model, eth-utils and jsonschema, 44 of 48 mutants killed (4 redundant) |
| `chain.policy` and `chain.decide` (the policy engine: canonical policy and digest, a pure decision function, 14 stable reasons, a decision record and digest) | built | `scripts/check_policy.py`: 989 checks against a separate model and jsonschema, every combination of up to three reasons, 119 of 121 mutants killed (2 equivalent) |
| `chain.envelope` (the authorisation envelope: a decision bound to the exact unsigned transaction and signed by an issuer key; `issue`, the signer's `verify` with 10 ordered refusals, the single-use ledger) | built | `scripts/check_envelope.py`: 1,187 checks against a separate model, libsecp256k1 and python-ecdsa; every fault alone, in every pair and in every trio; every changed bit; 85 of 92 mutants killed (7 equivalent) |
| `signer` (`tools/signer`, `chain.signer`): a process that takes one request line, verifies the envelope, records it in a hash-chained `cancho-log` ledger (flushed before any signature exists) and signs; authority: one directory, the clock, stdio | built | `scripts/check_signer.py`: 764 checks against the envelope model, libsecp256k1, python-ecdsa, eth-account and an independent ledger reader; 14 kinds of ledger damage, none ever signs; **an anchor `(count, head)` in a second directory: nothing is signed that it does not cover** (a cut tail or a rewritten ledger is refused, a damaged last record is cut only if it was never signed; the anchor protects only if kept out of reach, design §19.2); 100 of 104 mutants killed (4 equivalent); **a witness: the front keeps the signer's last anchor and hands it back, so a restore of the signer's directory is refused** (design §20) |
| `front` (`tools/front`): `POST /sign` behind `cancho-gateway`; the caller is the gateway's `X-Auth-Identity`; starts the signer once per request; authority: one port in, one program to start, one directory (the witness, §20), nothing else | built | `scripts/check_front.py`: 173 checks with the real signer behind it, 96 mutants (93 killed, 3 equivalent); `scripts/check_stack.py`: 15 checks through the real gateway with three API keys |
| `chain.rpc` (the JSON-RPC requests and a strict reader of a provider's answers: a receipt, a transaction or a block is believed only if it says what was signed; 15 stable refusals) | built | `scripts/check_rpc.py`: 635 checks with transactions signed by eth-account, every truncation and 400 damaged responses (none traps); 106 of 118 mutants killed (12 equivalent) |
| `chain.lifecycle` (what a signed transaction is, as a pure function of the record last kept and what two providers say: nine states, a 74-byte canonical record, resubmit only the same bytes, final only on the same block, no decision on a disagreement) | built | `scripts/check_lifecycle.py`: 509 checks, 209,088 observations of the full product against a model **and ten properties as predicates**, random walks with a lying provider; 76 of 83 mutants killed (7 equivalent) |
| `executor` (`tools/executor`, `chain.executor`: one tick per process; two providers must agree, the lifecycle decides, the same bytes are re-sent, every change is evidence in a `cancho-log` trail; authority: one directory, two loopback addresses, the clock; plain HTTP only) | built | `scripts/check_executor.py`: 176 checks against two mock nodes (faults, lies, reorganisations, chain mismatch, damaged state and evidence); 72 of 78 mutants killed (6 explained, 1 of them not proven equivalent: design §18.5) |
| everything else in [`docs/design.md`](docs/design.md) | designed, not built | -- |

`scripts/gate.sh` runs the formatting, the file budget and every check below (without `--mutants`); CI runs it with the compiler pinned in `cancho.toml` built by cargo. That compiler's Rust evaluator cannot run cancho's `secp256k1` package's statics, so `check_signer.py` prints `SKIPPED` for the signer's `cancho authority` claim there; run it with a self-hosted compiler (`scripts/build-standalone.sh` in cancho) for that claim.

```
cancho test --std tests/keccak.cho lib/keccak/keccak.cho
cancho build --bin chain && printf abc | build/chain
4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
CHAIN=build/chain python3 -I scripts/check_keccak.py [--mutants]     # --mutants needs CANCHO=the compiler
CANCHO=the-compiler CANCHO_PACKAGES=../cancho/packages python3 -I scripts/check_eth.py [--mutants]   # needs pip install eth-account coincurve
CANCHO=the-compiler CANCHO_PACKAGES=../cancho/packages python3 -I scripts/check_decode.py [--mutants]
CANCHO=the-compiler CANCHO_SCHEMA=../cancho-schema/src/schema.cho python3 -I scripts/check_intent.py [--mutants]   # needs pip install eth-account jsonschema
CANCHO=the-compiler python3 -I scripts/check_lifecycle.py [--mutants]
CANCHO=the-compiler CANCHO_PACKAGES=../cancho/packages CANCHO_SCHEMA=../cancho-schema/src/schema.cho CANCHO_LOG=../cancho-log/src python3 -I scripts/check_executor.py [--mutants]   # the real binary against two Python mock nodes
CANCHO=the-compiler python3 -I scripts/check_rpc.py [--mutants]   # needs pip install eth-account eth-abi rlp eth-utils pycryptodome
CANCHO=the-compiler CANCHO_PACKAGES=../cancho/packages CANCHO_SCHEMA=../cancho-schema/src/schema.cho CANCHO_LOG=../cancho-log/src python3 -I scripts/check_signer.py [--mutants]   # the real binary; needs cancho-log checked out too
CANCHO=the-compiler CANCHO_PACKAGES=../cancho/packages CANCHO_SCHEMA=../cancho-schema/src/schema.cho python3 -I scripts/check_envelope.py [--mutants]   # needs pip install coincurve ecdsa pycryptodome eth-account eth-abi rlp eth-utils
```

[`docs/design.md`](docs/design.md) holds the feasibility findings against the actual cancho tree (what exists, what is missing), the trust boundaries, the
threat model and the build order. It is written to be corrected in place as claims are measured.

Licence EUPL-1.2, copyright Alpibru S.L.
