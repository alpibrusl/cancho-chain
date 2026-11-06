# cancho-chain

An auditable authority and execution layer for autonomous blockchain agents, in pure [cancho](https://github.com/alpibrusl/cancho).

An agent may *propose* a transaction. A separately enforced policy decides whether it is allowed. A signer, in its own process, signs only the exact
bytes that were approved. Every step leaves evidence. The agent never holds a key and cannot change its own policy.

**Status: research, phase 0.** Nothing here moves value yet. What exists, and how it is checked:

| Piece | State | Check |
|---|---|---|
| `chain.keccak`, Keccak-256 (Ethereum's padding, not SHA-3's) | built | `scripts/check_keccak.py`: 425 inputs against pycryptodome, 12 of 12 mutants killed |
| everything else in [`docs/design.md`](docs/design.md) | designed, not built | -- |

```
cancho test --std tests/keccak.cho lib/keccak/keccak.cho
cancho build --bin chain && printf abc | build/chain
4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
CHAIN=build/chain python3 -I scripts/check_keccak.py [--mutants]     # --mutants needs CANCHO=the compiler
```

[`docs/design.md`](docs/design.md) holds the feasibility findings against the actual cancho tree (what exists, what is missing), the trust boundaries, the
threat model and the build order. It is written to be corrected in place as claims are measured.

Licence EUPL-1.2, copyright Alpibru S.L.
