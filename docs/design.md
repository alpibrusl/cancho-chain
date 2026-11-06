# cancho-chain: design

Status: **phase 0, research.** Written before the code it judges. Every claim carries one of three marks:

- **[measured]** with the command that measures it;
- **[read]** taken from a named file or document and not re-run here;
- **[choice]** a decision made here, with its reason; **[open]** not decided or not yet known.

A claim found false is corrected here, in place. Dates: measured on 2026-11-06, Linux x86-64, cancho at `162633a7` (`main`).

## 1. What this is, and what it is not

The claim to demonstrate, and the only one:

> An autonomous agent can propose a blockchain transaction, but the authority to execute it is independently constrained, checked and evidenced.

Not a blockchain, not a wallet, not a smart-contract language, not a proof that a policy is wise. Out of scope for the MVP: multisig, cross-chain,
zero-knowledge proofs, a contract compiler, token approvals (an unlimited allowance is far more authority than one transfer). **[choice]**

First target: ERC-20 `transfer` on one EVM test network (Sepolia, chain id 11155111). The first public demonstration shows a permitted payment **and**
the refusals of everything else; a payment alone proves nothing. **[choice]**

## 2. The rule: pure cancho

The shipped package is cancho. Python is for oracles, benchmarks and helper scripts only (`scripts/`). If a component cannot be cancho it is isolated
behind a narrow interface and the reason is written here. The compiler used is the self-hosted one. **[choice, from the maintainer]**

**The self-hosted compiler builds here. [measured]**
`cargo build --release -p cancho` (stage 0, 75 s) then `scripts/build-standalone.sh --cancho0 target/release/cancho --out DIR --rev $(git rev-parse HEAD)`:
stage 1 by the Rust build, stage 2 by stage 1, stage 3 by stage 2, and the script fails unless stage 2 equals stage 3 (it did; sha256
`ebef5ca1ff9a795a2fe6b3b1fe80f4e5433a4572b06dfd4cdc5313a5ab4ba160`, 2 min 10 s). `cancho --version` reports `rev 162633a7`.
Finding: `seed/` in that checkout holds only `aarch64-apple-darwin`, so a Linux x86-64 machine cannot yet start from the seed (`docs/seed.md` S1 lists the
other two as written elsewhere, not committed here); the Rust stage 0 was needed. `cancho.toml` pins the commit, as cancho-opt and cancho-gpu do.

## 3. What the existing tree gives, and what it does not

**Exists in `std/` [read; none of these re-run]:** `http` (client and server), `conns`, `udps`, `route`; `json`; `crypto` (SHA-256/384/512), `hmac`, `hkdf`;
`ed25519`, `x25519`, `ecdh`, `ecdsa` and constant-time `ecdsa_sign` for P-256 (`docs/ecdsa-sign.md`), `rsa`, `aes`/`gcm`/`chacha20`; `bigmod`
(`std/bigmod.cho`, 669 lines, used by RSA and P-256), `process`, `signals`, `test`; checked 64-bit `int` (an overflow traps, `docs/defined-behaviour.md`);
`cancho authority` reports what a binary can reach (`docs/authority.md`). TLS (`docs/tls-*.md`) is what an RPC client over `https` needs.

**Does not exist [measured: `grep -rIli 'keccak\|sha3\|secp256k1' std docs packages` finds no Keccak and no secp256k1; `docs/ecdsa.md` names only `secp256r1`/`secp384r1`]:**

| Need | Where it goes | Size, honestly |
|---|---|---|
| **Keccak-256** | `cancho-chain` (`lib/keccak`) | **built** this phase, section 4 |
| **secp256k1 ECDSA with public-key recovery** (RFC 6979, low-s, recovery id) | **cancho core** (general crypto) once it exists; here until then **[open]** | the critical path. `std/p256*` plus `ecdsa_sign` are about 4,900 lines for P-256, much of it performance work (`docs/p256-fast.md`: 20x). A first secp256k1 need not be fast but must be constant time in the secret scalar and checked against vectors. Whether `bigmod` is generic over the modulus (secp256k1's p and n) is **[open]**, to be read before estimating |
| RLP, EIP-1559 (type 2) transaction encoding, ABI encoding of `transfer(address,uint256)` | `cancho-chain` | small, byte manipulation, oracle `eth-account` |
| 256-bit unsigned amounts | `cancho-chain` | `std.bignum` is **not** this: its header says "only as wide as `std.fmt` needs", no multiply, no divide **[read]**. Amounts and limits need add, subtract, compare, parse and print of 256-bit values; `bigmod` may cover it **[open]** |
| JSON canonical form | `cancho-chain` | do not canonicalise JSON *bytes*; parse into typed fields and canonicalise those (section 5) **[choice]** |
| Process isolation of the signer | `std.process` + a unix or loopback socket | **[open]**: needs a capability grant that gives the agent-facing binary no key file and no `exec`; `cancho authority` on both binaries is the evidence |

If secp256k1 does not come, the only honest fallbacks are a native signer behind the narrow signing interface (breaks the pure-cancho rule, needs your
decision) or a non-EVM demo chain (Ed25519 exists), which weakens the pitch. **[choice: ask before taking either]**

**Siblings that help [read, from their READMEs; not yet built here]:**
- `cancho-schema`: a schema as data; validates a JSON body and reports **every** error with a JSON Pointer; `cancho authority` on a validator reports `heap` and
  nothing else. Candidate for the intent parser (section 5), so a malformed intent is refused with all its faults at once. **[open: adopt after reading it]**
- `cancho-web`: typed routes, `problem+json`, an OpenAPI document generated from the same declaration, on `http.server`. Candidate for the agent-facing
  API (phase 5) and for publishing the policy decision surface as a checked artifact. Not before phase 5. **[open]**
- `cancho-opt`, `cancho-gpu`, `cancho-hdl`, `cancho-ui`: no use here; their conventions (CLAUDE.md, rule tags, mutants, 2,000-line limit) are copied.

## 4. Keccak-256 (built)

`lib/keccak/keccak.cho`, module `chain.keccak`. Ethereum's Keccak-256: rate 136, padding `0x01 ... 0x80` (the SHA-3 standard's is `0x06`, which gives
different digests; the mutant that swaps them is killed). A 64-bit lane is two words in `[0, 2^32)` because `int` is signed 64-bit and `>>` is arithmetic
(the way `std.crc` holds a CRC-64); every shift is of a value under 2^32 by at most 31, so nothing overflows or traps. The caller provides `state_len()` = 110
words; the function allocates nothing, zeroes the state before and after, and refuses a digest buffer that is not 32 bytes (`keccak-output-length`, -90) or
a state shorter than 110 words (`keccak-state-length`, -91).

**Checks [measured].**
- `cancho test --std tests/keccak.cho lib/keccak/keccak.cho`: the empty string and `"abc"`, and the two refusals (a 31-byte output buffer is refused and left
  untouched; 109 words of working space is refused), 4 of 4.
- `CHAIN=build/chain python3 -I scripts/check_keccak.py`: every length 0 to 420 (crosses the 135/136/137, 271/272/273, 407/408/409 block edges), two
  1000-byte inputs and random inputs of 4,096 and 65,537 bytes, **425 of 425** equal to pycryptodome's `keccak(digest_bits=256)`.
- `CANCHO=<compiler> python3 -I scripts/check_keccak.py --mutants`: 12 faults (SHA-3 padding, missing final bit, rate 135, a rho offset, two round constants,
  theta rotation, chi without the complement, iota skipped, 23 rounds, a wrong pi, a lane-half boundary), **12 of 12 killed**.

**Not claimed.** Constant time is irrelevant for a public-data hash. Throughput is not measured and is not a goal (the proposal's own rule). Not independently
reviewed.

## 5. Architecture and trust boundaries

Components, in the order a request crosses them: intent parser and canonicaliser; policy engine; transaction builder and **final** validator; signing
gateway (own process, own trust zone); RPC submission; evidence and reconciliation. Authorization, signing, submission and settlement are separate states
and separate evidence events: a policy `allow` is not a payment.

- The agent is untrusted; its output is data, never authority.
- The policy engine is security-critical. It fails closed when identity, policy, chain configuration or a validation result is missing or inconsistent.
- The builder is security-critical too: the **serialised transaction bytes** are validated (decode them back and check chain id, `to`, selector, recipient,
  amount, nonce, fee fields), not just the intent that was meant to produce them.
- A decision is bound to the exact transaction digest, chain id, policy digest, caller identity, expiry and nonce. It cannot authorise another transaction.
- The signer verifies independently: caller, expiry, digest, chain id, key id, single use. It exposes no arbitrary-sign operation and no key.
- The RPC provider is an external, untrusted source for facts; chain identity is checked, and a receipt is "asserted by provider X at time T".
- Evidence is append-only with a hash chain (a signed checkpoint later); it is not the blockchain's history.

**Canonical forms [choice].** Hashed or signed data is a fixed binary layout over typed fields, never serialised JSON: an address is 20 bytes (parsed from
`0x` hex, EIP-55 checksum **verified** when mixed-case, lowercase accepted), a chain id and amounts are unsigned integers parsed from decimal strings with no
sign, no leading zeros, no exponent and no float, an amount carries its token's decimals from the policy, and unknown fields are a refusal, not ignored.

**Refusal reason codes (stable, machine-readable)** start from the proposal's list: `CHAIN_NOT_ALLOWED`, `ASSET_NOT_ALLOWED`, `RECIPIENT_NOT_ALLOWED`,
`AMOUNT_LIMIT_EXCEEDED`, `DAILY_LIMIT_EXCEEDED`, `POLICY_EXPIRED`, `AUTHORIZATION_REPLAYED`, `TRANSACTION_DIGEST_MISMATCH`, `CHAIN_ID_MISMATCH`,
`SIGNER_UNAVAILABLE`. The compiler-facing tag form is `chain.<name>`, exit status 2, a repair string; `tests/reject/` gets a fixture per tag and a gate fails on a
tag without one (cancho-gpu's pattern). **[choice]**

## 6. Threat model (MVP)

Objectives: the agent cannot raise its own authority or sign arbitrary transactions; an authorisation cannot be replayed or applied to a different
transaction; fields cannot change between approval and signing; a dependency failure never becomes an authorisation; retries and timeouts cannot silently
pay twice; evidence separates decided, signed, submitted, included and final.

| Threat | Mitigation | Check (planned) |
|---|---|---|
| Prompt injection / compromised agent | policy enforced outside the model; intent is data | adversarial intents refused |
| Different recipient, asset, chain, amount | allowlists; exact integers; chain id in the digest | one test per substitution |
| Mutation after approval | authorisation bound to the exact serialised-transaction digest; signer recomputes it | flip each field, signer refuses |
| Replay | unique authorisation id, expiry, consumption record, nonce | second use refused |
| Policy self-modification | policy admin authority is separate from execution authority; policy has an immutable digest | `cancho authority` of the agent-facing binary |
| Signer compromise | separate process, narrow API, rate limit, audit | key file unreachable from the agent binary |
| Duplicate payment after a timeout | idempotency key, nonce tracking, reconcile before retry | kill and retry tests |
| RPC lies or disagrees | chain-id check; second source for critical reads | inconsistent-RPC fixture |
| Reorg / late finality | explicit lifecycle; per-chain finality rule | reorg fixture |
| Evidence tampering | append-only, hash chain | edit one record, verification fails |

**Not proved, and said so in every release:** that an invoice or supplier is genuine, that a token is safe, that an approved contract has no bug, that a
policy matches the organisation's intent, that an RPC provider is honest, that a transfer can be reversed, that an application is secure because it uses
cancho. A local development key is a development key; nothing here claims production key management.

## 7. Build order and gates

1. **Keccak-256, EIP-55 addresses, RLP, ABI `transfer`, type-2 transaction encoding**, each against `eth-account`/vectors with mutants. (Keccak done.)
2. **Typed ERC-20 intent**: parse, canonicalise, refuse, with adversarial inputs.
3. **Policy engine** and its refusal suite *before any signer exists*; decisions reproducible from recorded inputs.
4. **secp256k1 + recovery** (the decision in section 3), then the **exact unsigned transaction**, its digest, and the final validator.
5. **Signing gateway**, a second binary; the agent binary's `cancho authority` shows no key access.
6. **Testnet execution**, lifecycle, idempotency, reconciliation, evidence log, inspection command.
7. Hardening, independent review, maturity statement. No production claim without review.

A gate is written before the code it judges and must be able to fail.

## 8. Open questions for the maintainer

1. secp256k1: build it in cancho core (preferred) or here first? Are fallbacks acceptable if it proves too large?
2. May `cancho-chain` depend on `cancho-schema` (a package dependency) or is vendoring preferred? How do sibling repos consume each other (`cancho.toml` has no
   dependency section in cancho-opt)?
3. Is the Linux x86-64 seed expected to land in `cancho`, so CI can start without Rust?
