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

## 8. Ethereum encodings (slice 2): addresses, RLP, ERC-20 calldata, type-2 transactions

**Status: built.** Measured numbers are in §8.3. Everything the signer will eventually be asked to sign has to be produced, and later checked, byte for byte.

### 8.1 What is built, and the choices

- `chain.hex`: encode and decode, lowercase output, either case accepted on input. A bad length or digit is a refusal, never a trap.
- `chain.address`: the 20-byte address of a public key (`keccak256(x || y)[12..]`), the EIP-55 checksummed text, and parsing text back. **[choice]** A parsed address is
  exactly `0x` + 40 hex digits (no `0X`, no bare 40 digits, no ENS); all-lowercase and digits-only text are accepted as *unchecked*; mixed case must match its EIP-55
  checksum; **all-uppercase is refused**, since it claims a checksum it does not have. Policies compare the 20 bytes, never the text.
- `chain.rlp`: encoders over a caller-provided output slice and a position, returning the new position or a refusal (`rlp-overflow` when the slice is too small). Integers
  are minimal big-endian; zero is the empty string. No decoder yet (the final-transaction validator needs one, §7 step 4; it is the next slice).
- `chain.erc20`: `transfer(address,uint256)` calldata, 68 bytes, selector `a9059cbb`.
- `chain.tx1559`: an EIP-1559 (type 2) transaction as `body` (the nine fields, access list empty), the unsigned message `02 || rlp(body)` whose Keccak-256 is what is signed, and the
  signed message `02 || rlp(body, y_parity, r, s)`. **[choice]** Fields are byte strings and small integers the caller has already validated; a value, a fee or a calldata
  is never a float and never wider than 32 bytes. An access list is always empty in the MVP (a non-empty one is a refusal at the intent, not here).
- Signing is `secp256k1.sign` from the cancho repository (`packages/secp256k1`, PR alpibrusl/cancho#710). **Interim dependency [choice]:** cancho's package manager pulls
  from a published, hash-checked store at a pinned commit, and that package is neither merged nor published, so the oracle scripts build against a sibling checkout named by
  `CANCHO_PACKAGES` (default `../cancho/packages`). When it is published this becomes a `[dependencies.secp256k1]` entry in `cancho.toml`.

### 8.2 How it is checked

`scripts/check_eth.py` builds `tools/ethdrv/main.cho` and compares it with `eth-account` (and `rlp`, which it depends on) on: the address of a key (against `Account.from_key(..).address`, checksummed),
EIP-55 on the specification's own vectors and on random addresses, parse and refuse cases, RLP against `rlp.encode` on strings and integers across every length boundary
(0, 1, 55, 56, 255, 256, 65535, 65536 bytes), ERC-20 calldata, and whole type-2 transactions (unsigned message, signing hash, signed raw transaction and transaction hash) against
`Account.sign_transaction` with random fields. `--mutants` rebuilds with one deliberate fault at a time; every mutant must be killed.

### 8.3 Measured

**[measured]** 2026-11-06, Linux x86-64, the self-hosted `cancho` (stage 2 = stage 3) at `162633a7`, `eth-account` 0.13 / `eth-abi` / `rlp` from pip, `secp256k1` from PR alpibrusl/cancho#710
at its head. `CANCHO=<compiler> CANCHO_PACKAGES=<cancho>/packages python3 -I scripts/check_eth.py --cases 40`: **531 of 531** checks agree.

- EIP-55: the eight addresses of the specification (mixed case, all-caps and all-lowercase: the all-caps ones are refused by design, §8.1), 40 random keys' addresses against
  `Account.from_key(..).address` (and the lowercase and checksummed forms parsed back), a single flipped letter's case refused whenever the result is still mixed, and the
  refusals: no prefix, `0X`, 41 and 43 characters, a non-hex character, all-uppercase, digits-only accepted, a compressed-prefix or short public key.
- RLP against `rlp.encode`: lists of one string of 0, 2, 54, 55, 56, 57, 255, 256, 257 and 1,000 bytes; every single byte value that matters (00, 01, 7f, 80, ff); 40 random lists of up
  to 8 strings with lengths at the boundaries; two long-list headers (one-byte length and two-byte length); 40 random unsigned integers of 0 to 256 bits with and without leading zeros.
- ERC-20 `transfer` calldata against `eth-abi` and the selector from `eth-utils` (40 random recipients and amounts of 0 to 256 bits), and the 19-byte recipient and 33-byte amount refusals.
- Type-2 transactions: 40 random ones (chain id, nonce, fees, gas, recipient, value of 0 to 256 bits, data of 0 to 200 bytes), each signed with `Account.sign_transaction`:
  our signing hash equals `TypedTransaction.hash()`, our unsigned message hashes to it, our signed raw transaction and our transaction hash are **byte for byte** `eth-account`'s, and
  `Account.recover_transaction` of our bytes gives the signer's address. Refusals: a 19-byte `to`, a 33-byte value; the signed-message encoder alone with recovery ids 0 and 1 (accepted),
  2 and 255 (refused) and a 64-byte signature.
- `--mutants`: 29 deliberate faults (every RLP threshold, base byte and byte order; the checksum's threshold and nibble order; the address's offset and its hashing the prefix; the
  acceptance of mixed case unchecked, all-caps, `0X` and non-hex; the selector, the offsets and the alignment of the calldata; the type byte, a missing access list, swapped
  fields, y parity, r and s; a wider value and an accepted recovery id; uppercase hex digits): **29 of 29 killed**. A first run killed 28: the recovery-id-2 refusal was reachable
  only by a signature a signer almost never produces, so the driver gained `M`, which feeds the encoder one the script crafts.

**Not claimed.** No decoder, so nothing here yet checks *a transaction someone else built*; that is the final-transaction validator, the next slice. The intent, the policy and the signer
as a separate process are not built. `secp256k1` is from an unmerged PR (§8.1).

## 9. The decoder and the final-transaction validator (slice 3)

**Status: built.** Results are in §9.3. The signer must never sign bytes it has not read. The policy engine approves an *intent*; the builder turns it into bytes; this
module reads those bytes back, with a decoder that shares no code with the encoder, and refuses unless every field is what was authorised (§5: "validate the final serialized
transaction, not the intent that was meant to produce it").

### 9.1 The decoder (`chain.rlp.item`)

`item(data, pos, end, meta)` reads one item at `pos` within `[pos, end)` and puts its kind (0 string, 1 list), payload start and payload end in `meta[0..3]`; it answers the position
after the item, or a refusal. **[choice]** It is *strict*: the encoding of a value is unique, so any other is refused, because a transaction whose bytes differ from the canonical ones
for the same fields hashes differently and could be used to smuggle a second reading past a validator:
- `rlp-truncated` (-152): the item or its length runs past `end`;
- `rlp-noncanonical` (-153): a one-byte string below 0x80 written with a header, a long form for a length under 56, a length with a leading zero byte;
- `rlp-oversized` (-154): a length of more than seven bytes (more than 2^56, which no transaction reaches). Lengths are compared as `len > end - start`, never added, so nothing overflows.
`rlp.whole(data)` is `item` over all of `data` and answers 0 only when exactly one item fills it (trailing bytes are `rlp-trailing`, -155).

### 9.2 The validator (`chain.txcheck`)

`validate_unsigned(raw, ...)` for the message about to be hashed and signed, and `validate_signed(raw, ...)` for the bytes about to be submitted. The expectation is what the policy authorised:
chain id, nonce, the token contract, the recipient, the amount (big-endian), a fee cap (max fee per gas, big-endian) and a gas cap. It reads `raw` as `02 || list` of exactly nine fields (twelve
when signed) and checks, in this order, answering the **first** that fails with a stable code:

| code | tag | when |
|---|---|---|
| -180 | `tx-format` | not one canonical list of nine (twelve) items, trailing bytes, a string where a list belongs or the reverse, an integer with a leading zero, an integer wider than its field allows |
| -181 | `tx-type` | the first byte is not 0x02 |
| -182 | `tx-chain-id-mismatch` | chain id differs |
| -183 | `tx-nonce-mismatch` | nonce differs |
| -184 | `tx-to-mismatch` | `to` is not the token contract (a contract creation, an empty `to`, is this too) |
| -185 | `tx-value-not-zero` | an ERC-20 transfer sends no native value |
| -186 | `tx-data-length` | the calldata is not 68 bytes |
| -187 | `tx-selector` | the first four bytes are not `a9059cbb` |
| -188 | `tx-recipient-padding` | the 12 bytes before the recipient are not zero |
| -189 | `tx-recipient-mismatch` | the recipient differs |
| -190 | `tx-amount-mismatch` | the amount differs |
| -191 | `tx-access-list` | the access list is not empty |
| -192 | `tx-fee-cap` | max fee per gas is above the cap |
| -193 | `tx-gas-cap` | gas limit is above the cap |
| -194 | `tx-fee-order` | max priority fee is above max fee |
| -195 | `tx-signature` | (signed) y parity above 1, or r or s zero or wider than 32 bytes |

**[choice]** It does not verify the signature (that is `secp256k1.recover` and a comparison with the signer's address, at the gateway), and it does not judge whether the fee is *sensible*, only
whether it is within what the policy allowed. The codes are the proposal's `CHAIN_ID_MISMATCH` and `TRANSACTION_DIGEST_MISMATCH` family in the stable kebab form of §5.

### 9.3 How it is checked

`scripts/check_decode.py` against `rlp` (strict mode) and `eth-account`, with the same `--mutants` discipline as the encoders: (1) **accept/reject agreement** with `rlp.decode(strict=True)` on
random byte strings, on every one-byte mutation of valid encodings and on the length-boundary encodings; (2) every valid transaction the encoders make validates, unsigned and signed; (3) for each of the
sixteen codes, a transaction tampered in exactly that field is refused with exactly that code; (4) malformed encodings are refused as `tx-format`.

**[measured]** 2026-11-06, Linux x86-64, the self-hosted `cancho` at `162633a7`, `rlp` and `eth-account` from pip, `secp256k1` from alpibrusl/cancho#710 at its head.
`CANCHO=<compiler> CANCHO_PACKAGES=<cancho>/packages python3 -I scripts/check_decode.py --cases 30`: **1,423 of 1,423** checks agree.
- **Decoder against `rlp.decode(strict=True)`:** 30 random nested encodings (each valid), and for each a truncation, an appended byte, a duplicated first byte, a replaced byte, a deleted byte and
  an inserted byte; 60 random byte strings; 36 length-boundary encodings (every long-form edge: 55, 56 and 57 bytes, the two-byte and three-byte lengths, leading zero length bytes, eight-byte lengths).
  Accept/reject agree on every one. 20 more cases check the *reason* (`rlp-truncated`, `rlp-noncanonical`, `rlp-oversized`, `rlp-trailing`), which `rlp` cannot give.
- **Validator:** 30 random ERC-20 transfers (chain id, nonce, fees, gas, token, recipient, amounts of 0 to 256 bits) validate unsigned and signed (signed by `eth-account`), and also as built and signed
  by our own encoder and signer; an amount in the expectation padded to 32 bytes with zeros is the same number; 13 single-field tamperings, each as unsigned and as signed, are refused with exactly
  the code of that field (chain id, nonce, `to`, a contract creation, value, calldata one byte short and one long, selector, padding, recipient, amount low and high byte, access list); fee and gas above their caps,
  priority above max fee, and two faults at once answering the first in the table. Also: fee and gas *equal* to their caps (accepted), a token whose first byte is zero (and a 19-byte `to` equal to it
  without that byte, refused), padding nonzero at its first and last byte, a recipient differing at its first and last byte, chain id, nonce and gas at 2^63 + 5 and of nine bytes, nine signature-field cases
  (y parity 2 and 255, r or s zero, 33 bytes, a leading zero, a list), 23 malformed encodings (empty, type 1, 3 and 0x7f, a legacy list, truncated, trailing byte, 8, 10, 13 and 20 items, signed given for unsigned
  and the reverse, `to`/data/chain id as a list, the access list as a string, leading-zero integers, a 33-byte value, a lying header, an outer string holding the items), and a malformed expectation.
- `--mutants`: 51 deliberate faults (every threshold and base of the decoder, its canonical-form checks, its truncation arithmetic and its trailing-byte check; and, in the validator, the type byte, the
  list and item-count checks, each width, each of the field-shape checks, the 2^63 edges, every comparison, each selector and padding byte, the cap comparators, the fee order, each signature check, the
  leading-zero handling of the comparison and the expectation's sizes): **50 killed, 1 equivalent** (a bound that only keeps the field table in range; the item count is compared after, so the same code answers).
  Reaching that took three runs: a first run killed 39 of 51 and showed that several faults change only the *reason* (so agreement with `rlp` cannot see them), that the harness counted a trap as a
  plain refusal, and that some inputs were missing (a token starting with a zero byte, `fee == cap`, padding at its first and last byte, an outer string, a long-form length of exactly 55); two mutants
  did not build and were rewritten.

**Not claimed.** The signature is not verified (that is `secp256k1.recover` and a comparison with the signer's address, at the gateway, next to the single-use authorization). The validator is for one
shape of transaction, an ERC-20 `transfer` in EIP-1559 form; other shapes (native transfers, approvals, arbitrary calls) are refused as `tx-data-length` or `tx-selector`, not understood. It does not judge
whether the fee is *sensible*, only that it is within what was authorised.

## 10. Open questions for the maintainer

1. secp256k1: build it in cancho core (preferred) or here first? Are fallbacks acceptable if it proves too large?
2. May `cancho-chain` depend on `cancho-schema` (a package dependency) or is vendoring preferred? How do sibling repos consume each other (`cancho.toml` has no
   dependency section in cancho-opt)?
3. Is the Linux x86-64 seed expected to land in `cancho`, so CI can start without Rust?
