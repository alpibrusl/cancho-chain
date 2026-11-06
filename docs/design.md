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
  checksum, and **so must any text with an uppercase letter**: it claims a checksum, so it has to be the one EIP-55 gives (an address whose checksum happens to be all capitals, as two of the specification's own vectors are, is valid;
the all-capitals spelling of any other address is refused). *Corrected in place:* this document first refused all-uppercase text outright, reading the specification's "all caps" vectors as invalid spellings when they are valid checksummed
addresses; found when a random policy's address, whose correct checksum is all capitals, was refused by the policy tests of slice 5. Policies compare the 20 bytes, never the text.
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

- EIP-55: the eight addresses of the specification (mixed case, all-caps and all-lowercase, all accepted: the two all-caps ones are checksummed addresses whose checksum is all capitals, §8.1), 40 random keys' addresses against
  `Account.from_key(..).address` (and the lowercase and checksummed forms parsed back), a single flipped letter's case refused whenever the result is still mixed, and the
  refusals: no prefix, `0X`, 41 and 43 characters, a non-hex character, the all-capitals spelling of an address whose checksum is not all capitals, digits-only accepted, a compressed-prefix or short public key.
- RLP against `rlp.encode`: lists of one string of 0, 2, 54, 55, 56, 57, 255, 256, 257 and 1,000 bytes; every single byte value that matters (00, 01, 7f, 80, ff); 40 random lists of up
  to 8 strings with lengths at the boundaries; two long-list headers (one-byte length and two-byte length); 40 random unsigned integers of 0 to 256 bits with and without leading zeros.
- ERC-20 `transfer` calldata against `eth-abi` and the selector from `eth-utils` (40 random recipients and amounts of 0 to 256 bits), and the 19-byte recipient and 33-byte amount refusals.
- Type-2 transactions: 40 random ones (chain id, nonce, fees, gas, recipient, value of 0 to 256 bits, data of 0 to 200 bytes), each signed with `Account.sign_transaction`:
  our signing hash equals `TypedTransaction.hash()`, our unsigned message hashes to it, our signed raw transaction and our transaction hash are **byte for byte** `eth-account`'s, and
  `Account.recover_transaction` of our bytes gives the signer's address. Refusals: a 19-byte `to`, a 33-byte value; the signed-message encoder alone with recovery ids 0 and 1 (accepted),
  2 and 255 (refused) and a 64-byte signature.
- `--mutants`: 29 deliberate faults (every RLP threshold, base byte and byte order; the checksum's threshold and nibble order; the address's offset and its hashing the prefix; the
  acceptance of any uppercase text unchecked, `0X` and non-hex; the selector, the offsets and the alignment of the calldata; the type byte, a missing access list, swapped
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
  Accept/reject agree on every one **at the header**. *Corrected 2026-11-06:* this paragraph first said the decoder agrees with `rlp.decode(strict=True)` on these, which is false in general. `item` reads one header and never looks inside a list
  (`txcheck` walks the payload field by field and refuses it there, `tx-format`), so a list with a canonical header over a payload that is not canonical is accepted by `rlp.whole` and refused by `rlp.decode`. The default seed never produced one; running the
  same script with `--cases 20` did (`c681e7aeb82ad4`: a list of six bytes whose second item announces 46). `scripts/check_decode.py` now compares the header with a reference written from the specification where `rlp` cannot answer, and the other
  cases with `rlp`; 983, 1,423, 2,303, 4,503 and 8,903 checks agree for `--cases` 20, 30, 50, 100 and 200. 20 more cases check the *reason* (`rlp-truncated`, `rlp-noncanonical`, `rlp-oversized`, `rlp-trailing`), which `rlp` cannot give.
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

## 10. The typed intent (slice 4)

**Status: built.** Results are in §10.4. The agent's output is data, never authority (§5). This is where it becomes a typed, canonical value, or is refused.

### 10.1 The wire format and the schema

The agent sends one JSON object. **[choice]** It carries *addresses*, not names: a name such as `approved_supplier_01` would be one more thing to resolve, and an alias that resolves to the wrong
address is a new way to be wrong; names belong in the policy's allowlist as labels for humans and evidence.

```
{"kind":"erc20_transfer","chain_id":11155111,"asset":"0x...40 hex...","recipient":"0x...40 hex...","amount":"250000000","reference":"invoice-2026-0042","request_id":"2026-0042-a"}
```

The structure is declared once with `cancho-schema` (`alpibrusl/cancho-schema`, a schema as data that validates a body, reports **every** error with a JSON Pointer, and exports the same schema as JSON Schema 2020-12), as a strict object:
unknown keys are refused (so there is no `from`, `gas_price`, `spender`, `data`, `to` or `value` for an agent to smuggle), and `kind` is the single choice `erc20_transfer`, `chain_id` an integer from 1 to 2^53 - 1 (the largest integer
JSON carries without loss), `asset` and `recipient` strings of exactly 42 characters, `amount` a string of 1 to 78 characters (a uint256 has at most 78 decimal digits), `reference` and `request_id` strings of 1 to 64 characters.
An amount is a **string** of **base units** (6-decimals USDC: `"250000000"` is 250), never a number and never decimals: a JSON number is a float in half the world's parsers. `request_id` is the agent's idempotency key (§6: a retry after a timeout must not pay twice).

### 10.2 What the schema cannot say, and the code that does

`cancho-schema` has types, ranges, lengths and choices but no patterns, so a second stage reads the validated fields and refuses what the schema lets through. **[choice]** Strings are plain ASCII with no JSON escape (a `\u0041` that decodes to
`A` is two spellings of one value), and **duplicate keys are refused**: `std.json` and `cancho-schema` let the first win, which is deterministic here and exactly what a log reader or an audit tool taking the last one would disagree about.
Bodies larger than 4 KiB are refused before they are parsed (§6: bounded inputs). The fields are read in the order chain id, asset, recipient, amount, reference, request id, and the first check that fails answers; a schema failure also has `intent.explain`, the RFC 9457 `problem+json` body listing every error.

| code | tag | when |
|---|---|---|
| -200 | `intent-json` | not valid JSON (strict RFC 8259 and UTF-8), or not one object |
| -201 | `intent-schema` | the structure: a missing or unknown key, a wrong type, a range, a length, a kind other than `erc20_transfer` |
| -202 | `intent-asset` | not `0x` and 40 hex digits, bad EIP-55 checksum (including an all-capitals spelling that is not the checksum's), an escape (`chain.address.parse`'s rules, §8.1) |
| -203 | `intent-recipient` | the same, for the recipient |
| -204 | `intent-amount` | not canonical decimal digits (a sign, a leading zero, a point, an exponent, a space, a non-digit), or above 2^256 - 1 |
| -205 | `intent-amount-zero` | zero: a transfer of nothing is a probe, not a payment |
| -206 | `intent-reference` | a character outside `A-Z a-z 0-9 . _ : -`, or an escape |
| -207 | `intent-request-id` | the same, for the request id |
| -208 | `intent-duplicate-key` | a key twice |
| -209 | `intent-key-escape` | a key written with an escape |
| -210 | `intent-output` | the caller's output slice is shorter than `max_len()` |
| -211 | `intent-work` | the Keccak working space is shorter than `keccak.state_len()` |
| -212 | `intent-size` | more than 4,096 bytes |
| -213 | `intent-number` | the chain id is written with a fraction or an exponent (`1.0`, `1e2`): JSON Schema calls those integers, but no float is parsed on this path, and a number has one spelling |

### 10.3 The canonical form

**[choice]** What is hashed, compared and recorded is never the JSON (ambiguous by nature, §7.3) but a fixed binary layout of the typed fields, version 1: byte 0 the layout version (1), byte 1 the kind (1, `erc20_transfer`), bytes 2 to 10 the
chain id (8 bytes, big-endian), 10 to 30 the asset (20 bytes), 30 to 50 the recipient (20), 50 to 82 the amount (a uint256, 32 bytes big-endian), then the reference as a length byte and its bytes, then the request id likewise: at most 212 bytes.
The **intent digest** is `keccak256("cancho-chain/intent/v1" || canonical)`: a different layout or a different protocol cannot produce the same digest. The same intent spelled differently (the checksummed and the lowercase address,
reordered keys, any whitespace) has one canonical form and one digest.

### 10.4 How it is checked

`scripts/check_intent.py` against an independent implementation in Python (the spec above, written separately, with `eth-utils` for addresses and `jsonschema` for the structure): accept/reject agreement and the canonical bytes and digest of every accepted
intent, on valid intents in every spelling, on each field damaged in each way the table names, on random JSON, and on every duplicate-key and escape case; the exported JSON Schema is validated as Draft 2020-12 and agrees with the structure stage on random
documents. `--mutants` as for the other slices.

**[measured]** 2026-11-06, Linux x86-64, the self-hosted `cancho` at `162633a7`, `cancho-schema` at `ab15474`, `eth-utils` and `jsonschema` 4.26 from pip.
`CANCHO=<compiler> CANCHO_SCHEMA=<cancho-schema>/src/schema.cho python3 -I scripts/check_policy.py --cases 20`: **989 of 989** checks agree.
- **The policy:** 20 random policies (ids and principals of 1 to 64 characters over every allowed character, versions to 2^32 - 1, chain ids to 2^53 - 1, 1 to 32 recipients, limits to 2^256 - 1, with and without an approval threshold), each in three
  forms (as generated; keys shuffled and indented; addresses in lowercase), all giving the model's canonical bytes and digest; and 125 damaged or edge-case policies, each refused with exactly its code or accepted when it is a boundary:
  each of the 19 required fields missing, an unknown key in the policy and in each of its four objects, wrong types and out-of-range numbers (version 0 and 2^32, decimals 37, ttl 0 and 3601, gas limit 0, operations empty, doubled or other, no recipients, 33),
  bad addresses (checksum, upper case, no prefix) in the contract and at either end of the recipients, every amount spelling (zero, leading zero, sign, point, exponent, space, 2^256) for each of the four amount fields, integers spelled as floats,
  identifiers with a space, slash, non-ASCII, quote or escape, duplicate keys at the top and nested, escaped keys, duplicate recipients (adjacent, apart, and in a different case), each ordering rule (per-transaction above daily, approval above per-transaction,
  an empty or reversed window) with its equal-is-fine boundary, no approval threshold, JSON errors, and exactly 8,192 bytes (accepted) against 8,193. The exported JSON Schema is valid Draft 2020-12 and the structure stage agrees with `jsonschema` on every
  document where the two are comparable.
- **The decision:** 120 random scenarios (random policy limits, window and version, caller, clock around every edge, registry state, a history of up to five records some of which replay the intent); **each of the 14 reasons alone and every combination of up to three of them, 469
  scenarios**, which is what holds the table's order; every boundary (`now` one below and at `not_before`, one below, at and above `not_after`; amounts one below, at and one above the per-transaction limit and the approval threshold; a history record at 86,401, 86,400
  and 86,399 seconds old and at `now`; the daily total reached exactly, exceeded by one and one short; a sum that overflows 2^256 and one that is 2^256 - 1; a replay older than the window; several records summed and an old one not); a replay at each of four positions in the history; an
  overflow in the first, the second or the first of three records; the intent's chain below the policy's; the decision digest of records of 0, 1, 117, 118, 150, 181, 182 and 300 bytes; 20 decisions from the JSON of both documents, end to end; and the malformed inputs: policies and intents truncated,
  extended, with a wrong layout or kind byte, or consistent in length but out of range (no recipients, 33, an empty or 65-byte id or principal), histories of 71 and 73 bytes, from the future, with a timestamp of 2^63 and of 2^64 - 1, callers of 0, 65 bytes, with a space, a slash or a non-ASCII byte,
  a clock of -1 and of 2^62 + 1 (and 2^62 accepted), and a short output and a short working space for the policy parser and for `decide`.
- `--mutants`: **121 deliberate faults** (each registry, validity and caller check; each comparison and its boundary: strict against inclusive, one way against the other; the replay scan and the daily window at 86,399, 86,400 and 86,401 seconds; the overflow flag; every byte
  and offset of the decision record and its digest; the schema's bounds, strictness and required flags; the float spellings of each integer field; the duplicate and escape checks; the ordering rules; every offset and bound of the canonical reader; both digests' domains and inputs; the input
  validation limits): **119 killed, 2 equivalent, 0 unexpected survivors.** The two are in the script with their reasons: the `decide` working-space bound (with 50 to 109 words the first check passes and the Keccak call that follows refuses the short space with the same code) and the escape check on
  later keys (an escaped and a duplicate key share the refusal code -225, and the outer loop reaches every escaped key by itself).
- **Found by the checks.** The first full run of this slice's tests refused a random policy whose recipient's correct EIP-55 spelling is all capitals: `chain.address.parse` (slice 2) had refused all-uppercase text outright. That was my misreading of the specification, whose "all caps" vectors are valid
  checksummed addresses; §8.1 is corrected in place and the slice-2 test that had encoded the misreading now expects those vectors to be accepted. The mutant runs themselves took three passes: the first stopped after 66 of 121 mutants without saying why (58 killed, five survivors seen) and was
  replaced by a parallel run; the second killed 115 and left five (one equivalent, four needing canonical policies that are consistent in length but out of range, which the tests did not build); the third is the result above.

**Not claimed.** The model is written from this section by the same author, so a shared misreading passes; the independent checks are `eth-utils` and `jsonschema`. The decision is not yet bound to the transaction bytes (the next slice), the history, the registry and the clock are
inputs this repository does not provide, and nothing has been independently reviewed.

**Interim dependency [choice]:** `cancho-schema` is consumed from a sibling checkout (`CANCHO_SCHEMA`, default `../cancho-schema/src/schema.cho`), as `secp256k1` is (§8.1); its `vcs lock` / `vcs fetch` route
(documented in its README) needs a published store at a pinned commit and is the better way once the two packages settle. It compiles with this repository's compiler although it pins an older one (`cancho check --std src/schema.cho` is clean).

## 11. The policy and the decision (slice 5)

**Status: built.** Results are in §11.5. The policy engine is a pure function: the same policy, intent, caller, time, registry state and history always give the same decision, and nothing it reads is the agent's word.
It decides; it signs nothing and moves nothing. Binding a decision to the exact transaction bytes is the next slice (the builder and the authorisation envelope).

### 11.1 The policy

An administrator's JSON document, read with the same machinery as the intent (`cancho-schema`, strict, no duplicate keys, no escapes, no floats, amounts as decimal strings of base units) into a canonical binary
layout and an immutable digest, `keccak256("cancho-chain/policy/v1" || canonical)`. **[choice]** The policy names exactly one asset and one chain (the MVP's claim is one network and one operation); the agent cannot change any of it, because
the engine has no operation that does (the proposal's `may_change_policy`, `may_manage_keys` and `may_change_allowlists` are not flags to be set false but things the interface does not contain).

```
{"policy_id":"procurement-usdc-v1","version":1,"principal":"agent-procurement-01","chain_id":11155111,
 "asset":{"contract":"0x...","decimals":6},"operations":["erc20_transfer"],"recipients":["0x...","0x..."],
 "limits":{"per_transaction":"500000000","daily_total":"2000000000","approval_required_above":"250000000"},
 "fees":{"max_fee_per_gas":"30000000000","gas_limit":100000},
 "validity":{"not_before":1730000000,"not_after":1830000000},"decision_ttl_seconds":300}
```
`recipients` has 1 to 32 distinct addresses; `approval_required_above` is optional (absent: never); the fee cap and gas limit are what `chain.txcheck` will be given as its expectation, so they come from the policy and not from the agent;
`decimals` (0 to 36) is recorded for evidence and display, and never used in arithmetic: every amount in the system is an integer of base units. Refusals while reading a policy: `policy-json` (-220), `policy-schema` (-221), `policy-address` (-222),
`policy-number` (-223: an amount not in canonical decimal, zero, or above 2^256 - 1; a float spelling), `policy-text` (-224: a policy id or principal outside `A-Z a-z 0-9 . _ : -`), `policy-duplicate` (-225: a key twice, a key written with an escape, or a recipient listed twice),
`policy-order` (-226: a limit above the one it is supposed to be below: per-transaction above daily, approval threshold above per-transaction, `not_after` not after `not_before`), `policy-size` (-227: over 8 KiB), `policy-output` (-228), `policy-work` (-229).

### 11.2 The decision function

`decide(policy, intent, caller, now, registry, history, ...)` where `policy` and `intent` are the canonical forms (§10.3, §11.1), `caller` is the **authenticated** principal the service established (a string of word characters, 1 to 64), `now` is the
service's clock in Unix seconds (never the agent's), `registry` is the policy registry's answer `(current_version, revoked)` for this policy id (`current_version < 0`: the registry could not be asked), and `history` is the list of authorisations already issued, each
`timestamp (8 bytes) || intent digest (32) || amount (32)`, 72 bytes, oldest to newest or in any order. The first check that fails answers; outcomes are `allow` (1), `refuse` (2), `approval-required` (3):

| reason | code | when |
|---|---|---|
| `POLICY_STATE_MISSING` | 1 | the registry could not be asked: refuse, never allow |
| `POLICY_REVOKED` | 2 | the registry says revoked |
| `POLICY_SUPERSEDED` | 3 | the policy's version is below the registry's current version |
| `POLICY_NOT_YET_VALID` | 4 | `now` below `not_before` |
| `POLICY_EXPIRED` | 5 | `now` at or above `not_after` |
| `PRINCIPAL_MISMATCH` | 6 | the authenticated caller is not the policy's principal |
| `OPERATION_NOT_ALLOWED` | 7 | the intent's kind is not in the policy's operations |
| `CHAIN_NOT_ALLOWED` | 8 | chain id differs |
| `ASSET_NOT_ALLOWED` | 9 | asset contract differs |
| `RECIPIENT_NOT_ALLOWED` | 10 | recipient is not in the policy's list |
| `AMOUNT_LIMIT_EXCEEDED` | 11 | amount above the per-transaction limit |
| `REQUEST_REPLAYED` | 12 | this intent's digest is already in the history: an authorisation was issued, so reconcile, do not ask again |
| `DAILY_LIMIT_EXCEEDED` | 13 | the amounts issued in the last 86,400 seconds plus this one exceed the daily total (or the sum overflows 2^256) |
| `APPROVAL_REQUIRED` | 14 | outcome 3: within every limit but above `approval_required_above`; a human decides |
| `ALLOWED` | 0 | outcome 1 |

**[choice]** Cumulative limits are over a *rolling* 86,400 seconds, `timestamp > now - 86400` and `timestamp <= now`, and count amounts at **issuance**, not settlement: an authorisation that was never used still counts until it ages out, which is the
conservative reading (releasing one is a later, explicit operation). A timestamp after `now` is an inconsistent history and fails closed, as does a length that is not a multiple of 72. An outcome of `approval-required` is not counted, and a
later `allow` after approval is a new decision. Malformed *inputs* (a policy or intent that is not canonical, a bad caller, a bad history) answer a negative code and **no decision**: `decide-policy` (-230), `decide-intent` (-231), `decide-caller` (-232),
`decide-history` (-233), `decide-output` (-234), `decide-work` (-235), `decide-clock` (-236); the caller treats any negative answer as a refusal and records it.

### 11.3 The decision record

Canonical bytes, at most 181: byte 0 the layout version (1), byte 1 the outcome, bytes 2 to 4 the reason (a big-endian 16-bit code), 4 to 36 the intent digest, 36 to 68 the policy digest, 68 to 76 `decided_at` (8 bytes), 76 to 84 `expires_at`
(`decided_at` plus the policy's TTL for an `allow`, `decided_at` for anything else), 84 to 116 the amount counted (the intent's for an `allow`, zero otherwise), then the caller as a length byte and its bytes. The **decision digest** is
`keccak256("cancho-chain/decision/v1" || record)`. It binds the decision to the exact intent, the exact policy version, the caller and the time window; it cannot be presented for another intent or after it expires.

### 11.4 What it does not do

It does not authenticate the caller (it is told who that is), keep the clock, store the history or consult the registry (it is given their answers: the evidence store and the registry are later slices), and it does not know the transaction bytes (the next slice
binds the decision to them). A caller that lies about `now`, `caller` or `history` defeats it; that is the service's trust boundary (§5.2), and the evidence log is what lets an auditor notice.

### 11.5 How it is checked

`scripts/check_policy.py` against a model in Python written separately from this section: every policy and intent the model accepts has the same canonical bytes and digest; for random policies, intents, callers, times, registry states and histories
the decision (outcome, reason, every byte of the record and its digest) is the model's; each of the 14 reasons is reached alone and in every pairing that tests the table's order; every boundary (`now` at `not_before`, `not_after` and one either side; an
amount at, one below and one above each limit; a history record at and either side of the 86,400-second edge; sums that reach, exceed and overflow the daily total); every malformed input. `--mutants` as for the other slices. Results are added below when measured.

## 13. The authorisation envelope (slice 6)

**Status: design, written before the code.** Claims are *choice* or *open* until measured; the measured results go into §13.5. The envelope is what crosses from the policy side to the signer: a decision (§11) bound to the exact unsigned transaction,
signed by an **issuer** key that is not the wallet key. The signer trusts nothing in it until the issuer's signature is checked, and re-derives everything it can.

### 13.1 The envelope

A fixed binary layout (big-endian, version 1), 262 bytes plus the caller:

| bytes | field |
|---|---|
| 0 | layout version, 1 |
| 1 to 33 | envelope id: 32 bytes the issuer draws fresh; the key of single use |
| 33 to 65 | the decision digest (§11.3): evidence, the signer cannot recompute it |
| 65 to 97 | the transaction digest: `keccak256` of the unsigned message `02 \|\| rlp(body)`, which is the hash that is signed |
| 97 to 105 | chain id |
| 105 to 125 | the address that must sign (the wallet) |
| 125 to 145 | token contract; 145 to 165 recipient; 165 to 197 amount (32 bytes) |
| 197 to 205 | nonce; 205 to 237 fee cap per gas (32); 237 to 245 gas cap |
| 245 to 253 | `issued_at`; 253 to 261 `expires_at` (Unix seconds) |
| 261 | the caller's length `n` (1 to 64), then the caller's bytes |

The envelope digest is `keccak256("cancho-chain/envelope/v1" || layout)`; the **issuer signs that digest** with secp256k1 (`r || s || recid`, low s, RFC 6979), and the signer recovers the issuer's address from it and compares with the one it was configured with.
**[choice]** An issuer signature, and not a MAC under a secret both sides hold: the signer then holds no secret that can *make* an envelope, so a compromised signer cannot authorise anything for itself, and a compromised policy service cannot sign (it has no wallet key).
The two keys must differ; the signer refuses to start if they do not (a later slice).

The fields after the digest are the **expectation** `chain.txcheck` is given (§9.2): the signer recomputes nothing from the decision, but it does decode the exact bytes and require every field to be what the envelope says, and the envelope to be what the issuer signed.

### 13.2 Issuing

`issue` takes the decision record (§11.3), the unsigned message, the expectation, the wallet address, a fresh envelope id, `now` and the issuer key. It refuses (reasons below) unless the decision's outcome is `allow`, `now` is in `[decided_at, expires_at)` of the decision, the decision's amount is the expectation's,
and `validate_unsigned` passes on the message. The envelope expires when the **decision** does: an envelope cannot outlive the authority it carries. It writes the layout and the signature.

### 13.3 Verifying (the signer's side)

`verify` takes the envelope, the signature, the unsigned message, and **the signer's own configuration**: the issuer address, chain id, wallet address, the authenticated caller of this request and its clock. Checks, in this order, the first failure answers:

1. the layout is whole and version 1 (`ENVELOPE_FORMAT`); nothing in it is believed yet;
2. the recovered issuer is the configured one (`SIGNATURE_INVALID` if recovery fails or `s` is high; `ISSUER_MISMATCH`);
3. `chain id`, the wallet address and the caller equal the signer's (`CHAIN_ID_MISMATCH`, `SIGNER_KEY_MISMATCH`, `CALLER_MISMATCH`): the caller is the one the gateway authenticated (`auth_identity_header`), so an envelope issued to one principal is useless to another;
4. `issued_at <= now < expires_at` (`ENVELOPE_NOT_YET_VALID`, `ENVELOPE_EXPIRED`);
5. `keccak256(message)` is the envelope's transaction digest (`TRANSACTION_DIGEST_MISMATCH`);
6. `validate_unsigned` against the envelope's expectation (`TRANSACTION_INVALID`, with `txcheck`'s code as the detail).

Single use is **state**, kept by the signer, and is not part of `verify`: a **ledger** of `envelope id || transaction digest` (64 bytes per entry). `ledger_check(ledger, id, digest)` answers *fresh*, *same* or *conflict*.
**[choice]** The entry is written and flushed **before** the signature is produced. A crash between the two loses a signature, never lets a second one out. An envelope seen again **with the same transaction digest** is signed again, and gets the same bytes (RFC 6979 is deterministic): a retry after a timeout cannot pay twice, because it is the same
transaction with the same nonce, and refusing it would leave the caller unable to recover the signature. An envelope id seen with a **different** digest is `AUTHORIZATION_REPLAYED`.

### 13.4 What it does not do

It does not keep the ledger durable (the signer process does, on cancho-log), draw the id's randomness, hold either key, or run the signer; those are the next slice. It proves nothing about the decision beyond the issuer's word that one was made: the decision digest is evidence an auditor can match to the log, not something
the signer can check. An issuer that is compromised can authorise anything within a policy it is willing to sign for: the signer's own configuration (chain id, wallet) and the expiry bound it, the policy does not (the signer never sees it). That is the trust placed in the issuer, and it is said in §6.

### 13.5 How it is checked

`scripts/check_envelope.py`, against a model in Python written separately from this section: envelopes issued by the code have the model's bytes and digest and a signature the model verifies with libsecp256k1 (`coincurve`) and recovers to the issuer's address; every refusal reached alone and in the pairings that test the order; every boundary (`now` at
`issued_at`, `expires_at` and one either side); a changed byte at every offset of the envelope, of the signature and of the message (each must be refused, with the reason the order says); the ledger's three answers; `--mutants` as for the other slices. Results are added below when measured.

## 12. Open questions for the maintainer

1. secp256k1: build it in cancho core (preferred) or here first? Are fallbacks acceptable if it proves too large?
2. May `cancho-chain` depend on `cancho-schema` (a package dependency) or is vendoring preferred? How do sibling repos consume each other (`cancho.toml` has no
   dependency section in cancho-opt)?
3. Is the Linux x86-64 seed expected to land in `cancho`, so CI can start without Rust?
