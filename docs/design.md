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

**Status: built.** Results are in §13.5. The envelope is what crosses from the policy side to the signer: a decision (§11) bound to the exact unsigned transaction,
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

**[measured]** 2026-11-07, Linux x86-64, the self-hosted `cancho` at `162633a7`, `secp256k1` from alpibrusl/cancho#710 (merged), `coincurve`, `python-ecdsa` and `pycryptodome` from pip.
`CANCHO=<compiler> CANCHO_PACKAGES=<cancho>/packages CANCHO_SCHEMA=<cancho-schema>/src/schema.cho python3 -I scripts/check_envelope.py`: **1,187 of 1,187** checks pass (`--cases 120`).
- **Issue:** 120 random cases (chain, nonce, fees, a 1- to 64-byte caller, windows from 1 second): the envelope is the model's, byte for byte; the signature is the model's (libsecp256k1, RFC 6979) and python-ecdsa verifies it; it recovers to the issuer; `verify` accepts it; the digest is the model's;
  an amount padded to 32 bytes gives the same envelope. The refusal cases of `issue`, each alone, each with its code (the decision's length, version, caller length and outcome, both ends of the window, the amount one either side, each field of the transaction, every length, the issuer key at 0 and at `n`, an issuer that is the wallet).
- **Verify:** every refusal alone, each with its code; **every one of the ten faults alone, in each of the 44 pairs that can occur together and each of the 112 trios: the first in §13.3's order answers**; every changed bit of the envelope (two bits at each of its bytes) is refused by the signature or the layout, every changed bit of the signature
  is refused, every changed byte of the message is a digest mismatch; the low-s edge (`s` exactly `n/2` is accepted as low, one above is not); the window's edges (`issued_at` accepted, one before refused; `expires_at` refused, one before accepted); the longest (326 bytes) and the shortest (263 bytes) envelopes; the
  configuration's lengths; the six `txcheck` detail codes (nonce, token, recipient, amount, gas cap, fee cap) and the chain one. Ledger: 60 random ledgers and the edges (the same id with different digests anywhere in the list conflicts; the same entry twice is the same; a length that is not a multiple of 64).
- `--mutants`: 92 deliberate faults (every offset of the layout, each bound and comparison of `issue` and `verify`, the order of the checks, the low-s test and its constant at both ends, every expectation field handed to `txcheck`, the ledger's offsets and answers): **85 killed, 7 equivalent**, each explained in the script (a bound that an earlier or later check of the
  same input already enforces, or a buffer length the driver fixes). The first run killed 83 of 92; the survivors were a case that happened to have amount 0 (so "one less" did not exist), a short digest never given to the ledger, and a 261-byte envelope never given to `verify`; each became a check.
- **A claim of an earlier slice was found false while building this one** (§9.3, corrected in place): the decoder is header-level and does not agree with `rlp.decode(strict=True)` on every input.

**Not claimed.** That the ledger is durable or the id unique: the caller draws the id (a repeat would be `AUTHORIZATION_REPLAYED` only if the ledger holds it), and the signer keeps the ledger. That the decision digest is the decision of anything the signer can check. That `secp256k1` is constant time (#712). That nothing has been independently reviewed.

## 14. The signer (slice 7)

**Status: built.** Results are in §14.7. The signer is the only process that holds the wallet key. It takes one request, answers with a signature or a refusal with a stable rule tag, and leaves a durable record of what it consumed. This slice is its core and its process boundary; the network front is not in it.

### 14.1 What it is, and what it is not

A program `signer`, built from `tools/signer/main.cho`, run as one process per request, on a request line from its front (v1: a person, a test, or a small adapter; the front that listens on a socket behind `cancho-gateway` is the next slice).
**[choice]** One request per process: it makes the process boundary and the authority report trivial (no `net_*`, no `exec`, no `signals`, no command line; it performs the clock, one directory, standard input and output, and the heap for the ledger), and recovery and the lock are paid at each start (milliseconds for a ledger of thousands). A long-running signer is an optimisation and changes none of the rules below.

Its directory is a **compile-time constant** (`/var/lib/cancho-signer`), so `cancho authority` names the one path it can read and write, and nothing else (a path taken from the command line would make the report unbounded). The test harness builds a copy with another path.

| file | what |
|---|---|
| `wallet.key` | the wallet key, 64 hex digits (a development key: nothing here claims production key management, §6) |
| `signer.conf` | `issuer=<40 hex digits>` and `chain=<decimal>`: the issuer's address and the one chain it signs for |
| `ledger.seg` | the ledger: a `cancho-log` segment in **trail mode** (cancho-log `docs/trail.md`), one event `envelope.consumed` per envelope, hash-chained |
| `/var/lib/cancho-anchor/anchor` | **(slice 12, §19)** the ledger's `(count, head)`, in a second directory: the signer signs only what the anchor covers |

### 14.2 A request

One line on standard input: `<envelope hex> <signature hex> <message hex> <caller hex>`: the envelope and its issuer signature (§13), the unsigned message to sign, and the **caller as the front authenticated it** (v1 trusts its front for the caller exactly as §11.4 trusts the service; the front is `cancho-gateway` with `auth_identity_header`, which removes whatever the client sent and says who the key was).
The time is the signer's own clock; there is no field for it, and no flag that overrides it.

### 14.3 The steps, in this order

1. **Start.** Take `flock` on `ledger.seg` (a second signer on the same directory is refused, `signer-locked`: two signers would each see an envelope as fresh). Read the configuration and the key; derive the wallet address; refuse to start if it is the issuer's (`signer-same-key`).
   **Verify the whole chain first, read-only** (`trail.verify`: every event, every parent link), and only then recover (cut a torn tail): `recover` cuts a log at the first thing that is not a whole record, and for damage in the middle of the file that would throw away entries that were consumed, after which their envelopes would look fresh. Only a *torn* tail (the file ends inside a record) is ever cut; any other verdict is refused. Then read the entries. A ledger that does not verify is `signer-ledger-corrupt` and nothing is signed: **fail closed**. A ledger over 65,536 entries is `signer-ledger-full`.
2. `envelope.verify` with the signer's own configuration: the issuer, the chain, the wallet, the caller, its clock, the message (§13.3). Its ten refusals pass through as they are.
3. `envelope.ledger_check`: *fresh*, *same* or *conflict* (`AUTHORIZATION_REPLAYED`).
4. **Fresh: append `envelope.consumed` to the ledger and flush, then sign.** If either fails, **no signature is produced** (`signer-ledger-write`): a crash between the flush and the answer loses a signature and never lets a second one out. *Same*: sign again; RFC 6979 gives the same bytes, so the retry is the same transaction.
5. **Sign** the transaction digest (the envelope's, which `verify` has shown is `keccak256(message)`) with the wallet key, no added randomness: the answer is `r || s || recid`, low s.

The answer is one JSON line: `{"ok":true,"signature":"<130 hex digits>","entry":"fresh"|"same","anchor":{"count":<n>,"head":"<64 hex>"}}` (the anchor is §19's), or `{"ok":false,"rule":"chain.<tag>","repair":"..."}` and exit status 2. No key, digest, envelope or message is ever logged or printed on a refusal; the rule tag is the same one `chain.envelope` gives (§13), plus the signer's own.

### 14.4 The payload of a ledger event, and why trail mode

`{"id":"<64 hex>","digest":"<64 hex>"}`, exactly: 149 bytes, read back by position and refused (`signer-ledger-corrupt`) if it is anything else. **[choice]** Trail mode and not a bare log: the chain makes the ledger tamper-evident to an auditor who holds an anchor `(count, head)` (cancho-log `docs/trail.md` §2 says what it proves and what it cannot: a cut tail or a consistent rewrite verify unless an anchor is held elsewhere), and the same events are the *evidence* that an envelope was consumed, which is the start of the evidence log (§5). The event time is the signer's clock in milliseconds.

### 14.5 What it does not do

Before slice 12 it could not tell a ledger whose **last** record has a damaged length field from a torn tail (both end inside a record), and cut it: that entry was lost and its envelope could be signed again, once. **Closed in slice 12 (§19):** a record the anchor covers is refused, not cut; one beyond it was never signed, so cutting it is safe. It does not listen on a socket, draw randomness, rate-limit, keep the history the policy engine reads (that is the evidence store's, later), take the issuer's address from anywhere but its configuration, sign anything but an ERC-20 `transfer` that `txcheck` accepts, or protect the key from a person with the directory (a file readable by root is readable by root: a hardware key is out of scope). A compromised front can ask for signatures it has envelopes for, and no others; a compromised issuer key can authorise anything within the signer's chain and wallet (§13.4).

### 14.6 How it is checked

`scripts/check_signer.py`: the real binary, built with a test directory, against the Python model of §13 (which makes the envelopes) and independent verifiers (libsecp256k1 and python-ecdsa for the signature, which must recover to the wallet's address and be the model's bytes; `eth-account` for the signed transaction built from it): a valid request signs; each refusal of §13 is the rule tag it should be; the same envelope twice gives the same signature and one ledger entry; the same id for another transaction is refused; an expired and a not-yet-valid envelope are refused (against the real clock); a request from another caller is refused; **no signature is ever produced when the ledger cannot be written** (`/dev/full`, a read-only directory, a ledger whose tail is torn, one whose chain is broken, one that a second process holds locked); a signature is never produced for a ledger event that did not reach the disk (a kill between the flush and the answer is a retry that gets the same bytes); the ledger verifies with `cancho-log`'s own `trailtool` and with the independent model in its `tests/trail_sweep.py`; and `cancho authority` of the binary names the one directory and nothing else. `--mutants` as for the other slices. Results are added below when measured.

### 14.7 Measured

**[measured]** 2026-11-07, Linux x86-64, the self-hosted `cancho` at `162633a7`, `cancho-log` at its main (trail mode, merged), `secp256k1` from alpibrusl/cancho#710 (merged).
`CANCHO=<compiler> CANCHO_PACKAGES=<cancho>/packages CANCHO_SCHEMA=<cancho-schema>/src/schema.cho CANCHO_LOG=<cancho-log>/src python3 -I scripts/check_signer.py [--slow] [--mutants]`: **386 of 386** checks pass.
- **Valid requests (6 random cases):** the signature is the model's (libsecp256k1, RFC 6979), recovers to the wallet, python-ecdsa verifies it, and `eth-account` signing the same transaction gives the same `r`, `s` and parity; the ledger holds exactly one `envelope.consumed` event with the envelope's id and the transaction digest, read back by a reader written in the script (record layout, lex-trail's event id); its time is the signer's clock in milliseconds; a retry gets the same signature, `"same"`, and writes nothing; `trailtool` of cancho-log verifies the ledger clean.
- **Refusals, each its rule tag, exit status 2, a repair, no signature, the ledger unchanged:** every envelope refusal reachable from a process (another issuer, a malformed signature, a truncated envelope, another caller, another transaction, a transaction that is not the envelope's expectation, expired, not yet valid, another chain, another wallet, another issuer configured, an id used for another transaction); 23 configuration and key faults (each of the files' shapes, an issuer that is the wallet, files longer than their buffers); 11 request-line faults (up to 4,096 bytes); 14 ledger faults (a torn tail is cut and the ledger goes on, separately; then is cut and the ledger goes on; a flipped byte in any record, a flipped length, a flipped checksum, a deleted middle or first record, two records swapped, a zeroed block, a long garbage tail, and whole events whose payload is not a ledger entry: each is `signer-ledger-corrupt` and the file is **byte for byte as it was**).
- **No signature without a durable entry:** a ledger that cannot be written (`/dev/full`), one whose flush fails (`/dev/null`), one that is a directory, one another process holds locked (`flock`): each refused, none signs. The state "killed between the flush and the answer" is the retry above: the entry is there, the same bytes come back.
- **Authority:** `cancho authority` of the binary: performs `clock`, `file_read`, `file_write`, `fs_read("/var/lib/cancho-signer")`, `fs_write("/var/lib/cancho-signer")`, `heap`, `io_read`, `io_write`; never touches the network, the command line, signals, other programs or foreign code. Arguments are ignored (a test passes `--now 5 /tmp` and gets the same answer).
- **Cost:** one request is 4 ms with an empty ledger, 10 ms at 1,000 entries, 36 ms at 5,000 and 63 ms at 10,000 (a process start, a full verification of the chain, one signature); a ledger of the 65,536-entry limit is about 400 ms by that slope, and is refused beyond it (`--slow` checks that, and takes minutes because the *script* writes 65,537 events in Python).
- `--mutants`: 50 deliberate faults in the signer (the lock, which damage is cut, the lookup and what is written, the flush, the clock, the hedge, the digest signed, the first event's parent, every bound of the request line and the two files, the payload's every byte, the tags): **49 killed, 1 equivalent** (a torn tail can never be longer than the bound that is checked: a larger declared length is a bad record, not a torn one). The first run killed 38 of 51: the survivors were tests missing (a colon where `=` belongs, the last digit of the issuer in upper case, 19- and 0-digit chains, a 66-digit key, files longer than their buffers, a payload with another quote or one byte too long, a double space between four fields, an unusable flush), and each became a check.
- **Found while building:** a region holds 64 KiB in all in this language, so the key's workspace and the ledger (4 MiB at the limit) are on the heap, which is why the report says `heap`; and my first design of recovery would have cut a ledger at damage in its middle (above, and §14.3).

**Not claimed.** A front: nothing listens on a socket (the next slice), so "who the caller is" is whatever the line says. That a ledger whose last record is damaged is noticed (§14.5). Durability beyond `fsync` of one file: the directory entry of a new ledger is not synced. That a hardware key or a second signer could be added: one process, one key. Independent review.

## 15. The front (slice 8)

**Status: built.** Results are in §15.4. The signer (§14) takes one request on standard input. This slice puts a network in front of it without giving the network anything the signer has: a small HTTP service, the **front**, behind `cancho-gateway`.

### 15.1 Three processes, three authorities

| process | holds | can reach |
|---|---|---|
| `cancho-gateway` (existing) | the digests of the callers' API keys | the network, to the front only (its upstream set is compiled in) |
| `front` (`tools/front`) | nothing secret | one TCP port in, **one program to start** (the signer's path, a compile-time constant), the clock, the heap, and, since slice 13, **one directory** for the witness (§20). **No network out** |
| `signer` (§14) | the wallet key | one directory, the clock, standard input and output. No network, no program to start |

The front is the only one that listens and the only one that can start the signer; the signer is the only one that can read the key. `cancho authority` of each shows exactly its row, and a compromised front can ask for signatures for the envelopes it is given, and nothing else (§14.5).

### 15.2 The API

`POST /sign`, nothing else. A request carries **one header the front believes**, `X-Auth-Identity`: the name of the API key the gateway authenticated (`auth_identity_header`, `cancho-gateway` `docs/auth.md` §3.1: the gateway removes whatever the client sent under that name and sets its own). The front **requires exactly one** such header, whose value is 1 to 32 bytes of `[a-z0-9._-]` (the generator's rule for key names), and refuses (`401`, `front-no-identity`) otherwise: it is the **caller** the signer is told. **A deployment that lets a client reach the front without the gateway has no caller at all:** the front must listen on a port only the gateway can reach (loopback, or a private interface); that is the deployment's, and it is said here because the header proves nothing on its own.
The body is exactly `{"envelope":"<hex>","signature":"<hex>","message":"<hex>"}`: three members in this order, no whitespace, lower-case hex of even length (the envelope at most 652 digits, the signature exactly 130, the message at most 2,048), at most 4,096 bytes in all. **[choice]** One canonical spelling and not a JSON parser: the issuer's side writes it, there is nothing to be liberal about, and a body that is anything else is `400 front-body`.

The front builds the signer's request line from them and the caller, starts the signer with it on standard input, and reads its one line of output, at most 4,096 bytes, for at most 10 seconds:

| the signer | the front answers |
|---|---|
| exit 0, `{"ok":true,...}` | `200`, the signer's line as it is |
| exit 2, `{"ok":false,"rule":...}` | `422`, the signer's line as it is (a refusal is a successful security outcome; the status says the request is understood and refused) |
| exit 2 with a rule the signer could not act on (`signer-locked`, `signer-ledger-write`, `signer-ledger-corrupt`, `signer-ledger-full`, `signer-config`, `signer-key`, `signer-same-key`) | `503`, the same line: the signer is unwell, not the request |
| anything else (no such program, a crash, a timeout, output that is not one line) | `502`, `{"ok":false,"rule":"chain.front-signer","repair":"..."}` made by the front |

Any other path is `404`, any other method on `/sign` is `405`, a body that is too large is `413`, a missing or wrong `Content-Type` is not looked at. Every refusal the front makes has a `chain.front-*` rule tag and no value from the request in its repair. **Serial:** one request is served at a time (the signer allows no other, §14.3), so the front never starts two signers.

### 15.3 How it is checked

`scripts/check_front.py`: the real front and the real signer on loopback, the front built with a test port and the signer's path, the signer with a test directory: a valid request signs (the signature the model's, as in §14.6) and the answer is the signer's line byte for byte; each refusal of the signer arrives with its rule tag and the status above; a missing, duplicate, empty, upper-case, too long or badly spelled `X-Auth-Identity` is `401`; every malformed body (a member missing, doubled, reordered, with whitespace, a non-hex digit, an odd length, a field over its bound, trailing bytes) is `400` and **the signer is never started** (counted by a wrapper); the front's answer to a signer that crashes, hangs, writes nothing or writes too much; `cancho authority` of the front names the one port in, the one program and nothing else (no file, no network out); and `--mutants` as for the other slices.
`scripts/check_stack.py`: `cancho-gateway` (with `auth_identity_header`), the front and the signer, a client with API keys: the caller the signer sees is the name of the key; a forged `X-Auth-Identity` from the client is replaced; a second key whose name is another principal's cannot use the first one's envelope; no key, a wrong key and a key the route does not allow never reach the front. Results are added below when measured.

### 15.4 Measured

**[measured]** 2026-11-07, Linux x86-64, the self-hosted `cancho` at `162633a7` for the front and the signer, the gateway built by its own harness with the compiler it pins (`2fcf4cde`), `http.server` from the cancho repository.
`python3 -I scripts/check_front.py` (**117 of 117** checks) and `python3 -I scripts/check_stack.py` (**15 of 15**), with the environment their headers name.
- **Valid requests (4 random cases):** 200, `application/json`, the signer started once, the signature the model's, a retry `"same"` with the same bytes, and the answer **byte for byte the signer's own line** for the same request.
- **The signer's refusals** arrive with their rule tags: the envelope's (another issuer, a truncated envelope, another transaction, another caller) as `422`; an unwell signer (a ledger that cannot be written, one held locked, no `signer.conf`, a bad `wallet.key`, an issuer that is the wallet, a damaged ledger) as `503`; and for every tag in the table a signer *made* to say it (a wrapper that prints a given rule) the status the table gives, including `signer-ledger-full`, which a real ledger reaches only after 65,536 entries.
- **The identity:** 10 bad spellings (missing, twice, twice the same, empty, upper case, 33 bytes, a space, a comma, a slash, non-ASCII) and 5 more at the edges of the character classes (`{`, `:`, `` ` ``, `@`, `[`) are `401 front-no-identity` and **the signer is never started** (counted by the wrapper); headers that only *begin like* the identity (`X-Auth-Identity-Extra`, `X-Auth-Identit`, `X-Auth-Identityx`, `Y-Auth-Identity`) are not it; 1-, 32-byte and punctuated names are within the rule; the header name in any case is the header.
- **The body:** 31 malformed bodies (empty, not JSON, a member missing, doubled, extra or reordered, whitespace, a newline or a space at the end, an upper-case digit, an odd length, `g`, `` ` ``, `/` and `:` among the digits, an empty envelope or message, a signature a byte short or long, an envelope or message one digit over its bound, a number in place of a string, an escaped digit, each member's name misspelt, the object closed with a bracket) are `400 front-body` and the signer is never started; 4,097 bytes is `413`.
- **Routes:** another path and a trailing slash are `404`; a query string on `/sign` is the route; `GET`, `PUT`, `DELETE` and `PATCH` are `405` with `Allow: POST`.
- **A signer that fails** (crashes, says nothing, floods its output, writes a line that is not its own, writes two lines, writes a refusal with no rule, a refusal with an exit status of 3, a line of over 4,096 bytes) is `502 front-signer`; one that **hangs** is `502` after 10 seconds and the next request is served.
- **Concurrency:** keep-alive (two requests on one connection) works; six clients at once are served one after another, all `200`, one signature, **one ledger entry**.
- **Authority of the front:** performs `child_signal`, `clock`, `conn_accept`, `conn_read`, `conn_write`, `exec("<the signer's path>")`, `heap`, `net_in("<its port>")`, `pipe_read`, `pipe_write`, `poll`; never touches the console, the filesystem, the command line, signals or foreign code, and the report is **bounded** (no `UNBOUNDED`). The first build was not: it held the unnarrowed `Net`; edition 11's `ports` capability, narrowed to the port, is what bounds it.
- **The stack** (gateway, front, signer, three API keys): the procurement key signs the envelope issued to `agent-procurement-01` (the name of the key is the caller; the signature is the model's); a client's own `X-Auth-Identity` does not change the caller (the gateway replaces it): the same key forging another name gets the *same* entry, and the other key forging the first's name is `envelope-caller`; the other key presenting the first's envelope is `envelope-caller`, and signs its own; **no key, no key with a forged header, a wrong key, a key the route does not allow and a `GET` never start the signer or change the ledger** (`401`, `401`, `401`, `403`, `405` from the gateway); the gateway's log names the key and holds no key value; a refusal through the whole stack keeps its tag.
- **What the stack check shows about the deployment, on purpose:** a request sent **straight to the front** with the header is believed (`200`): the front trusts its header, and the gateway is the only thing that makes the header true. The front must listen where only the gateway can connect.
- `--mutants`: 61 deliberate faults (every bound of the body, each member's name, the hex alphabet and its edges, the identity's bounds and alphabet, the header's name and case, the route and method, how the caller is spelt to the signer, each exit status, the shape of the signer's line, each of the seven unwell tags, the output bound and the deadline, the refusals' statuses): **59 killed, 2 equivalent** (a quote that the next literal checks again; a missing header that `handle` refuses by its index). The first run killed 48 of 61; the survivors were tests missing (boundary characters, names that begin like the header, a signer that lies about its exit status, a rule-less refusal, an over-long line, a tag the real signer reaches only after minutes), and each became a check.
- **Found while building:** the first body refusal was not valid JSON (its repair text held unescaped quotes), found by the first run that parsed it.

**Not claimed.** TLS between the gateway and the front (loopback or a private link is assumed), rate limiting of the signer's callers beyond the gateway's, logging in the front (there is none: no request value reaches a log), a second signer or a queue (the signer is one at a time by design), and that `exec`'s narrowing is more than a prefix: `exec("/usr/local/lib/cancho-chain/signer")` also admits `.../signer-anything`, so the directory should hold nothing else.

## 16. The RPC codec (slice 9)

**Status: built.** Results are in §16.5. What a transaction does after it is signed is read from a provider that is, by §5, *external and untrusted*. This slice is the part of that which needs no network and can be checked exactly: the JSON-RPC requests, and a **strict reader of the responses** that believes nothing about a transaction it has not compared with what was signed. The lifecycle (submitted, included, final, dropped, replaced) and the executor that polls are the next slice; they are built on what this one can say.

### 16.1 Requests

Fixed texts, `{"jsonrpc":"2.0","id":<n>,"method":"<m>","params":[...]}`, written into a buffer of at least 8,448 bytes (a raw transaction is limited to 4,096 bytes, `-312` beyond): `eth_chainId`, `eth_blockNumber`, `eth_getTransactionCount` (an address, `"latest"` or `"pending"`), `eth_sendRawTransaction`, `eth_getTransactionReceipt`, `eth_getTransactionByHash`, `eth_getBlockByNumber` (a number, no transaction bodies). Quantities are `0x` and lower-case hex with no leading zero; hashes and addresses are `0x` and lower-case hex; `id` is the caller's integer.

### 16.2 Responses

A response is at most 65,536 bytes (`rpc-json`), one JSON object with `"jsonrpc":"2.0"`, the `id` that was sent (`rpc-id`), and **exactly one** of `result` and `error` (`rpc-shape`). **[choice]** A key that appears twice in the response or in an object read from it, or is written with an escape, is refused (`rpc-duplicate`): `std.json` lets the first win, and a reader that takes the first where another takes the last is how two parties come to disagree about what a provider said. Members the codec does not read are ignored: providers add fields.
An `error` is its code and nothing else (the message is a provider's free text and is never interpreted: **no decision is taken from the wording of an error**).

| reader | accepts | refuses |
|---|---|---|
| quantity | `0x0`, or `0x` and 1 to 15 lower-case hex digits starting with 1 to f | upper case, `0X`, a leading zero, an empty `0x`, 16 digits or more, not a string, an escape (`rpc-quantity`) |
| hash | `0x` and exactly 64 lower-case hex digits | anything else (`rpc-hash`) |
| address | `0x` and exactly 40 hex digits, either case (providers return checksummed text) | anything else (`rpc-address`) |
| data | `0x` and an even number of lower-case hex digits | `rpc-data` |
| chain id | a quantity equal to the configured chain id | `rpc-chain` |

### 16.3 What a transaction must be, to be believed

**A receipt** (`eth_getTransactionReceipt`): `null` is *not found*, not an error. An object is believed only if its `transactionHash` is the hash we computed from the bytes we signed, its `from` is the wallet, its `to` is the token contract (a receipt with no `to` is a contract creation, not ours), `status` is exactly `0x1` or `0x0` (a receipt without a status is pre-Byzantium and not accepted: `rpc-status`), and `blockNumber`, `blockHash` and `gasUsed` are well-formed. A receipt for another transaction, from another account, or to another contract is `rpc-receipt`: a provider that answers about something else is lying or confused, and either way the answer is not used.
**A transaction** (`eth_getTransactionByHash`): `null` is not found. An object is believed only if its `hash`, `from`, `to`, `nonce`, `input` and `value` are exactly the hash, wallet, token, nonce, calldata and zero that were signed (`rpc-tx`); `blockNumber` is `null` (pending) or a quantity (mined).
**A block** (`eth_getBlockByNumber`): `null` or an object whose `number` is the number asked for and whose `hash` is well-formed; it is how a block hash at a height is read again later, so that a reorganisation is a hash that changed.

### 16.4 How it is checked

`scripts/check_rpc.py`: requests are compared with the model's text byte for byte and must parse as JSON with exactly the fields; responses are fixtures in the shapes real clients write (Geth, Erigon, an Infura-style gateway: extra fields, checksummed addresses, `null` for not found, the error codes of `-32000`, `-32601`, `-32602`), with the transaction built and signed by `eth-account` (the hash, the sender and every field of the node's answer come from its transaction, not from this code), and the adversarial ones: a duplicate key at every level, a wrong `id`, both or neither of `result` and `error`, another `jsonrpc`, each quantity and hash and address spoiled each way, a receipt with another hash, sender, contract, or no status, a transaction object that differs from what was signed in each field, a chain id off by one; every response truncated at every byte (never accepted, never a trap); and `--mutants`. Results are added below when measured.

### 18.5 Results (measured)

`CANCHO=... python3 -I scripts/check_executor.py` (the real binary against two mock nodes): **176 checks, 0 failed**. `--mutants`: **78 mutants, 72 killed, 6 survivors, each explained** in `EQUIVALENT` in the script (five are equivalent: a cut or too-long answer is also refused by the length check, the JSON reader or the head check; the write deadline cannot be reached by a request that fits the socket buffer; a failed append is followed by a failed flush). **One is not proven equivalent** (`a receipt without its transaction`): the clause rejects a receipt in block 0 next to a pending transaction, and a test that sends exactly that is refused by the mutated executor too, for a reason I did not trace; so no input is known that this clause alone catches. It stays as defence in depth.

**The checks found a real fault in the executor, now fixed** (corrected in place): when both providers were behind the block they named (tip below the block), `lifecycle.observe` refused with `-321` even though no decision was being made, so a lagging pair of providers stopped the executor with `chain.executor-state` instead of "no decision". The executor now passes the record no block it cannot be in. The same checks also showed that a corrupt `state` file was read as absent; it is now refused (`executor-state`) unless the file is missing.

**Still not done:** TLS (a provider is reached through a loopback forwarder), chunked answers, verifying the signature, an external copy of the signer's anchor kept by the front or the gateway (§19.2: the signer only emits it), constant-time secp256k1 (alpibrusl/cancho#712), an independent review.

**Not in this slice, said now.** A network connection (nothing here opens a socket), a second provider for critical reads (§5 asks for one: the executor will take two answers and require them to agree before a transaction is called final), and the lifecycle's states and transitions.

### 16.5 Measured

**[measured]** 2026-11-07, Linux x86-64, the self-hosted `cancho` at `162633a7`, `eth-account`, `eth-abi`, `rlp`, `eth-utils` and `pycryptodome` from pip. `CANCHO=<compiler> python3 -I scripts/check_rpc.py [--mutants]`: **635 of 635** checks pass.
- **Requests:** 6 random cases of each of the eight requests, and a fixed grid of 11 ids by 15 block numbers at every decimal and hexadecimal digit-count edge (0, 1, 9, 10, 99, 100, 255, 256, 65,535, 65,536 and 2^53 - 1; 0, 1, 9, 10, 15, 16, 17, 255, 256, 4,095, 4,096, 65,535, 65,536, 2^50 and 2^56 - 1), each the model's text byte for byte; an `id` of 2^53, a raw transaction of 4,097 bytes or none, and an address or hash a byte short are refused; 4,096 bytes is accepted.
- **Real shapes:** from transactions built and signed by `eth-account` (random chain, nonce, fees, token, recipient and amount; its hash and sender), the receipt (status 1 and 0), the transaction (mined and pending), the block, the chain id and each `null` are read as the model says, with checksummed addresses, `logs`, `logsBloom` and a dozen members the codec does not read; a receipt with 300 more members and a result with 1,500 are read.
- **Spoiled:** 29 receipts (another hash, sender or contract; no contract (a creation) and no `to` key; a status of 2, `0x01`, a number, a boolean, `0X1`, or none; each quantity with a leading zero, in upper case, of 16 digits, a number, or missing; each hash short, long, upper-case or with no prefix), 24 transactions (every signed field different, malformed, or missing; a `value` that is zero only in disguise), blocks and chain ids, and each of the quantity, hash, address and data readers at its edges, each answers **with the code the design gives**; a name twice (the first saying success), or written with an escape, at every level is `rpc-duplicate`.
- **The envelope:** 41 shapes of a response (another `id`, below it, and one that wraps an int to it; a string, a float and no `id`; `jsonrpc` 1.0, a number, an escape, or none; a `result` and an `error`, neither, a `result` of `null`; an error with no code, a string code, a code too big for an int, an error that is a string; a batch; a string; trailing bytes, two objects, a trailing comma, single quotes; 65,537 bytes refused and 65,536 read): each its code. **An error is its code and nothing else.**
- **Truncation and damage:** every proper prefix of a receipt response is `rpc-json` and none traps; 400 responses with 1 to 5 bytes replaced at random never trap; a response nested 5,000 deep is read or refused.
- `--mutants`: 118 deliberate faults (every bound and digit of the requests, each test of the envelope, each reader's alphabet, length and prefix, and each comparison of the receipt, transaction and block): **106 killed, 12 equivalent**, each explained in the script (a test that the next one repeats, or a length the driver fixes). The first run killed 83 of 118. Of the 35 survivors, 11 were a mutant of mine that changed nothing (a threshold of `-5` against codes that start at `-300`; rewritten), 12 are the equivalents, and the rest were checks missing (a one-digit id, the digit edges of a decimal and a hexadecimal count, an id that is one *less*, a chain id one less, a `jsonrpc` written with an escape, an error code too big for an int, a one-character quantity, a `/` among the digits, a hash with only one digit in upper case, a block one less, no `to` key, a malformed sender or nonce in a transaction).
- **Found while building:** the driver's integer reader keeps 7 bytes, so the first run of the grid showed block 2^60 - 1 as 2^52 - 1; the codec was right, the driver is documented as 2^56 - 1 and the grid stops there. A quantity of 15 hex digits is read by the codec (tested through a result).

**Not claimed.** A connection (nothing here opens a socket), a second provider, the lifecycle, and that the model and the code agree on *what a provider says* beyond the shapes tested: the fixtures are in the shapes of real clients, written by me, not recorded from a node.

## 17. The lifecycle (slice 10)

**Status: built.** Results are in §17.6. A signed transaction is not a payment: it is bytes, and what becomes of them is read from untrusted providers (§16). This is the part of the executor that decides, as a **pure function** of what was last known and what the providers now say, what a transaction is and what, if anything, may be done about it. The executor that fetches the answers, and the HTTP, are the next slice; this one is checked exhaustively.

### 17.1 The record

74 bytes, canonical, so that it can be kept by a process that is killed at any moment: `[0]` version 1, `[1]` the state, `[2..10]` the nonce, `[10..18]` `sent_at` (ms, the last time a send was tried), `[18..26]` `changed_at` (ms, the last time the state changed), `[26..34]` `consumed_at` (ms, when the account's nonce was first seen past ours with our transaction nowhere: 0 if not), `[34..42]` the block it is in, `[42..74]` that block's hash. `check` refuses anything else: a state outside 1 to 9, a block and hash on a state that is not in a block (and none on one that is), a `consumed_at` on a state that cannot have one.

| state | meaning | may be left? |
|---|---|---|
| 1 `SIGNED` | we hold the bytes and have never sent them | yes |
| 2 `SUBMITTED` | a provider took it, or it was seen pending | yes |
| 3 `UNCERTAIN` | a send failed or timed out and nothing has shown the transaction since | yes |
| 4 `INCLUDED` | a receipt with status 1, in a block | yes: a reorganisation can undo it |
| 5 `REVERTED` | a receipt with status 0, in a block: gas was spent and nothing moved | yes, the same |
| 6 `FINAL` | `INCLUDED`, with at least `k` confirmations, **and the block still the one it was**: terminal |
| 7 `FAILED_FINAL` | `REVERTED`, final in the same sense: terminal |
| 8 `REPLACED` | the account's nonce passed ours, our transaction was nowhere, and that stayed true for `settle_ms`: terminal, **not moved** |
| 9 `DROPPED` | not seen by the providers for `drop_ms` since the last send, and the nonce still unused | yes: the same bytes may be sent again |

### 17.2 What it is told

Each step is one **observation**, made by the executor from two providers' answers: *agree* (the providers said the same, else the observation is empty and nothing changes: **no decision is taken on one provider's word when two are asked and differ**); *tx* (0 not found, 1 pending, 2 mined); for a mined one, *status* (success or reverted), its *block* and *block hash*, the chain's *tip* and the *hash now at that block's height* (or unknown); the account's *latest nonce*; the *time*; and the configuration `k`, `drop_ms`, `settle_ms`.
A send is told as `after_send(ok)`.

### 17.3 The rules

**[choice]** The table, in this order, for a state that is not terminal and an observation that *agrees*:

1. **mined**: the state becomes `INCLUDED` (status 1) or `REVERTED` (0) with this block and hash (a different block or hash than before is a reorganisation and is recorded as the change it is); `consumed_at` is cleared. If the tip is at least `block + k - 1` **and** the hash now at that height is the block's hash, it becomes `FINAL` or `FAILED_FINAL`. A tip below the block, or a block that cannot be, is a refused observation.
2. **pending**: the state becomes `SUBMITTED` (from any non-terminal state, including `INCLUDED` and `REVERTED`: a receipt that was and is not, with the transaction back in the pool, is a reorganisation); `consumed_at` is cleared.
3. **not found**:
   * `SIGNED`: answer **submit**.
   * `INCLUDED` or `REVERTED`: the receipt has vanished: it becomes `UNCERTAIN` and, **if the nonce is still unused**, the answer is **resubmit**.
   * `SUBMITTED`, `UNCERTAIN`, `DROPPED`, and the account's nonce is past ours: if `consumed_at` is 0 it is set to now and nothing else happens; once `now - consumed_at >= settle_ms` the state becomes `REPLACED` (with a `settle_ms` of 0 the first sight is enough, as the operator asked). (The first sight of a consumed nonce with no transaction might be a provider that has the block and not yet the receipt; only a consumed nonce that *stays* is believed.)
   * `SUBMITTED` or `UNCERTAIN`, and the nonce unused: once `now - sent_at >= drop_ms` it becomes `DROPPED` and the answer is **resubmit**. `DROPPED` with the nonce unused answers **resubmit** (until a send moves it).
4. A terminal state never changes, and answers nothing.

`after_send(ok)`: from `SIGNED`, `UNCERTAIN` or `DROPPED`: `SUBMITTED` if ok, `UNCERTAIN` if not (and `sent_at` is now either way); from `SUBMITTED`: ok keeps it, not ok makes it `UNCERTAIN`; from any other state it is refused (`lifecycle-state`): **a transaction in a block, or ended, is never sent again**.

**Resubmitting is safe because the bytes are the same bytes.** The same signed transaction has the same hash and nonce, so a provider that has it ignores it and one that does not takes it; it cannot be paid twice. What the machine must never do is ask for a *new* signature for the same authorisation, and it has no such action: the signer's ledger (§14) would refuse it too.

### 17.4 Properties

Checked exhaustively over small domains and against a model, as predicates, not as a copy of the table: a terminal state is fixed under every observation; `FINAL` is reached **if and only if** a mined, agreeing, success observation has `tip - block + 1 >= k` and a hash at that height equal to the block's; `REPLACED` only after a consumed nonce was seen at least `settle_ms` earlier and is still there with the transaction nowhere; **no observation that disagrees changes anything**; a state in a block comes only from a mined observation; **submit** only from `SIGNED`; **resubmit** only when the nonce is unused and the transaction was not found; every record the machine writes passes `check`; and `check` refuses every single-byte spoiling of a record that makes it non-canonical.

### 17.5 How it is checked

`scripts/check_lifecycle.py`: the machine as a program (`tools/lifedrv`) against a model in Python written separately (a different formulation: the model is a rule list evaluated top-down on a dictionary, not the order of `if`s); the exhaustive product of every state, every observation shape over a small domain (tx 0 to 2, status, block and tip around the finality edge, hash equal or not, nonce below, equal and above, times around the two windows, agree or not), the properties of §17.4 as predicates over the result, random long walks (thousands of steps with a random provider that sometimes lies, reorganises or forgets) that must keep every invariant, and `--mutants`. Results are added below when measured.

**Not in this slice.** Fetching the answers, asking two providers and deciding that they agree, the HTTP, persisting the record, and the evidence events written at each change.

### 17.6 Measured

**[measured]** 2026-11-07, Linux x86-64, the self-hosted `cancho` at `162633a7`. `CANCHO=<compiler> python3 -I scripts/check_lifecycle.py [--walks N] [--mutants]`: **509 of 509** checks pass.
- **`check`:** 12 records (every state, `consumed_at` set where it may be) and every single-byte spoiling of each (six values at each of 74 offsets), a record one byte short or long, empty, a zero hash on a state in a block and a block on one that is not: 4,591 records and spoilings in all, each agreeing with the model's canonical form.
- **`after_send`:** every state, both outcomes, four times: the model's record, byte for byte; a state in a block or ended is refused (`E322`) and never written.
- **`observe`, the full product: 209,088 observations** (12 records by two configurations, `k` of 3 with windows of 100 and 50 ms and `k` of 1 with none; agreeing and not; not found, pending and mined with every status, three blocks, two hashes, a tip at `block - 1`, `block` and the three edges of `k`, the hash at that height known or not and equal or not; a nonce below, at and above; six times around both windows): each answer, the record and the action, **equals the model's**, and **every property of §17.4 holds of every one of them, as a predicate** (`P1` to `P10`: terminal states fixed; a disagreement changes nothing; `FINAL` iff mined, agreeing, confirmed and the same block; in a block only from a mined observation; `REPLACED` only after a consumed nonce stayed consumed; **submit** only from `SIGNED`; **resubmit** only for an absent transaction and an unused nonce; `consumed_at` is when it was first seen; `changed_at` moves with a change and only then; `sent_at` and the nonce are not touched). Refused observations: a `tx` of 3, a tip below the block, a hash a byte short, a `k` of 0, a spoiled record.
- **Random walks** (default 60, in a world that advances, reorganises up to `k - 1` deep, forgets its pool, and where another transaction can take the nonce; at each step at most one of two providers lies, in six ways): every step keeps every property; **the machine is never `FINAL` unless the truth says the transaction is mined with `k` confirmations and the status it claims, and never `REPLACED` unless the nonce was taken and the transaction is nowhere**; a world with honest providers reaches its end every time (in a run of 120 walks: 96 `FINAL` or `FAILED_FINAL`, 24 `REPLACED`, none stuck, with lying providers as well).
- `--mutants`: 83 deliberate faults (every bound and offset of the record and its `check`, each of the nine states in the places it matters, the arguments' ranges, the two windows and their edges, the finality edge and its three conditions, the first sight of a consumed nonce, a vanished receipt in each of its two forms, each action): **76 killed, 7 equivalent** (the driver's integers are unsigned, so a negative argument cannot be given; the check is for callers that compute their own). The first run killed 73 of 83; the survivors were a hash zeroed on a state in a block (a single-byte spoiling cannot make it), a window measured from the wrong field (the model's `sent_at` and `changed_at` were equal), and a vanished receipt with `settle_ms` of 0, each of which became a case of the product.
- **Found while building:** with `settle_ms` of 0 the first sight of a consumed nonce is enough (the property first said otherwise, and is now stated as the rule is); a consumed nonce that is *not* settled cannot end in `REPLACED` through a receipt that vanished, by design.

**Not claimed.** That the world model resembles a chain beyond the cases it has (it is mine); the persistence of the record and the evidence events at each change; fetching, quorum and HTTP, which are the next slice.

## 18. The executor (slice 11)

**Status: built (§18.5).** The executor is what makes a signed transaction happen and be known to have happened: it asks two providers what they see, decides with the lifecycle (§17) whether they agree and what to do, sends the same bytes again when that is what the lifecycle says, and leaves evidence of every change. It is one tick per process, like the signer: run it from a timer; every tick is safe to repeat and to kill.

### 18.1 What it holds, and what it can reach

It holds **no key**. Its authority (`cancho authority`): one directory, **two outbound addresses** (the two providers, compile-time constants, narrowed one each), the clock, the heap, standard output. No `exec`, no listening port, no foreign code. **[choice]** The providers are plain TCP and HTTP/1.1 with `Content-Length` (a chunked answer is `provider-chunked` and refused): the executor does not speak TLS, so a provider that needs it is reached through a local forwarder that does (stunnel or a reverse proxy on loopback). This is a limit, said here and in the README: until a TLS client is in the executor, a provider across the internet is not reached by it directly.

| file | what |
|---|---|
| `config` | `chain=<n>`, `k=<n>`, `drop_ms=<n>`, `settle_ms=<n>`, one to a line, in this order |
| `envelope` | the authorisation envelope (§13), hex: **what was authorised** |
| `raw` | the signed transaction, hex: **what is sent** |
| `state` | the lifecycle's 74-byte record, hex; written by `state.new` and a rename |
| `evidence.seg` | `cancho-log` in trail mode (as the signer's ledger): one `tx.state` event per change |

### 18.2 A tick

1. Take `flock` on `evidence.seg`; verify the trail whole and read-only, then recover a torn tail (the signer's rule, §14.3): a ledger that does not verify stops the tick (`executor-evidence-corrupt`).
2. Read the job and **check that it is what was authorised**: the envelope well formed, and `txcheck.validate_signed` of `raw` against the envelope's own chain, nonce, token, recipient, amount and caps (so what is sent is exactly what the policy allowed, whoever wrote `raw`); the configured chain is the envelope's. The transaction hash is `keccak256(raw)`, the wallet and token are the envelope's. (The signature is not verified here: a receipt whose `from` is not the wallet is what catches a transaction signed by another key, §16.3.)
3. If there is no `state`, make one (`SIGNED`, the envelope's nonce) and leave evidence.
4. **Ask each provider** (a few JSON-RPC requests each, a few seconds' deadline apiece): the chain id (**it must be the configured one, else the provider is refused**), the account's latest nonce, the tip, the transaction by hash, its receipt, and, if it is mined, the block's hash at that height. Each answer is read by `chain.rpc` and believed only as §16.3 says. A provider that cannot be reached, answers wrongly, or contradicts itself (a receipt with no transaction mined, or a transaction mined with another block) is **unusable** this tick.
5. **Agree:** both providers usable and the same on what they say about the transaction (not found, pending, or mined with the same status, block and block hash), the nonce and, if mined, the hash at the height; the tip is the lower of the two. Otherwise `agree` is false and the lifecycle changes nothing. **One provider's word is never enough, and a provider that is down is not a vote.**
6. `lifecycle.observe`. If it answers **submit** or **resubmit**, send `raw` to both providers; a provider *took* it if its `result` is this transaction's hash (anything else, an error included, is a failure: **no decision from an error's wording**); the send is ok if either took it; `after_send`.
7. If the state changed, append the evidence event and flush, **then** write `state`. A tick killed between the two leaves the evidence one step ahead of the state; the next tick sees the same facts, makes the same change and writes the event again: **evidence is at-least-once, the state exactly the lifecycle's**. A tick killed after a send and before the state is written finds the transaction pending, which is `SUBMITTED`: the same bytes are never a second payment.
8. Print one line: `{"ok":true,"state":"<name>","action":"nothing"|"submit"|"resubmit","sent":<bool>,"agree":<bool>}` and exit 0; a refusal is `{"ok":false,"rule":"chain.<tag>","repair":"..."}` and exit 2.

### 18.3 The evidence event

Kind `tx.state`, payload `{"envelope":"<id hex>","tx":"<hash hex>","state":"<name>","block":<n>}` (the block is 0 outside a block): written when the state changes. It names the envelope's id (§13) and the transaction's hash, so an auditor can walk from the signer's ledger entry (`envelope.consumed`) to what became of it.

### 18.4 How it is checked

`scripts/check_executor.py`: the real executor against **two mock nodes** (Python HTTP servers speaking JSON-RPC from a model of a chain: blocks, a mempool, an account nonce, with a transaction built and signed by `eth-account`) that can be made to forget, reorganise, lie, answer with another chain id, hang, answer in chunks or with garbage, or be down. Ticks are driven by the script. Scenarios: an honest chain to `FINAL` (the evidence has each change, the hash chain verifies with `trailtool`); a reverted transaction to `FAILED_FINAL`; a transaction the mempool forgets (`DROPPED`, resent, final); a reorganisation (back to `SUBMITTED`, then final in the new block); a nonce taken by another transaction (`REPLACED` only after `settle_ms`); one provider lying at each step (nothing changes, nothing is sent twice, and the state is never `FINAL` unless the truth says so); one provider down or hanging; a provider on another chain; a job that is not what the envelope authorised (refused before any request); a killed tick (state and evidence consistent, the same transaction); the authority of the binary; `--mutants`. Results are added below when measured.

**Not in this slice, said now.** TLS, a chunked answer, more than two providers, scheduling (the caller's), verifying the signature, a fee bump or replacement (the lifecycle has no such action by design: §17.3).

## 19. The signer's anchor (slice 12)

**Status: built (§19.5).** §14.5 said what the signer could not do: it cannot tell a ledger whose last record has a damaged length field from a torn tail, and it cuts it, so one consumed entry is lost and its envelope can be signed again. More generally a cut tail, or a ledger rewritten consistently, verifies: a hash chain proves nothing about what is *missing from its end* unless someone holds `(count, head)` from outside it (cancho-log `docs/trail.md`). `trail.verify` already takes that anchor; this slice wires it.

### 19.1 The rule, and why it is enough

**An envelope is signed only if its ledger entry is covered by the anchor.** The signer keeps the anchor `(count, head)`, the number of entries and the id of the last one, in a file of its own, and moves it **after the ledger flush and before the signature**:

1. verify the ledger whole, read-only, **against the anchor** (`trail.verify` with the anchor);
2. a fresh envelope: append and flush the entry; **then write the new anchor** (a temporary file and a rename); **then sign**.

Consequences, each of which the checks make fail if it is false:

- No signature ever exists for an entry beyond the anchor. So a torn or damaged *last* record that is beyond the anchor was never signed: **cutting it is safe**, which is exactly the case §14.5 could not decide. A damaged record *within* the anchor (fewer events than the anchor counts) is refused, not cut: `signer-anchor-short`.
- A tail cut below the anchor is refused (`signer-anchor-short`); a ledger rewritten with another entry at the anchor's count is refused (`signer-anchor-mismatch`).
- A crash after the flush and before the anchor write leaves the ledger one entry ahead of the anchor. The next start finds the entry beyond the anchor, **writes the anchor to cover it before any signature**, including for the same envelope presented again (*same* signs again only once it is covered).
- A crash after the anchor write and before the answer loses a signature and never lets a second one out, as before.

### 19.2 The file, and what the signer is trusted with

`/var/lib/cancho-anchor/anchor` (a second compile-time directory, so `cancho authority` names exactly two paths): `<count in decimal> <head, 64 lowercase hex>\n`, read by position and refused if anything else (`signer-anchor-corrupt`: a leading zero, a missing newline, upper case, a second line, a count over the ledger's limit). **[choice]** No anchor file with a ledger of two or more entries is `signer-anchor-missing`, not "no anchor": deleting the file must not switch the protection off. A new deployment (empty ledger, no anchor) starts normally and writes the first anchor with the first entry; no anchor and **one** entry is what a crash at the very first entry leaves (the anchor is "zero entries" and the rule below allows one ahead), so it is covered and goes on. That makes deleting the anchor of a one-entry ledger and cutting that entry undetectable: a window of one entry, closed by the second. A ledger that already exists is adopted by the operator writing the file from `trailtool verify` (its `events` and `head`).
**[choice]** The entries beyond the anchor may be **at most one**; more is `signer-anchor-behind` (the signer writes the anchor with every entry, so a larger lag means the anchor was restored from an older copy, or the ledger was extended by someone else). A consistent rollback of both files cannot be told from a clean history: no anchor can.

**What this does not give, said now.** The anchor protects only if the party that can damage the ledger cannot also rewrite the anchor. The signer's process can write both; a person with the signer's user can too. The protection is real **when the anchor directory is another user's, another volume, an append-only mount, or is copied out**: the signer's answer therefore also carries the new anchor, `"anchor":{"count":N,"head":"<hex>"}`, so the front, the gateway or an auditor can keep a copy the signer cannot reach. How the copy is kept and compared is the deployment's, and **until it is, this closes accidental damage and ledger-only tampering, not an attacker who owns the whole host.** The executor's evidence trail has the same gap and is not changed here (its state is the lifecycle's and it signs nothing).

### 19.3 New refusals

`signer-anchor-corrupt`, `signer-anchor-missing`, `signer-anchor-short`, `signer-anchor-mismatch`, `signer-anchor-behind`, `signer-anchor-write` (the anchor could not be written: **no signature**, the entry stays and the next start covers it). Each has a stable tag, a repair, and no input reaches a panic.

### 19.4 How it is checked

`scripts/check_signer.py` grows, against the independent ledger reader and `trailtool`: the anchor after each fresh request is `(count, head)` as the reader computes it; every refusal above; a ledger cut at each record boundary below the anchor; a last record damaged in each byte of its length field (which §14.5 cut and now is refused when covered and cut when not); a flush-then-fail run (anchor directory unwritable: no signature, ledger one ahead, the next start covers it, the same signature is returned); the anchor restored from an older copy; the file with each kind of damage; the answer's anchor equals the file's; `cancho authority` names exactly the two directories. New `--mutants`. Measured results are added below.

### 19.5 Results (measured)

`check_signer.py`: **618 checks, 0 failed** (386 before this slice), and `--mutants`: **85 mutants, 83 killed, 2 equivalent, each explained** (one older: a torn length bound that no input can miss; one new: a six-digit count is over `max_entries`, which the next check refuses with the same tag). `check_front.py` (117) and `check_stack.py` (15, through the real gateway) still pass with the signer built for two directories; the whole gate (`scripts/gate.sh`) passes.

What the checks measured, and what they changed:

- The anchor in the file and in the answer equals `(count, head)` as the independent ledger reader computes them after every request, and `trailtool verify <dir> <count> <head>` confirms it (`anchor 1`).
- Refused with the ledger and the anchor **byte for byte untouched**: no anchor with two or more entries, 19 kinds of damaged anchor file (leading zero, zero, over the limit, no newline, a second line, upper case, short and long heads, a colon in the count, a directory, 5,000 bytes, and others), a ledger cut at each record boundary below the anchor, a ledger rewritten consistently (the same chain with another third entry; another whole ledger of the same length), a ledger two or three entries ahead of its anchor, and an anchor with no ledger.
- **A fault the first run showed, now fixed:** a failed anchor write at the very first entry left a ledger of one entry and no anchor, which the rule above refused as `signer-anchor-missing`, so one crash would have stopped a new deployment until a person wrote the file. "No anchor" is now "zero entries": one entry ahead is allowed, so it is covered and goes on; two or more is still refused. The cost, said in §19.2: deleting the anchor of a one-entry ledger and cutting that entry goes undetected, a window the second entry closes.
- A ledger one ahead of the anchor (a crash between the flush and the anchor write) is covered at the next start, before any signature, and the signature is the clean run's (RFC 6979). An anchor that cannot be written (`/dev/full`) gives no signature and leaves the entry on the ledger; the next run covers it and signs.
- **The damaged-length case of §14.5, measured:** of 12 single-bit damages to the length field of the last record (four bytes, three bits), **one** looked torn (a length grown past the end of the file); the others were already refused as corrupt. The one that looked torn is refused when the anchor covers it and **cut when it does not**, the entry then fresh and signed once.
- Not tested, said plainly: the order flush, anchor, signature is not distinguished from anchor-then-flush by any kill point (a process is not killed between two lines here); what the tests show is its observable result (no signature when the anchor cannot be written; a covering anchor after a crash). Durability across a power loss depends on `fs_write` and the file system (it does not call `fsync`); across a process kill the order holds.

## 20. The witness: an anchor kept outside the signer's directory (slice 13)

**Status: built (§20.5).** §19 keeps the anchor `(count, head)` in a second directory, and says its protection holds only if whoever can damage the ledger cannot also rewrite the anchor. This slice puts a **copy** where the signer's directory is not: the **front** keeps the last anchor the signer answered, in its own directory, and hands it back with every request; the signer refuses a ledger that the copy contradicts.

### 20.1 What it protects against, and what it does not

The signer's user holds the wallet key. Someone who owns that user can sign anything, with or without a ledger, so **no anchor protects against them, and none is claimed to.** What a copy elsewhere protects against is what can *write files in the signer's directories but cannot run the signer*: a **snapshot or backup restore** of the signer's volume (the most ordinary way to lose entries: the ledger and its anchor go back together, every envelope signed since can be signed again), a sync or deployment tool that overwrites the directory, an operator who "repairs" the ledger, a disk that loses its last blocks. The local anchor of §19 catches a ledger damaged on its own; the witness catches a ledger and anchor restored **together**. It is only as independent as the front's directory is from the signer's: **a different volume with its own snapshot schedule, or the same volume restored at another time, is what the deployment must provide**; two directories in one snapshot are one copy.

### 20.2 The protocol

- The signer's request line gets a **fifth field**: `<count> <head>` (the front's last witnessed anchor, as in §19.2: a decimal count, a space, 64 lower-case hex digits) or `-` (the front has none). The signer's answer already carries `"anchor":{"count":N,"head":"…"}` (§19.2).
- The front keeps **`/var/lib/cancho-front/witness`**, one line in the anchor's own format, written (a temporary file and a rename) from the anchor of each `200` answer **before it sends that answer on**; if it cannot write, it answers `503` (`front-witness-write`) and keeps the signature to itself: the next request for the same envelope is *same*, with the same bytes, and only then is the answer given. The front reads the file at each request and puts it on the line; an unreadable file, or one that is not a single line of lower-case hex digits and spaces of at most 72 bytes, is `503` (`front-witness`), not "none"; **how strict the text is is the signer's to say** (a witness that is a line of that alphabet but not an anchor is `signer-request`), the front only keeps it from breaking the request line. (Corrected in place from the first draft, which had the front validate the anchor's whole format.)
- The signer, after the §19 checks and before anything is signed: **with a witness `(w, hw)`**, the ledger must hold at least `w` entries and the one at `w` must have id `hw` (`trail.verify`'s anchor test, as for the local anchor), and the ledger may be **at most one entry ahead** of the witness *when it is checked* (the front writes it after every signature; a crash or a failed write between the signature and the write leaves one). **So up to two signatures can be lost to a front that cannot write** (the second request is checked at one ahead, appends and signs, and its answer is lost too); the third is refused. Measured in §20.5. Refusals: `signer-witness-short`, `signer-witness-mismatch`, `signer-witness-behind`. **With `-`**, the ledger must hold **at most one entry**: `signer-witness-missing` otherwise, so that deleting the front's file does not switch the check off. (The window of one entry is the same as §19.2's, and for the same reason.)
- A request line with four fields, or six, is `signer-request`: the front is the signer's only caller in the stack, and a signer that quietly accepts a caller without a witness is a signer a restore can get around.

### 20.3 What the front is trusted with

Nothing it could use to sign. A compromised front can send `-` or an **older** witness (weaker or refused: it never makes the signer accept more than the local anchor already does), a **newer** or wrong one (the signer refuses everything: a denial of service the front already had by not forwarding), and cannot reach the key. Its authority grows by **one directory** (`fs_read` and `fs_write` of `/var/lib/cancho-front`), which the report shows. It still holds nothing secret, has no network out and starts one program.

### 20.4 How it is checked

`check_signer.py`: the fifth field in every request; a witness equal to, one behind and two behind the ledger; a witness ahead (short), a witness that names another entry (mismatch), `-` with a ledger of zero, one and two entries; a **restore** (the ledger and the local anchor both put back to an earlier state, which §19's checks cannot see and the witness does); four and six fields; each malformed witness. `check_front.py`: the witness written from each `200` answer and from none else; the file's bytes; a write that fails (`/dev/full`: `503`, and the retry returns the same signature); an unreadable or damaged file (`503`, the signer never started); the witness on the request line; the report of the front. `check_stack.py`: through the real gateway, a restore of the signer's directory is refused. `--mutants` for each. Results are added below when measured.

**Not in this slice, said now.** Signing the witness (a signed checkpoint, so that the front cannot be made to hold a wrong one by someone who writes its directory); a witness kept by a party other than the front; the executor's trail (§19.2).

### 20.5 Results (measured)

`check_signer.py`: **764 checks, 0 failed**; `--mutants`: **104, 100 killed, 4 explained** (the older equivalent bound of §14, a six-digit anchor count over `max_entries`, an odd hex field that `hex.decode` refuses anyway, and a short line that the empty-field check refuses anyway). `check_front.py`: **173 checks, 0 failed**; `--mutants`: **96, 93 killed, 3 explained** (two older equivalents, and a length bound that no valid answer can reach: a 200 line holding the anchor's tail is at least 107 bytes). `check_stack.py`: **15 of 15** through the real gateway. The whole gate passes locally, with the self-hosted compiler and with the cargo-built pinned compiler CI uses.

- **The protocol:** the front puts the witness on the signer's line (`-` before its first answer), writes it from each `200` before the answer goes on (the file is the answer's anchor, byte for byte), leaves it alone for a retry (the same entry), a refusal, a `502` and a signer that lies; a write that fails (`/dev/full`) is `503 front-witness-write`, **no signature in the answer**, and the retry is the same entry with the model's signature and writes the witness.
- **The signer:** a witness equal to the ledger and one behind are accepted; two behind is `signer-witness-behind`; ahead is `-short`; naming another entry, or the right head with the wrong count, is `-mismatch`; `-` is accepted for a ledger of zero or one entry and is `-missing` for two or more; four fields, six or seven, and 17 malformed witnesses are `signer-request`; an empty caller field is `signer-request`. **Refused with the ledger and both anchors untouched** in every case.
- **A restore** (the signer's ledger and local anchor put back to two entries, together) is **accepted by §19's checks and refused by the witness** (`signer-witness-short`), at the signer and through the front; with the witness restored too it is accepted, which is §20.1's limit, shown rather than said.
- **Two lost answers:** with the front unable to write, the first and second fresh requests are `503 front-witness-write` (both signed and on the ledger), and the third is `503 signer-witness-behind`, nothing signed.
- **Damaged witness files:** 15 kinds (empty, one byte, upper case, binary, two lines, no newline, over 72 bytes, a tab, a carriage return, `g`, `` ` ``, `/`, `:`, `@`, a directory) are `503 front-witness` and **the signer is never started**; a missing file with a ledger of several entries is `503 signer-witness-missing`.
- **The front must not trust a `200` blindly:** a signer whose `200` has no anchor, an upper-case head, a six-digit or empty count, junk after the count, or a head whose last digit is not hex is `502 front-signer` and no witness is written.
- **Authority of the front:** one directory (`fs_read` and `fs_write` of its own, and `file_read`), the port in, the signer to start, nothing else.

**Faults the checks found, fixed:**
- The front mapped the signer's `signer-anchor-*` refusals (slice 12) to `422` (a bad request) instead of `503` (an unwell signer): the front's own table was not updated with the signer's. Both families are `503` now, each tag tested.
- The first version of the front declared `file_write` in a row that never performed it. **The self-hosted `cancho` accepted it; the cargo-built pinned compiler refused it** ("a row is exact or it is decoration"), found by cancho-chain's CI. This is a difference between the two compilers, not fixed here.
- Several fake-signer modes of `check_front.py` had stopped testing what they were named for once a `200` had to carry an anchor (they failed for the missing anchor, so the line-count and size guards were no longer tested); each now carries a valid anchor and fails only for its own fault. Mutants showed it.

**Not claimed.** Independence of the front's directory from the signer's (the deployment's, §20.1); a signed witness; a witness kept by anyone but the front; the executor's trail; and that two signatures cannot be lost to a front that cannot write (they can; the third is refused).

## 21. The executor over TLS, and chunked answers (slice 14)

**Status: design, written before the code.** §18 says what the executor does not do: it speaks plain HTTP with a `Content-Length`, so a provider across the internet is reached only through a local forwarder that terminates TLS. That forwarder is a second program holding the connection the executor's decision rests on, and no provider (Infura, Alchemy, a node behind a gateway) answers without TLS or without chunking. This slice puts both in the executor, **by using what cancho already has and not by writing a second HTTP or TLS reader here**.

### 21.1 What exists (read in the cancho repository on 2026-11-07, not measured here)

- `packages/tls`: a sans-I/O TLS 1.3 client **engine** (`start`, `feed`, `take`, `send`, `recv`; no socket inside; the chain verified against roots the caller gives, the name and the time given at `start`; HelloRetryRequest refused). One client slot is about 269 KB (`docs/http-client.md` §2).
- `packages/http-client` (`docs/http-client.md`, built, with 118 unit tests, a million damaged responses and 517 mutants): a sans-I/O HTTP/1.1 client with the strict response framing the gateway and `cancho-hooks` agreed on: a length, **chunked** (with extensions and trailers), until close, none; a repeated `Content-Length`, `Content-Length` with `Transfer-Encoding`, and a `Transfer-Encoding` other than exactly `chunked` are refused with tags. Its authority is `heap` and nothing else.
- `examples/http_fetch_nb/fetch_io.cho` (690 lines): the **driver** that owns the sockets, the TLS engine and the poller for that package. It is an example, not a package.
- `tcp_connect(net, name, port)` accepts a name (it resolves with the C library's `getaddrinfo`, blocking); `net_out("host:port")` narrows by prefix, the port exactly.

So the pieces are there; what is missing is the driver for one process that makes a few requests and exits.

### 21.2 Decisions

- **D1: replace `exchange`, `parse_http` and the response reader of §18 with `http.client`'s framing and `packages/tls`**, driven by one small pump per connection in `tools/executor`. The hand-written parser of slice 11 goes: it is a second reading of HTTP that the repository already has a better-tested one of. Its mutants go with it, and the checks it has stay (they test behaviour, not code).
- **D2: a provider is `http` or `https`, decided at build time**, as its address is (a compile-time constant, so that `cancho authority` names exactly what the executor can reach: `net_out("rpc.example.com:443")`, not a network). **Corrected after reading the driver (same day, before any code):** `fetch_io.dial` is typed `Net("")` (`net_out("")`: any host), so using the driver as it is would widen the executor from two exact addresses to the whole network. Only `dial` touches the network (the rest of the driver, `pump`, `step`, `shut`, has no `Net`), so the plan is the executor's **own `dial`, one per provider with the literal bound in its type** (label variables are not allowed in a function's signature, so two copies of about 50 lines). And `dial` connects with `tcp_connect_start` to an **IP literal the caller resolved**; an exact host bound (`net_out("rpc.example.com:443")`) is compared with the name, not the address, so the executor connects **by name with `tcp_connect`**, which resolves with the blocking `getaddrinfo` (D6's limit) and answers a connected socket that the copy of `dial` puts in the driver's table. **[open]** whether a driver slot can begin as already connected (to be probed before anything is built on it); if it cannot, the choices are a wider `net_out("")` for an `https` build (a weaker claim, said in the report), or a change in cancho's driver, and that is the maintainer's to choose. Plain `http` stays for loopback and for the tests; an `https` build adds the TLS engine. **[choice]** Two builds, not a runtime switch: a runtime scheme would put `net_out("")` back.
- **D3: the roots are a file in the executor's own directory** (`roots.pem`, PEM), read once per tick. The executor does **not** read the system's CA store (that would add a directory outside its own to its authority, and a store is a policy the operator should choose). **No roots, or none that parse, refuses every handshake** (`executor-tls-roots`); it never falls back to "no verification".
- **D4: the name checked is the provider's host in the constant**, and the time is the clock's (`clock_unix_ms`); both are given to `tls.start`. A name that does not match the certificate, an expired or not-yet-valid certificate, a chain that does not reach a root, a signature the engine does not support: the provider is **unusable this tick** (no decision), as any provider failure is in §18.2.
- **D5: randomness for the handshake is read from `/dev/urandom`** once per tick, which adds `fs_read("/dev/urandom")` and `file_read` to the report and nothing else. **[open]** whether the engine's `random` argument must be fresh per connection (read it per connection).
- **D6: the deadline of §18 (3,000 ms per provider call) covers the handshake too** (connect, handshake and every call of a tick may share one connection per provider, so a tick makes one handshake per provider, not one per call). A handshake that does not complete in time is the same unusable provider. **Name resolution is blocking and outside the deadline** (`getaddrinfo`); said as a limit: a resolver that hangs holds the tick, and the caller's timer (§18: scheduling is the caller's) must kill it. **[open]** `examples/tls_nb/rtcp.cho`'s non-blocking resolver would close it, at the price of `net_out("")`-class authority for DNS.
- **D7: a body that runs to the end of the connection needs `close_notify`** (the package's rule, §10.3 of `docs/http-client.md`): a TLS connection that ends without it is `reset`, not `eof`. A JSON-RPC answer has a length or is chunked, so this changes nothing for a provider that answers correctly; a provider that answers without a length and closes abruptly is unusable, which is what §18.2 already does with a short body.
- **D8: still refused or not done:** HTTP/2, a proxy, client certificates, session resumption, pinning a certificate or key beyond the roots, revocation (no OCSP or CRL: a revoked certificate under a trusted root is accepted), redirects, and a provider that wants a header (an API key) other than in the path: **the key of a provider is a secret, and the executor holds none by design (§18.1)**, so a provider that needs `Authorization` is reached through its own path-key URL (Infura's style) or not at all in this slice. **[open, and a real limit]** that is a restriction on which providers can be used; the alternative, a key file in the executor's directory sent as a header, makes the executor hold a credential and needs its own design.

### 21.3 What the authority becomes

The report of an `https` build: the directory (`fs_read`, `fs_write`), `/dev/urandom` (`fs_read`, `file_read`), the clock, the heap, standard output, **`net_out("<host>:443")` for each provider**, `poll`, `conn_read`, `conn_write`. No `exec`, no listening port, no foreign code, no other directory. The check pins it, as for the other binaries.

### 21.4 How it is checked

The mock nodes of `check_executor.py` get an **HTTPS mode**: Python's `ssl` with a test CA made by the script (`openssl` or the `cryptography` package), a server certificate for the name the executor was built with, and the CA's PEM written as the executor's `roots.pem`. Every scenario of §18.4 runs over both transports (so the lifecycle's behaviour is shown independent of the transport), and then the transport's own: a good chain (works); a **wrong name**, an **expired** and a **not-yet-valid** certificate, a chain to a **CA that is not in the roots**, a self-signed certificate, an empty `roots.pem` and one with garbage (each: the provider is unusable, nothing is sent, no decision, the state is not changed); a server that speaks TLS 1.2 only or SSL 3 (refused); a server that **closes without close_notify** after a complete length-framed answer (accepted) and in the middle of a body (unusable); an answer in **chunks** at every split size, with extensions and trailers, and a chunk size that lies (refused); a server that **never completes the handshake** (the deadline, about three seconds, no decision); a server that sends the answer in one-byte records; and a provider that **changes its certificate between two ticks** (each tick verifies afresh). `--mutants` over the new driver. The cost of a tick is measured and said (the handshake's CPU against the 3,000 ms budget, and the memory of two slots).

**Not claimed.** That the executor's choice of providers is safe against a provider that is a trusted-root-signed adversary (it is the point of two providers, §18.2); revocation; that name resolution is bounded.

## 12. Open questions for the maintainer

1. secp256k1: build it in cancho core (preferred) or here first? Are fallbacks acceptable if it proves too large?
2. May `cancho-chain` depend on `cancho-schema` (a package dependency) or is vendoring preferred? How do sibling repos consume each other (`cancho.toml` has no
   dependency section in cancho-opt)?
3. Is the Linux x86-64 seed expected to land in `cancho`, so CI can start without Rust?
