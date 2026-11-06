# CLAUDE.md -- cancho-chain

Bounded, auditable authority for autonomous agents that move assets, in pure cancho. Read [`docs/design.md`](docs/design.md) first; cancho's `AGENTS.md`
(`cancho agent-guidelines`) before writing cancho.

- **Pure cancho.** The package is cancho. Python is allowed for oracles, benchmarks and helper scripts under `scripts/`, never in the shipped binary.
  A native library is allowed only behind a narrow interface, with the reason written in `docs/design.md`.
- **The compiler is the self-hosted one**: the commit in `cancho.toml`, built by `scripts/build-standalone.sh` in the cancho repository (stage 2 = stage 3).
- **Design before code**: each verb or module gets a section in `docs/design.md` before its implementation, and every claim in it is *measured* (with the
  command), a *choice*, or *open*. A claim found false is corrected in place, in the document that made it.
- **Oracles, bit for bit.** Keccak-256 against pycryptodome (`scripts/check_keccak.py`); later, transactions and signatures against `eth-account`
  and the Ethereum test vectors. A gate is written so it can fail: `--mutants` rebuilds with one deliberate fault at a time and every mutant must be killed.
- **Fail closed. Every refusal has a stable rule tag. No input reaches a panic.** A refusal is a successful security outcome.
- **No float anywhere near an amount.** Amounts are exact integers in token base units.
- **No source file over 2,000 lines.** Split by concern.
- Licence EUPL-1.2, copyright Alpibru S.L. Commit trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`; PRs stay draft until the maintainer says merge;
  no force-push to main. Never put a model identifier in a commit message or PR title.
