#!/bin/sh
# The gate: everything that must pass before a change is called done (CLAUDE.md).
#
#     CANCHO=<the pinned compiler> CANCHO_PACKAGES=<cancho>/packages CANCHO_SCHEMA=<cancho-schema>/src/schema.cho \
#     CANCHO_LOG=<cancho-log>/src scripts/gate.sh
#
# Formatting, the file budget, the unit tests, and every check against its independent oracle. The mutant runs (`--mutants` on each
# check) rebuild the program once per fault and take much longer: they are run when a check or the code it judges changes, not here.
# `check_stack.py` needs a built cancho-gateway and is run by hand (README).
# needs: pip install coincurve ecdsa pycryptodome eth-account eth-abi rlp eth-utils jsonschema
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CANCHO=${CANCHO:-cancho}
cd "$ROOT"
export CANCHO
: "${CANCHO_PACKAGES:=$ROOT/../cancho/packages}"
: "${CANCHO_SCHEMA:=$ROOT/../cancho-schema/src/schema.cho}"
: "${CANCHO_LOG:=$ROOT/../cancho-log/src}"
export CANCHO_PACKAGES CANCHO_SCHEMA CANCHO_LOG

"$CANCHO" fmt --check lib tools tests

# No source file over 2,000 lines.
big=$(find lib tools tests scripts -type f \( -name '*.cho' -o -name '*.py' -o -name '*.sh' \) -exec wc -l {} + | awk '$2 != "total" && $1 > 2000 { print }')
if [ -n "$big" ]; then
    echo "source files over 2,000 lines:" >&2
    echo "$big" >&2
    exit 1
fi

"$CANCHO" test --std tests/keccak.cho lib/keccak/keccak.cho
"$CANCHO" build --bin chain

for c in keccak eth decode intent policy envelope lifecycle rpc signer front executor; do
    echo "== check_$c"
    python3 -I "scripts/check_$c.py"
done
echo "gate: all passed"
