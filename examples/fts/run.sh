#!/usr/bin/env bash
#
# Run one FTS example: start Fluent Bit with the example configuration, send
# input.json to the OpenTelemetry input, print the processed output and
# compare it with expected-output.json.
#
# usage: examples/fts/run.sh <example-directory> [path-to-fluent-bit]

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <example-directory> [path-to-fluent-bit]" >&2
    exit 2
fi

example=$(cd "$1" && pwd)
root=$(cd "$(dirname "$0")/../.." && pwd)
fluent_bit=${2:-${FLUENT_BIT_BINARY:-$root/build/bin/fluent-bit}}
port=4318

case "$(head -c 200 "$example/input.json")" in
    *resourceLogs*)    signal=logs ;;
    *resourceMetrics*) signal=metrics ;;
    *resourceSpans*)   signal=traces ;;
    *) echo "cannot detect the signal of $example/input.json" >&2; exit 2 ;;
esac

work=$(mktemp -d)
trap 'kill "$pid" 2>/dev/null || true; rm -rf "$work"' EXIT

# Relative script paths are resolved from the working directory.
(cd "$example" && exec "$fluent_bit" -c fluent-bit.yaml) >"$work/stdout" 2>"$work/stderr" &
pid=$!

for _ in $(seq 1 50); do
    if curl -s -o /dev/null "http://127.0.0.1:$port/"; then
        break
    fi
    sleep 0.2
done

curl -sS --fail -H 'Content-Type: application/json' --data-binary "@$example/input.json" \
     "http://127.0.0.1:$port/v1/$signal" >/dev/null

# The pipeline flushes every second; give it time to write the output.
for _ in $(seq 1 25); do
    if grep -q '^{' "$work/stdout"; then
        break
    fi
    sleep 0.2
done
sleep 1
kill -INT "$pid"
wait "$pid" || true

grep '^{' "$work/stdout" | python3 -c '
import json, sys
print(json.dumps([json.loads(line) for line in sys.stdin], indent=2))
' >"$work/output.json"

cat "$work/output.json"

if diff -u "$example/expected-output.json" "$work/output.json" >&2; then
    echo "OK: output matches expected-output.json" >&2
else
    echo "FAIL: output differs from expected-output.json" >&2
    cat "$work/stderr" >&2
    exit 1
fi
