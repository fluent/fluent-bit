#!/bin/sh

set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

"$root_dir/scripts/agent-build.sh"
"$root_dir/scripts/agent-test.sh"
git -C "$root_dir" diff --check
git -C "$root_dir" diff --cached --check
