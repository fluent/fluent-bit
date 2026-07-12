#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

for script in "$repository_root"/scripts/agent-*.sh; do
    sh -n "$script"
done

"$repository_root/scripts/agent-build.sh" "$@"
"$repository_root/scripts/agent-test.sh"
