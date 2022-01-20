set -euo pipefail

die() {
	echo $* >&2
	exit 1
}
