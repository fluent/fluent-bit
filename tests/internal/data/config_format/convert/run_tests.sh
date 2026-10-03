#!/bin/bash

# Test a batch of parsers that have been converted from .conf to .yaml,
# to make sure they produce the same results (for each parser that provides
# test-case sample logs).

warn()
{
  echo "$@" >&2
}

die()
{
  warn "$@"
  exit 1
}

# Parsers that do not extract a date and use it will fall back to
# current time for date - changing from one run to the next.
# We have no choice but to squash well-formed date fields.
# N.B.: requires sed -E support - GNU or BSD sed
squash_date()
{
  ##"date":1763275639.56544,
  ##"date":1763275640.571014,
  sed -E 's/"date":[0-9]+\.[0-9]+,/"date":1234567890.123456,/'
}

# Unless in verbose mode, flatten each output to a checksum of itself
filter()
{
  squash_date | sha256sum | cut -d\  -f1
}

usage()
{
  die "Usage: $0 [-v] [file1.test [file2.test ...]]

  Process parser*.*.test files, either each one named on the command line,
  or every file in pwd matching that pattern.

  Makes sure the output produced by the .conf file and .yaml configs match.

  Needs a corresponding .conf and .yaml for each.
"
}

# Empty output (or a hash of an empty string) is a sure sign of failure
check_output()
{
  local check="$1"
  [[ "$check" = "" ]] || \
  [[ "$check" = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b" ]] || \
  [[ "$check" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ]] && \
	echo -e "\n" && die "### FAIL '$TEST_FILE' output was empty"
}

TEST_FILES=()

for arg in "$@"; do
  case "$arg" in
    -v) filter() { squash_date; }; ;;
    -*) usage ;;
    *)  TEST_FILES+=("$arg") ;;
  esac
done

# Make sure we have fluent-bit and confirm basic functionality
command -v fluent-bit >/dev/null 2>&1 || die "fluent-bit not found in PATH"
if ! echo '{"a":"b"}' | fluent-bit -q -i stdin -o stdout -p format=json_lines | grep -E -q '{"date":[0-9]+\.[0-9]+,"a":"b"}' ; then
  die "fluent-bit self-test failed, cannot continue."
fi

# If not provided any filenames, process all that match
[[ ${#TEST_FILES[@]} -eq 0 ]] && TEST_FILES=(parser*.*.test)

for TEST_FILE in "${TEST_FILES[@]}" ; do
  [[ $TEST_FILE =~ ^([^.]*)\.([^.]+)\.[^.]+$ ]] || \
	{ warn "'${TEST_FILE}': must contain three dot-separated tokens, skipping."; continue; }
  PARSER_FILE="${BASH_REMATCH[1]}"
  PARSER_NAME="${BASH_REMATCH[2]}"

  echo "### '$TEST_FILE'"
  [[ -e ${PARSER_FILE}.conf ]] || { warn "'${TEST_FILE}': legacy '${PARSER_FILE}.conf' not found, skipping"; continue; }
  [[ -e ${PARSER_FILE}.yaml ]] || { warn "'${TEST_FILE}': new '${PARSER_FILE}.yaml' not found, skipping"; continue; }
  echo -n "CONF: ";
  CONF_OUT="$(cat "$TEST_FILE" | fluent-bit -q -R "${PARSER_FILE}".conf -i stdin -p parser="${PARSER_NAME}" -o stdout -p format=json_lines | filter)"
  check_output "$CONF_OUT"
  echo "$CONF_OUT"
  echo -n "YAML: ";
  YAML_OUT="$(cat "$TEST_FILE" | fluent-bit -q -R "${PARSER_FILE}".yaml -i stdin -p parser="${PARSER_NAME}" -o stdout -p format=json_lines | filter)"
  check_output "$YAML_OUT"
  echo "$YAML_OUT"
  if [[ "$CONF_OUT" == "$YAML_OUT" ]]; then
    echo "### OK '$TEST_FILE'"
  else
    die "### FAIL '$TEST_FILE'"
  fi
  echo
done
