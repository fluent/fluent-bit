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
squash_date()
{
  ##"date":1763275639.56544,
  ##"date":1763275640.571014,
  sed -E 's/"date":[0-9]+\.[0-9]+,/"date":1234567890.123456,/'
}

filter()
{
  squash_date | sha256sum | cut -d\  -f1
}

if [[ $1 = -v ]]; then
  filter()
  {
    squash_date
  }
  shift
fi

if [[ $# -gt 0 ]]; then
  die "Usage: $0 [-v]

  Processes every parser*.*.test file in pwd, and makes sure the
  output produced by the .conf file and .yaml config versions match.

  Needs a corresponding .conf and .yaml for each.
"
fi

for A in parser*.test ; do
  F=$(echo "$A" | cut -d. -f1)
  P=$(echo "$A" | cut -d. -f2)
  echo "### $A"
  [[ -e ${F}.conf ]] || { warn "legacy '${F}.conf' not found, skipping"; continue; }
  [[ -e ${F}.yaml ]] || { warn "new '${F}.yaml' not found, skipping"; continue; }
  echo -n "CONF: ";
  CONF_OUT="$(cat $A | fluent-bit -q -R "${F}".conf -i stdin -p parser="${P}" -o stdout -p format=json_lines | filter)"
  echo "$CONF_OUT"
  echo -n "YAML: ";
  YAML_OUT="$(cat $A | fluent-bit -q -R "${F}".yaml -i stdin -p parser="${P}" -o stdout -p format=json_lines | filter)"
  echo "$YAML_OUT"
  if [[ "$CONF_OUT" == "$YAML_OUT" ]]; then
    echo "OK"
  else
    die "FAIL"
  fi
  echo
done
