#!/bin/sh

test_generate_config() {
  output_file="${TMPDIR:-/tmp}/fluent-bit-generate-config-$$.yaml"
  error_file="${TMPDIR:-/tmp}/fluent-bit-generate-config-$$.err"
  check_file="${TMPDIR:-/tmp}/fluent-bit-generate-config-check-$$.out"

  "$FLB_BIN" -f 2.5 -i dummy -p 'dummy={"message":"a:b # c"}' \
    -t 'generated.*' -o stdout -p 'format=json_lines' \
    --generate-config > "$output_file" 2> "$error_file"
  result=$?

  assertEquals "configuration generation should succeed" 0 "$result"
  assertTrue "generated configuration should not write to stderr" \
    "[ ! -s '$error_file' ]"
  assertTrue "service settings should be generated" \
    "grep -Fq '\"flush\": \"2.5\"' '$output_file'"
  assertTrue "input plugin should be generated" \
    "grep -Fq '\"name\": \"dummy\"' '$output_file'"
  assertTrue "special YAML characters should be quoted" \
    "grep -Fq '\"dummy\": \"{\\\"message\\\":\\\"a:b # c\\\"}\"' '$output_file'"
  assertTrue "tag should be generated" \
    "grep -Fq '\"tag\": \"generated.*\"' '$output_file'"
  assertTrue "output property should be generated" \
    "grep -Fq '\"format\": \"json_lines\"' '$output_file'"

  "$FLB_BIN" --dry-run -c "$output_file" > "$check_file" 2>&1
  result=$?

  assertEquals "generated YAML configuration should pass validation" 0 "$result"
  assertTrue "generated YAML validation should report success" \
    "grep -Fq 'configuration test is successful' '$check_file'"

  rm -f "$output_file" "$error_file" "$check_file"
}

. "$FLB_RUNTIME_SHELL_PATH/runtime_shell.env"
