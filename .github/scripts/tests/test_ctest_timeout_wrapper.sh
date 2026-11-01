#!/bin/bash

set -eu

script_dir="$(cd "$(dirname "$0")" && pwd -P)"
wrapper="$script_dir/../ctest-wrapper/ctest"
temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/flb-ctest-wrapper.XXXXXX")"

cleanup()
{
    rm -rf "$temporary_dir"
}

trap cleanup EXIT

fake_ctest="$temporary_dir/fake ctest"
arguments_file="$temporary_dir/arguments"

cat > "$fake_ctest" <<'EOF'
#!/bin/bash
printf '%s\n' "$@" > "$FLB_CTEST_ARGUMENTS_FILE"
exit "${FLB_CTEST_FAKE_EXIT_CODE:-0}"
EOF
chmod +x "$fake_ctest"

FLB_CTEST_REAL_PATH="$fake_ctest" \
FLB_CTEST_ARGUMENTS_FILE="$arguments_file" \
FLB_CTEST_DEFAULT_TIMEOUT_SECONDS=17 \
    "$wrapper" --test-dir "directory with spaces" --output-on-failure

expected_arguments="$temporary_dir/expected-arguments"
cat > "$expected_arguments" <<'EOF'
--test-dir
directory with spaces
--output-on-failure
--timeout
17
EOF
cmp "$expected_arguments" "$arguments_file"

set +e
FLB_CTEST_REAL_PATH="$fake_ctest" \
FLB_CTEST_ARGUMENTS_FILE="$arguments_file" \
FLB_CTEST_FAKE_EXIT_CODE=42 \
    "$wrapper"
wrapper_status=$?
set -e

if [ "$wrapper_status" -ne 42 ]; then
    echo "wrapper returned $wrapper_status instead of the ctest status 42" >&2
    exit 1
fi

timeout_project="$temporary_dir/default-timeout"
mkdir "$timeout_project"
cat > "$timeout_project/CTestTestfile.cmake" <<'EOF'
add_test(slow-test /bin/sleep 2)
EOF

set +e
FLB_CTEST_REAL_PATH="$(command -v ctest)" \
FLB_CTEST_DEFAULT_TIMEOUT_SECONDS=1 \
    "$wrapper" --test-dir "$timeout_project" --output-on-failure
timeout_status=$?
set -e

if [ "$timeout_status" -eq 0 ]; then
    echo "ctest unexpectedly passed a test longer than the default timeout" >&2
    exit 1
fi

property_project="$temporary_dir/explicit-timeout"
mkdir "$property_project"
cat > "$property_project/CTestTestfile.cmake" <<'EOF'
add_test(slow-test /bin/sleep 2)
set_tests_properties(slow-test PROPERTIES TIMEOUT 3)
EOF

FLB_CTEST_REAL_PATH="$(command -v ctest)" \
FLB_CTEST_DEFAULT_TIMEOUT_SECONDS=1 \
    "$wrapper" --test-dir "$property_project" --output-on-failure

set +e
FLB_CTEST_REAL_PATH="$wrapper" "$wrapper"
recursion_status=$?
set -e

if [ "$recursion_status" -ne 2 ]; then
    echo "wrapper did not reject itself as the real ctest executable" >&2
    exit 1
fi
