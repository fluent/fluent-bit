#!/usr/bin/env bash

# Keep the unit-test driver with the sources whose tests it configures.
set -eo pipefail

SOURCE_DIR=${SOURCE_DIR:-$PWD}
SOURCE_DIR=$(cd "$SOURCE_DIR" && pwd)
platform=$(uname -s)
cpu_count=$(getconf _NPROCESSORS_ONLN)
build_jobs=${FLB_BUILD_JOBS:-$((cpu_count > 8 ? 8 : cpu_count))}

validate_jobs()
{
    if [[ ! "$1" =~ ^[1-9][0-9]*$ ]]; then
        echo "Build and test parallel levels must be positive integers: $1" >&2
        exit 1
    fi
}

validate_jobs "$build_jobs"
test_jobs=$build_jobs

# Runtime tests frequently wait for flushes, timers, and network responses.
# Keep sanitizer and macOS concurrency conservative until measured separately.
if [[ "$platform" == Linux && ! "${FLB_OPT:-}" =~ SANITIZE ]]; then
    test_jobs=$((build_jobs * 3))
fi
test_jobs=${FLB_TEST_JOBS:-$test_jobs}
validate_jobs "$test_jobs"

results="$SOURCE_DIR/build/ci-results"
mkdir -p "$results"
printf 'phase\telapsed_seconds\texit_code\n' > "$results/timings.tsv"
printf 'platform=%s\ncpus=%s\nbuild_jobs=%s\ntest_jobs=%s\n' \
    "$platform" "$cpu_count" "$build_jobs" "$test_jobs" | tee "$results/runner.txt"
printf 'cc=%s\ncxx=%s\ncmake_options=%s\n' "${CC:-}" "${CXX:-}" "${FLB_OPT:-}" \
    | tee -a "$results/runner.txt"

run_timed()
{
    local phase=$1
    local started=$SECONDS
    local status=0
    shift

    if [[ "$platform" == Linux ]]; then
        /usr/bin/time -v -o "$results/$phase.resources.txt" "$@" || status=$?
    else
        /usr/bin/time -l "$@" 2> >(tee "$results/$phase.resources.txt" >&2) || status=$?
    fi
    printf '%s\t%s\t%s\n' "$phase" "$((SECONDS - started))" "$status" \
        | tee -a "$results/timings.tsv"
    return "$status"
}

for symbolizer in /usr/bin/llvm-symbolizer-5.0 /usr/local/clang-5.0.0/bin/llvm-symbolizer \
                  /usr/bin/llvm-symbolizer-6.0 /usr/bin/llvm-symbolizer; do
    if [[ -x "$symbolizer" ]]; then
        export ASAN_SYMBOLIZER_PATH=$symbolizer
    fi
done

skip_tests=(out_elasticsearch out_td out_forward in_disk in_proc)
if [[ "$platform" == Darwin ]]; then
    skip_tests+=(filter_kubernetes)
fi
skip_options=(-DFLB_WITHOUT_flb-it-fstore=1)
for test in "${skip_tests[@]}"; do
    skip_options+=("-DFLB_WITHOUT_flb-rt-$test=1")
done
if command -v ip >/dev/null 2>&1; then
    addresses=$(ip a)
else
    addresses=$(ifconfig)
fi
if [[ ! "$addresses" =~ ::1 ]]; then
    skip_options+=(-DFLB_WITHOUT_flb-it-network=1)
fi

# These inputs are whitespace-separated CMake options, as in the previous driver.
read -r -a flb_options <<< "${FLB_OPT:-}"
read -r -a linker_options <<< "${LDFLAG:-}"
if [[ "${FLB_OPT:-}" =~ COVERAGE|SANITIZE ]]; then
    flb_options+=(-DFLB_CORO_STACK_SIZE=4194304)
fi

cd "$SOURCE_DIR/build"
run_timed configure cmake -DFLB_BACKTRACE=Off -DFLB_SHARED_LIB=Off -DFLB_DEBUG=On \
    -DFLB_ALL=On -DFLB_EXAMPLES=Off -DFLB_TESTS_INTERNAL=On -DFLB_TESTS_RUNTIME=On \
    "${linker_options[@]}" "${flb_options[@]}" "${skip_options[@]}" ..
run_timed build cmake --build . --parallel "$build_jobs"
run_timed tests ctest --parallel "$test_jobs" --output-on-failure \
    --no-tests=error --output-junit "$results/unit-tests.xml"

if [[ "${FLB_OPT:-}" =~ COVERAGE ]]; then
    mkdir -p "$SOURCE_DIR/coverage"
    find lib \( -name '*.gcda' -o -name '*.gcno' \) -print0 | xargs -0 -r rm
    run_timed coverage gcovr -e 'build/sql.l' -e 'build/sql.y' -e 'build/ra.l' \
        -e 'build/ra.y' -p -r .. .
    run_timed coverage_html gcovr -e 'build/sql.l' -e 'build/sql.y' -e 'build/ra.l' \
        -e 'build/ra.y' --html --html-details -p -r .. -o "$SOURCE_DIR/coverage/index.html" .
fi
