#!/usr/bin/env sh
set -eu

benchmark=${1:-./build/benchmarks/cmt-benchmark}
repetitions=${REPETITIONS:-5}

run_repeated()
{
    mode=$1
    cardinality=$2
    operations=$3
    iteration=1

    while [ "$iteration" -le "$repetitions" ]; do
        "$benchmark" "$mode" "$cardinality" "$operations"
        iteration=$((iteration + 1))
    done
}

run_repeated lookup 5000 100000
run_repeated update 5000 100000
run_repeated update 1 5000000
run_repeated prometheus 5000 100
run_repeated opentelemetry 5000 100
run_repeated opentelemetry-mixed 2000 100

perf stat \
    -e cycles,instructions,branches,branch-misses,cache-misses \
    -r "$repetitions" \
    "$benchmark" lookup 5000 100000

perf stat \
    -e task-clock,cycles,instructions,branches,branch-misses,cache-misses \
    -r "$repetitions" \
    "$benchmark" opentelemetry 5000 500
