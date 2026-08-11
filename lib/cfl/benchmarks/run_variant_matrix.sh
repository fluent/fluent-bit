#!/bin/sh

set -eu

build_dir=${1:-build-bench}
benchmark="$build_dir/benchmarks/cfl-benchmark-variant-mutable"
iterations=${CFL_MATRIX_ITERATIONS:-20}
records=${CFL_MATRIX_RECORDS:-100}

if [ ! -x "$benchmark" ]; then
    echo "benchmark not found: $benchmark" >&2
    exit 1
fi

echo "matrix_version=1 iterations=$iterations records=$records"

for content_size in 0 65536 2097152; do
    distributions="uniform bimodal heavy random"
    if [ "$content_size" -eq 0 ]; then
        distributions="uniform"
    fi

    for distribution in $distributions; do
        for mutation_rounds in 0 10; do
            "$benchmark" heap "$iterations" "$records" \
                "$mutation_rounds" 8192 "$content_size" 0 "$distribution"

            for chunk_size in 4096 8192 32768; do
                for threshold in 0 1024 4096 16384 1073741824; do
                    "$benchmark" arena "$iterations" "$records" \
                        "$mutation_rounds" "$chunk_size" "$content_size" \
                        "$threshold" "$distribution"
                done
            done
        done
    done
done
