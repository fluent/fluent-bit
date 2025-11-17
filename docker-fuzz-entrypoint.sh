#!/bin/bash
# Entrypoint script for AFL++ fuzzing campaign

set -e

echo "=========================================="
echo "AFL++ Fuzzing Campaign for Fluent Bit"
echo "Target: flb_json_fuzzer (LLVMFuzzerTestOneInput)"
echo "=========================================="
echo ""

# Set AFL++ environment variables
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_AUTORESUME=1

# Check if we should use persistent mode AFL++ options
# AFL++ persistent mode can significantly speed up fuzzing
export AFL_TMPDIR=/tmp/afl

# Create temp directory
mkdir -p "$AFL_TMPDIR"

# Display AFL++ version
echo "AFL++ Version:"
afl-fuzz -h | head -n 3
echo ""

# Check if output directory has existing fuzzing data
if [ -d "/fuzz/output/default" ]; then
    echo "Found existing fuzzing session, resuming..."
    RESUME_FLAG="-"
else
    echo "Starting new fuzzing session..."
    RESUME_FLAG=""
fi

# Print fuzzing configuration
echo "Configuration:"
echo "  - Input corpus: /fuzz/input"
echo "  - Output directory: /fuzz/output"
echo "  - Fuzzer binary: /fuzz/flb-it-fuzz-flb_json_fuzzer"
echo "  - Seed files: $(ls -1 /fuzz/input | wc -l)"
echo ""

# Allow user to pass additional AFL++ flags via environment variable
AFL_EXTRA_FLAGS="${AFL_EXTRA_FLAGS:-}"

echo "Starting AFL++ fuzzer..."
echo "Press Ctrl+C to stop fuzzing"
echo ""

# Note: The fuzzer binary expects a file path as argument
# AFL++ will automatically provide test cases as files when using @@ syntax
exec afl-fuzz \
    -i /fuzz/input \
    -o /fuzz/output \
    -m none \
    -t 1000+ \
    $AFL_EXTRA_FLAGS \
    $RESUME_FLAG \
    -- /fuzz/flb-it-fuzz-flb_json_fuzzer @@
