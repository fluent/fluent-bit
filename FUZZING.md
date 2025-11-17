# AFL++ Fuzzing for Fluent Bit

This directory contains Docker-based AFL++ fuzzing setup for Fluent Bit's JSON parser.

## Overview

The fuzzing setup targets `LLVMFuzzerTestOneInput` in `tests/internal/fuzzers/flb_json_fuzzer.c`, which tests:
- JSON parsing via `flb_pack_json()`
- MessagePack unpacking
- JSON serialization via `flb_msgpack_to_json_str()`
- Various JSON format conversions

## Quick Start

### Build the Fuzzing Container

```bash
docker build -f Dockerfile.fuzz -t fluent-bit-fuzz .
```

### Run the Fuzzing Campaign

```bash
docker run --rm -it \
  -v $(pwd)/fuzz-findings:/fuzz/output \
  fluent-bit-fuzz
```

This will:
1. Start AFL++ fuzzer
2. Use seed inputs from `/fuzz/input`
3. Save findings to `/fuzz/output` (mapped to `./fuzz-findings` on host)
4. Resume automatically if you restart the container

### Monitor Fuzzing Progress

The AFL++ UI will show:
- **execs/sec**: Number of executions per second
- **coverage**: Code coverage achieved
- **crashes**: Number of unique crashes found
- **hangs**: Number of timeouts detected

### Stop Fuzzing

Press `Ctrl+C` to stop the fuzzing campaign. Results will be saved in the output directory.

## Advanced Usage

### Custom AFL++ Flags

You can pass additional AFL++ flags via environment variable:

```bash
docker run --rm -it \
  -e AFL_EXTRA_FLAGS="-D -L 0" \
  -v $(pwd)/fuzz-findings:/fuzz/output \
  fluent-bit-fuzz
```

Common flags:
- `-D`: Deterministic mode (slower but more thorough)
- `-L 0`: No core affinity
- `-M main`: Start as main fuzzer (for parallel fuzzing)
- `-S secondary`: Start as secondary fuzzer (for parallel fuzzing)

### Parallel Fuzzing

Run multiple fuzzers in parallel for better coverage:

```bash
# Terminal 1 - Main fuzzer
docker run --rm -it \
  -e AFL_EXTRA_FLAGS="-M main" \
  -v $(pwd)/fuzz-findings:/fuzz/output \
  fluent-bit-fuzz

# Terminal 2 - Secondary fuzzer
docker run --rm -it \
  -e AFL_EXTRA_FLAGS="-S secondary1" \
  -v $(pwd)/fuzz-findings:/fuzz/output \
  fluent-bit-fuzz
```

### Adding Custom Seed Inputs

Mount your own seed corpus:

```bash
docker run --rm -it \
  -v $(pwd)/my-seeds:/fuzz/input:ro \
  -v $(pwd)/fuzz-findings:/fuzz/output \
  fluent-bit-fuzz
```

### Analyzing Crashes

Crashes are saved in `/fuzz/output/default/crashes/`. To reproduce a crash:

```bash
# Copy crash file from findings
cp fuzz-findings/default/crashes/id:000000* crash-sample

# Run the fuzzer binary directly with the crash input
docker run --rm -it \
  -v $(pwd)/crash-sample:/crash \
  fluent-bit-fuzz \
  /fuzz/flb-it-fuzz-flb_json_fuzzer /crash
```

## Files

- **Dockerfile.fuzz**: Multi-stage Dockerfile that builds Fluent Bit with AFL++ instrumentation
- **docker-fuzz-entrypoint.sh**: Entrypoint script that configures and starts the fuzzing campaign
- **FUZZING.md**: This documentation file

## Technical Details

### Build Configuration

The fuzzer is built with:
- `CMAKE_C_COMPILER=afl-clang-fast`: AFL++ instrumentation
- `CMAKE_CXX_COMPILER=afl-clang-fast++`: AFL++ C++ instrumentation
- `FLB_TESTS_INTERNAL_FUZZ=On`: Enable fuzzer targets
- `CMAKE_BUILD_TYPE=Debug`: Debug symbols for better crash analysis
- `FLB_JEMALLOC=Off`: Disabled to avoid conflicts with AFL++

### Fuzzer Details

The `flb_json_fuzzer` tests JSON parsing and serialization:
1. Takes raw bytes as input
2. Attempts to parse as JSON using `flb_pack_json()`
3. If successful, converts to MessagePack
4. Converts back to JSON
5. Tests various JSON format options

### AFL++ Configuration

Default AFL++ environment variables:
- `AFL_SKIP_CPUFREQ=1`: Skip CPU frequency checks
- `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`: Continue without crash detection
- `AFL_AUTORESUME=1`: Automatically resume previous sessions

## Troubleshooting

### "No instrumentation detected"

This means the binary wasn't compiled with AFL++. Rebuild the Docker image:
```bash
docker build --no-cache -f Dockerfile.fuzz -t fluent-bit-fuzz .
```

### "CPU frequency scaling"

This warning can be ignored in Docker. The `AFL_SKIP_CPUFREQ=1` flag handles it.

### Low execution speed

- Ensure Docker has sufficient CPU/RAM allocated
- Try parallel fuzzing with multiple containers
- Use faster storage for output directory (avoid network mounts)

## References

- [AFL++ Documentation](https://github.com/AFLplusplus/AFLplusplus)
- [Fluent Bit Fuzzing](https://github.com/fluent/fluent-bit/tree/master/tests/internal/fuzzers)
