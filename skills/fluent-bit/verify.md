# Verifying a Fluent Bit Change

Use this guide to prove a change works before closing a task. A successful
compile is not proof. Run the focused tests and run the real `fluent-bit`
binary on a pipeline that exercises the change. `testing.md` covers which
test tree to pick and the integration and memory-checker requirements; this
guide covers driving the binary.

Report a step that cannot run with its exact blocker. Do not skip it silently.

## Launch

Build from the checkout root:

```sh
cmake -S . -B build -DFLB_TESTS_RUNTIME=On -DFLB_TESTS_INTERNAL=On
cmake --build build -j8
```

Create a disposable work directory outside the repository and write the
config there. Enable the HTTP server so readiness and counters are observable:

```sh
W=$(mktemp -d)
cat > "$W/pipeline.yaml" <<'EOF'
service:
  flush: 1
  log_level: info
  http_server: on
  http_listen: 127.0.0.1
  http_port: 2020

pipeline:
  inputs:
    - name: dummy
      tag: verify.dummy
      dummy: '{"message": "verify"}'
      samples: 3

  filters:
    - name: grep
      match: 'verify.*'
      regex: message verify

  outputs:
    - name: stdout
      match: '*'
EOF
```

Replace the input, filter, processor, or output with the component under
test. Keep `dummy` as the source and `stdout` as the sink when the change
allows it, so the result is visible without external services.

## Doctor

Run these before the live pipeline. Each must pass.

```sh
./build/bin/fluent-bit --version
ss -ltn | grep ':2020 ' && echo "port 2020 is taken: pick another http_port"
./build/bin/fluent-bit --dry-run -c "$W/pipeline.yaml"
```

- `--version` prints the git commit; confirm it matches `git rev-parse HEAD`
  so a stale binary is not being tested.
- `--dry-run` must print `configuration test is successful` and exit 0. A
  misspelled or unsupported key exits 1 with
  `unknown configuration property '<key>'` and the list of allowed keys.
- When a change adds or renames an option, also dry-run a config that uses a
  wrong key or value and confirm it is rejected.

## Drive

Run the focused tests for the touched component first:

```sh
ctest --test-dir build -R '^(flb-rt-in_dummy|flb-rt-filter_grep)$' \
  --output-on-failure
```

Then start the binary in the background, keep its pid, and send records to
`stdout.log` and Fluent Bit's own log to `stderr.log`:

```sh
./build/bin/fluent-bit -c "$W/pipeline.yaml" \
  > "$W/stdout.log" 2> "$W/stderr.log" &
echo $! > "$W/pid"
```

Wait for readiness with a bounded poll, not a fixed sleep:

```sh
for i in $(seq 1 50); do
    curl -s -m 1 http://127.0.0.1:2020/api/v1/uptime > /dev/null && break
    sleep 0.2
done
```

Give the pipeline enough flush intervals to emit the expected records, then
read the counters and stop the process you started:

```sh
curl -s http://127.0.0.1:2020/api/v1/metrics > "$W/metrics.json"
kill -TERM "$(cat "$W/pid")"
wait "$(cat "$W/pid")"; echo "exit=$?" > "$W/exit.txt"
```

Stop only the pid recorded in `$W/pid`. Never use `pkill fluent-bit` or
`killall`; other instances may be running on the machine.

## Evidence

A pass for the sample pipeline looks like this:

- `stdout.log` holds exactly three records shaped like
  `[0] verify.dummy: [[<timestamp>, {}], {"message"=>"verify"}]`.
- `metrics.json` reports `"records":3` for `dummy.0`, `"drop_records":0` for
  `grep.0`, and `"proc_records":3` with `"errors":0` and `"retries":0` for
  `stdout.0`.
- `stderr.log` has no `[error]` lines and contains
  `[engine] service has stopped (0 pending tasks)`.
- `exit.txt` holds `exit=0`.

For the component under test, state the expected records and counters before
running, then compare. Check a failure path as well: a rejected config, a
dropped record, or a retry, whichever the change affects.

Run the memory checker on the focused test binary. On Linux:

```sh
valgrind --leak-check=full --error-exitcode=1 ./build/bin/flb-rt-filter_grep
```

It passes when the test output ends with `SUCCESS: All unit tests have
passed.` and Valgrind prints `ERROR SUMMARY: 0 errors`. Components with a
`tests/integration` scenario also need the strict Valgrind or Leaks pass
described in `testing.md`.

## Cleanup

- Confirm the process is gone: `kill -0 "$(cat "$W/pid")"` must fail.
- Keep `$W` until the close-out is written, then remove it. Do not commit it
  or copy its logs into the repository.
- Remove any file the pipeline wrote outside `$W`, such as storage paths or
  output files configured for the test.

## Close-Out

List the commands that ran and their outcome, in the format from
`testing.md`. Include the record count and counters observed from the live
run, the memory-checker result, and any step that was blocked.
