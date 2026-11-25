# FTS typed fixture runner

Install dependencies into a Python virtual environment:

```sh
python3 -m venv /tmp/fts-fixtures
/tmp/fts-fixtures/bin/pip install -r tools/fts/requirements.txt
/tmp/fts-fixtures/bin/python tools/fts/fts_fixture.py \
  --binary "$PWD/build/bin/fluent-bit" packs/fts/multisignal/observability-basics/tests/*.yaml
/tmp/fts-fixtures/bin/python tools/fts/fts_fixture.py \
  --valgrind --binary "$PWD/build/bin/fluent-bit" packs/fts/multisignal/observability-basics/tests/*.yaml
```

Each case starts an isolated real Fluent Bit process and local capture endpoint.
There are no policy implementations or mocked adapters in the runner. Logs use
Forward MessagePack with metadata and EventTime retained. Metrics and traces use
OTLP protobuf on input and output. Fixtures require independently authored full
expected output; unmentioned fields are not silently discarded. Graceful process
shutdown drains outputs before comparison. Failure returns a nonzero exit code.
A listener bind race before readiness is reported and retried at most twice with
new ports. Submitted telemetry and all other failures are never retried.

`fixture_version: 1` requires `signal`, an FTS `processor`, and named `cases`.
Each case has `input` and `expected`. For logs, input and `expected.records` are
arrays of `{body, metadata?, timestamp?, tag?}`. Defaults are empty metadata,
`{sec: 1700000000, nsec: 0}`, and `fts.fixture`. Forward bodies must be maps;
use `transport: otlp` with full OTLP request objects in `input` and `expected.otlp`
for OTLP logs, including resource/scope, arbitrary AnyValue bodies and correlation
IDs. The FTS log adapter still validates its supported body shapes.

OTLP logs, metrics and traces use complete OTLP JSON request objects in `input` and
`expected.otlp`, converted to protobuf for comparison. Trace/span identifiers
use hex; bytes in OTLP AnyValue use base64. Preserve resource, scope, metric
family and span boundaries. `asInt`/`intValue` are decimal strings; `asDouble`
remains a double. Account for the actual adapter contract in expected fixtures,
including explicit metric description/unit fields.

Optional `expected.outcomes` contains `kept`, `dropped`, `errors`. These count
recipe callback units: logs, metric families, or spans, not metric datapoints.
Errors count as dropped only with `error_mode: drop`. Optional `expected.error`
requires a `step` and fixed error `class` in native diagnostics. Temporal metrics require explicit family release expectations, described below.
The runner does not simulate clocks or certify a window by comparing its
immediate callback result.

YAML supports `!int64`, `!uint64`, `!double`, `!!binary`, booleans, null, arrays
and maps. Bounds are checked before execution. Positive integers compare by
exact value; MessagePack's canonical positive encoding does not preserve a
signed-positive/unsigned distinction. Integers, floats and booleans compare as
different types. Aliases, duplicate keys, arbitrary Python tags, nonfinite
numbers and oversized/deep fixtures are rejected.

Pack manifest references in fixtures resolve relative to the fixture file.
The runner writes explicit `packages_dir` and relative `packs` in the generated
runtime configuration. Packages and fixtures are trusted executable local
configuration. Do not use production endpoints or credentials in fixtures.

For agents: inspect manifest versions, block Lua, and independent expected output
before changing any of them. Do not regenerate expected output from the current
implementation to make a test pass. Run normal and strict Valgrind modes against
the same binary/source snapshot, and report both results with hashes.

Temporal metrics fixtures can use an array of complete OTLP requests in `input`.
They are sent sequentially to the real input. Set
`expected.metric_window_families: {held: 2, released: 1, reduced: 1, pending: 0}`
and include `held` in `expected.outcomes`. The runner waits for these explicitly
labelled family counters and the expected downstream family count before stopping
the process. Deadlines use the real monotonic runtime clock; this is not a
simulation. Log HOLD fixtures still need the dedicated integration suite.

Fixtures may declare an `environment` map containing only bounded public test
values under `FTS_FIXTURE_` names. These are synthetic HMAC keys, never production
credentials; arbitrary process injection variables are rejected.

The [authoring model](../../plugins/processor_fts/schemas/README.md) exports nested
manifest/recipe/block schemas from the same runtime registry, enriched with live
native `-J` options. Use `fts_schema.py --check` to detect stale generated data,
`--block ID --output PATH` for one reusable unit, or `--pack MANIFEST` to include
local author parameter declarations without executing their Lua. This is a
developer workflow; production consumption needs neither the tool nor Lua CLI.

Schema export additionally requires a Lua command-line interpreter on `PATH`.
Set `FTS_LUA=/absolute/path/to/lua` or pass `--lua` when it is installed elsewhere.
The Python requirements do not install Lua. Linux DSO integration probes require
`cc` and a configured Makefile build tree matching `FLUENT_BIT_BINARY`; set
`FTS_BUILD_DIR` explicitly when that tree cannot be inferred from the binary path.
