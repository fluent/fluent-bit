# Observability basics: author-owned Lua pack

This pack contains Lua policies for logs, metric families, and spans. The native
FTS runtime loads `pack.json`, validates parameters, and binds each factory in an
immutable environment. Packages are trusted local configuration, like `script:`.
Loading performs no downloads. Production qualification still requires the
reviewed source/binary snapshot and the deployment-specific integration checks.

`packages_dir` is explicit per processor; use an absolute path for portability.
A relative packages_dir resolves against the process working directory, even
when the configuration file is elsewhere; prefer an absolute directory in
services and containers. Manifest references resolve under that directory. Module sources resolve relative
to their manifest. References cannot contain absolute paths or `..` components.
This is path validation, not a sandbox for untrusted filesystem contents or
symlinks. Package installation and ownership remain administrator responsibilities.

Block IDs use `<pack id>/<block name>` and cannot replace core block IDs. Core
and pack blocks compose in the same ordered `recipe`. `pack_version: 1` versions
the manifest grammar; `fts_api_version: 1` versions the author API;
`version: 1.0.1` versions the pack implementation. Pin deployed pack contents by
artifact hash; semantic version metadata alone does not make a mutable directory
immutable. Only numeric `major.minor.patch` versions are accepted in this revision.

The factory receives a deep private copy of validated parameters and returns one typed callback.
Factories have no filesystem/network access, `require`, `pcall`, random generator,
or user timers. Parameter maps/arrays are ordinary Lua tables, owned by that
factory; native helpers accept them directly. Changes cannot affect another block. Write policy logic in Lua; use native
operations for typed values, rollback and bounded state.

- `redact_log` recursively replaces structured secret-key values, including nested
  maps/arrays. It preserves other fields, bytes, null and exact integers. It does
  not scan free text or credentials embedded in URLs. Parse structured messages
  and remove private raw source first. `privacy: true` requires `error_mode: drop`.
- `metric_allowlist` selects complete metric families by exact name. It preserves
  all datapoints and their value types, attributes, resource and scope.
- `span_route_name` names server spans from a configured route attribute. Missing
  routes preserve names; wrong types fail transactionally. It relies on an
  upstream trusted route template; it does not turn raw URLs into templates.
- `dedupe_log` demonstrates `fb.dedupe(options)`. Call it in the factory and invoke
  the returned function per log. `fb.throttle(options)` follows the same pattern.
  These wrap the existing bounded transactional C APIs. `fb.window(options)`
  similarly wraps bounded log retention. Options match their core recipe blocks.
  One native state/window constructor is allowed per processor, in the terminal
  recipe step, on a log input, with `state_commit: local`. State is volatile,
  instance-local, and not an end-to-end delivery guarantee.

Run the independent typed fixtures using [the runner](../../../../tools/fts/README.md).
They cover nested replacement, exact integer limits, bytes, empty containers,
metric family selection, full span preservation and duplicate/control decisions.

For agents: start with the manifest and fixtures; preserve supported signal and
version contracts. Keep source mappings and policy decisions in Lua. Do not add
native processors for individual policies. Add success, no-edit control and
failure/rollback fixtures for changed behavior; verify through the real binary
normally and under strict Valgrind. Never silently rewrite expected data to match
an accidental adapter or policy change.

## Pack contract

Manifest: [pack.json](pack.json). Pack ID: `org.fluentbit.observability`; implementation version: `1.0.1`.

Requires FTS author API **1**, manifest grammar **1**, and recipe grammar **1**.
Install the complete pack directory, including its Lua sources. Pin the deployment artifact by hash.

### `redact_log`

Block ID: `org.fluentbit.observability/redact_log`. Signal: **logs**.
Policy source: [blocks/redact_log.lua](blocks/redact_log.lua).

The example uses `error_mode: drop`. A callback failure drops its item and rolls back its edits.
This privacy block requires `error_mode: drop`.

| Parameter | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `keys` | `strings` | No | `["password","authorization","api_key"]` | Structured key names to redact. |
| `replacement` | `string` | No | `"[REDACTED]"` | String written in place of selected secret values. |

Add this configuration under the input that carries the stated signal:

```yaml
processors:
  logs:
  - name: fts
    packs:
    - multisignal/observability-basics/pack.json
    recipe_version: 1
    error_mode: drop
    recipe:
    - id: privacy
      use: org.fluentbit.observability/redact_log
    packages_dir: ${FTS_PACKAGES_DIR}
```

### `metric_allowlist`

Block ID: `org.fluentbit.observability/metric_allowlist`. Signal: **metrics**.
Policy source: [blocks/metric_allowlist.lua](blocks/metric_allowlist.lua).

The example uses `error_mode: drop`. A callback failure drops its item and rolls back its edits.

| Parameter | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `names` | `strings` | Yes | — | Exact metric family names to select or reduce. |

Add this configuration under the input that carries the stated signal:

```yaml
processors:
  metrics:
  - name: fts
    packs:
    - multisignal/observability-basics/pack.json
    recipe_version: 1
    error_mode: drop
    recipe:
    - id: policy
      use: org.fluentbit.observability/metric_allowlist
      with:
        names:
        - requests
    packages_dir: ${FTS_PACKAGES_DIR}
```

### `span_route_name`

Block ID: `org.fluentbit.observability/span_route_name`. Signal: **traces**.
Policy source: [blocks/span_route_name.lua](blocks/span_route_name.lua).

The example uses `error_mode: drop`. A callback failure drops its item and rolls back its edits.

| Parameter | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `route_attribute` | `string` | No | `"http.route"` | Attribute containing the trusted route template used to name server spans. |

Add this configuration under the input that carries the stated signal:

```yaml
processors:
  traces:
  - name: fts
    packs:
    - multisignal/observability-basics/pack.json
    recipe_version: 1
    error_mode: drop
    recipe:
    - id: policy
      use: org.fluentbit.observability/span_route_name
      with: {}
    packages_dir: ${FTS_PACKAGES_DIR}
```

### `dedupe_log`

Block ID: `org.fluentbit.observability/dedupe_log`. Signal: **logs**.
Policy source: [blocks/dedupe_log.lua](blocks/dedupe_log.lua).

The example uses `error_mode: drop`. A callback failure drops its item and rolls back its edits.
Place this stateful block last in an input recipe and set `state_commit: local`.
State is local and volatile; route related observations to the same instance.

| Parameter | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `keys` | `selectors` | Yes | — | Ordered typed selectors forming the deduplication identity. |
| `ttl_ms` | `number` | Yes | — | Deduplication TTL in milliseconds, from 1 to 86400000; repeats do not extend it. |

Add this configuration under the input that carries the stated signal:

```yaml
processors:
  logs:
  - name: fts
    packs:
    - multisignal/observability-basics/pack.json
    recipe_version: 1
    error_mode: drop
    recipe:
    - id: policy
      use: org.fluentbit.observability/dedupe_log
      with:
        keys:
        - root: body
          path:
          - id
        ttl_ms: 60000
    state_commit: local
    packages_dir: ${FTS_PACKAGES_DIR}
```

## Use and verify

Set `FTS_PACKAGES_DIR` to the absolute installed directory containing these packs.
The `packs` path is relative to that directory; block source paths are relative to their manifest.
A relative `packages_dir` resolves against the process working directory.

Replay every included fixture from the repository root with the [fixture runner](../../../../tools/fts/README.md):

```sh
python3 tools/fts/fts_fixture.py --binary "$PWD/build/bin/fluent-bit" packs/fts/multisignal/observability-basics/tests/*.yaml
python3 tools/fts/fts_fixture.py --valgrind --binary "$PWD/build/bin/fluent-bit" packs/fts/multisignal/observability-basics/tests/*.yaml
```

Install the runner dependencies from `tools/fts/requirements.txt` into your Python environment first.

| Fixture | Case | Assertions |
| --- | --- | --- |
| [redact-log.yaml](tests/redact-log.yaml) | nested_keys_and_control | kept=1, dropped=0, errors=0 |
| [redact-log.yaml](tests/redact-log.yaml) | exact_types_survive | kept=1, dropped=0, errors=0 |
| [metric-allowlist.yaml](tests/metric-allowlist.yaml) | metric-allowlist | kept=1, dropped=1, errors=0 |
| [span-route-name.yaml](tests/span-route-name.yaml) | span-route-name | kept=1, dropped=0, errors=0 |
| [span-route-name.yaml](tests/span-route-name.yaml) | empty-route-preserves-name | kept=1, dropped=0, errors=0 |
| [dedupe-log.yaml](tests/dedupe-log.yaml) | dedupe-log | kept=2, dropped=1, errors=0 |
| [otlp-privacy.yaml](tests/otlp-privacy.yaml) | redact-otlp-attributes | kept=1, dropped=0, errors=0 |

Expected output is authored independently in these fixtures. Linux runtime and Valgrind results are recorded in [verification evidence](../../verification.json). Validate your own source schema, build and pipeline before rollout.

## Instructions for agents

Keep policy decisions in Lua and reuse `fb.block` for core operations. Preserve unrelated fields, exact numeric types, signal identity and the stated failure behavior. Update the manifest, this README and independent success/control/failure fixtures together. Breaking changes require a new implementation version and an explicit migration. Never rewrite expected output to match a regression or put production credentials in a pack.

License: Apache-2.0; see the repository LICENSE file.
