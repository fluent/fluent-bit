# Required fields and message budget

Require a string event_id and bound message UTF-8 bytes with an explicit truncation marker.
Other fields remain. This does not enforce total serialized event size or quarantine invalid
events.

`max_bytes` must be an integer from 0 through 1048576; it counts UTF-8 bytes and truncation preserves a valid character boundary. The core truncation block validates this requirement during binding.

## Pack contract

Manifest: [pack.json](pack.json). Pack ID: `org.fluentbit.policy.event-quality`; implementation version: `1.0.0`.

Requires FTS author API **1**, manifest grammar **1**, and recipe grammar **1**.
Install the complete pack directory, including its Lua sources. Pin the deployment artifact by hash.

The [complete pipeline](fluent-bit.yaml) declares its input, parsers and inspection output.
Select your real source and destination before deployment.

### `apply`

Block ID: `org.fluentbit.policy.event-quality/apply`. Signal: **logs**.
Policy source: [blocks/apply.lua](blocks/apply.lua).

The example uses `error_mode: drop`. A callback failure drops its item and rolls back its edits.

| Parameter | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `max_bytes` | `number` | No | `16` | Maximum UTF-8 bytes retained in message; valid range is whole numbers from 0 through 1048576. |

Add this configuration under the input that carries the stated signal:

```yaml
processors:
  logs:
  - name: fts
    packs:
    - logs/event-quality/pack.json
    recipe_version: 1
    error_mode: drop
    recipe:
    - id: policy
      use: org.fluentbit.policy.event-quality/apply
    packages_dir: ${FTS_PACKAGES_DIR}
```

## Use and verify

Set `FTS_PACKAGES_DIR` to the absolute installed directory containing these packs.
The `packs` path is relative to that directory; block source paths are relative to their manifest.
A relative `packages_dir` resolves against the process working directory.

From the repository root, try the included pipeline with the local build:

```sh
export FTS_PACKAGES_DIR="$PWD/packs/fts"
FTS_BINARY="$PWD/build/bin/fluent-bit"
(cd packs/fts/logs/event-quality && "$FTS_BINARY" --dry-run -c fluent-bit.yaml)
(cd packs/fts/logs/event-quality && "$FTS_BINARY" -c fluent-bit.yaml)
```

Replay every included fixture from the repository root with the [fixture runner](../../../../tools/fts/README.md):

```sh
python3 tools/fts/fts_fixture.py --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/event-quality/tests/*.yaml
python3 tools/fts/fts_fixture.py --valgrind --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/event-quality/tests/*.yaml
```

Install the runner dependencies from `tools/fts/requirements.txt` into your Python environment first.

| Fixture | Case | Assertions |
| --- | --- | --- |
| [policy.yaml](tests/policy.yaml) | trim-mark-explicitly | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | keep-small | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | reject-missing-id | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | utf8-boundary | kept=1, dropped=0, errors=0 |

Expected output is authored independently in these fixtures. Linux runtime and Valgrind results are recorded in [verification evidence](../../verification.json). Validate your own source schema, build and pipeline before rollout.

## Instructions for agents

Keep policy decisions in Lua and reuse `fb.block` for core operations. Preserve unrelated fields, exact numeric types, signal identity and the stated failure behavior. Update the manifest, this README and independent success/control/failure fixtures together. Breaking changes require a new implementation version and an explicit migration. Never rewrite expected output to match a regression or put production credentials in a pack.

License: Apache-2.0; see the repository LICENSE file.
