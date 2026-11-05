# Typed deployment log labels

This small runnable pack demonstrates manifest version 2: a nested target object,
an array of label objects and exact typed literal values. Users configure the
processor; authors own `blocks/enrich.lua`. The block uses the public typed-value helpers.

Set `FTS_PACKAGES_DIR` to the absolute installed `packs/fts` directory and inspect
`fluent-bit.yaml` before running it from this directory. Replace synthetic labels
and the inspection exporter with your deployment's values and destination.
The pack fills a top-level map (`labels` by default), preserving existing label
values and unrelated fields. Explicit `target.overwrite: true` replaces selected
values. It rejects duplicate/empty label names at binding. An empty label list
leaves the event unchanged. A non-map target restores the original event with
`error_mode: keep`. These are trusted operator labels, not authenticated identity.

Manifest grammar 2 requires a runtime supporting `pack_version: 2`; recipe,
author API and fixture grammar remain version 1. Older loaders reject the new
manifest before processing records. Deployment artifacts should be hash-pinned.

Four independent fixtures
cover defaults, explicit overwrite, uint64/bytes/bool types, preservation and
rollback. The backend must also preserve the chosen types; JavaScript consumers
may need IDs represented as strings. Use `fb.literal` for validated literal
configuration and preserve callback values as typed views. Never cache callback
views or store secrets in a manifest/default/fixture. JSON Schema defaults are
annotations; native binding applies them. Always run native `--dry-run` with the
actual pipeline and environment before deployment.

## Pack contract

Manifest: [pack.json](pack.json). Pack ID: `org.fluentbit.nested-labels`; implementation version: `1.0.0`.

Requires FTS author API **1**, manifest grammar **2**, and recipe grammar **1**.
Install the complete pack directory, including its Lua sources. Pin the deployment artifact by hash.

The [complete pipeline](fluent-bit.yaml) declares its input, parsers and inspection output.
Select your real source and destination before deployment.

### `enrich_logs`

Block ID: `org.fluentbit.nested-labels/enrich_logs`. Signal: **logs**.
Policy source: [blocks/enrich.lua](blocks/enrich.lua).

The example uses `error_mode: keep`. A callback failure preserves its original item and rolls back its edits.

| Parameter | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `target` | `object` | No | `{}` | Nested configuration for the destination label map. |
| `target.field` | `string` | No | `"labels"` | Top-level field holding the label map. |
| `target.overwrite` | `bool` | No | `false` | Whether selected labels replace existing label values. |
| `labels` | `array` | Yes | — | Required array of label definitions. |
| `labels[].name` | `string` | Yes | — | Unique, nonempty label name. |
| `labels[].value` | `literal` | Yes | — | Exact typed configuration literal, materialized with fb.literal. |

Add this configuration under the input that carries the stated signal:

```yaml
processors:
  logs:
  - name: fts
    recipe_version: 1
    packs:
    - logs/nested-labels/pack.json
    error_mode: keep
    recipe:
    - id: enrich
      use: org.fluentbit.nested-labels/enrich_logs
      with:
        labels:
        - name: environment
          value: staging
        - name: account_id
          value:
            type: uint64
            value: '18446744073709551615'
        - name: verified
          value: true
        - name: synthetic_bytes
          value:
            type: bytes
            value: 00ff
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
(cd packs/fts/logs/nested-labels && "$FTS_BINARY" --dry-run -c fluent-bit.yaml)
(cd packs/fts/logs/nested-labels && "$FTS_BINARY" -c fluent-bit.yaml)
```

Replay every included fixture from the repository root with the [fixture runner](../../../../tools/fts/README.md):

```sh
python3 tools/fts/fts_fixture.py --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/nested-labels/tests/*.yaml
python3 tools/fts/fts_fixture.py --valgrind --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/nested-labels/tests/*.yaml
```

Install the runner dependencies from `tools/fts/requirements.txt` into your Python environment first.

| Fixture | Case | Assertions |
| --- | --- | --- |
| [preserve.yaml](tests/preserve.yaml) | default-target-exact-types | kept=1, dropped=0, errors=0 |
| [preserve.yaml](tests/preserve.yaml) | preserve-existing-and-unrelated | kept=1, dropped=0, errors=0 |
| [preserve.yaml](tests/preserve.yaml) | wrong-target-type-rolls-back | kept=0, dropped=0, errors=1; classified error asserted |
| [overwrite.yaml](tests/overwrite.yaml) | explicit-overwrite | kept=1, dropped=0, errors=0 |

Expected output is authored independently in these fixtures. Linux runtime and Valgrind results are recorded in [verification evidence](../../verification.json). Validate your own source schema, build and pipeline before rollout.

## Instructions for agents

Keep policy decisions in Lua and reuse `fb.block` for core operations. Preserve unrelated fields, exact numeric types, signal identity and the stated failure behavior. Update the manifest, this README and independent success/control/failure fixtures together. Breaking changes require a new implementation version and an explicit migration. Never rewrite expected output to match a regression or put production credentials in a pack.

License: Apache-2.0; see the repository LICENSE file.
