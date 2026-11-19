# Stable keyed log sampling

XXH3-64 v1, fixed seed zero, with a versioned length-prefixed domain/tenant/string-key encoding.
The complete uint64 modulo 10000 is computed in C; only the exact small remainder is compared in
Lua. basis_points is an integer in [0,10000]. Decisions are invariant across processes/restarts
for equal configuration and key. ERROR/FATAL/CRITICAL records and missing keys are preserved.
This is log sampling, not unbiased trace retention or a privacy hash. Modulo reduction has a
bounded negligible distribution bias; no exact volume guarantee is claimed.

Error exemptions inspect the string field `body.level` for ERROR, FATAL or CRITICAL. Normalize another severity source into that field before sampling. OTLP severity numbers alone do not activate this exemption.

## Pack contract

Manifest: [pack.json](pack.json). Pack ID: `org.fluentbit.policy.stable-log-sampling`; implementation version: `1.0.0`.

Requires FTS author API **1**, manifest grammar **1**, and recipe grammar **1**.
Install the complete pack directory, including its Lua sources. Pin the deployment artifact by hash.

The [complete pipeline](fluent-bit.yaml) declares its input, parsers and inspection output.
Select your real source and destination before deployment.

### `apply`

Block ID: `org.fluentbit.policy.stable-log-sampling/apply`. Signal: **logs**.
Policy source: [blocks/apply.lua](blocks/apply.lua).

The example uses `error_mode: keep`. A callback failure preserves its original item and rolls back its edits.

| Parameter | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `field` | `string` | No | `"request_id"` | Top-level source field in the structured log body. |
| `tenant` | `string` | No | `"default"` | Trusted deployment tenant included in the identity; this parameter does not authenticate callers. |
| `domain` | `string` | No | `"logs"` | Deployment-controlled namespace included in the hash/HMAC identity. |
| `basis_points` | `number` | No | `1000` | Integer sampling threshold from 0 to 10000; 1000 means approximately 10%. |

Add this configuration under the input that carries the stated signal:

```yaml
processors:
  logs:
  - name: fts
    recipe_version: 1
    packs:
    - logs/stable-log-sampling/pack.json
    error_mode: keep
    recipe:
    - id: policy
      use: org.fluentbit.policy.stable-log-sampling/apply
      with:
        basis_points: 0
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
(cd packs/fts/logs/stable-log-sampling && "$FTS_BINARY" --dry-run -c fluent-bit.yaml)
(cd packs/fts/logs/stable-log-sampling && "$FTS_BINARY" -c fluent-bit.yaml)
```

Replay every included fixture from the repository root with the [fixture runner](../../../../tools/fts/README.md):

```sh
python3 tools/fts/fts_fixture.py --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/stable-log-sampling/tests/*.yaml
python3 tools/fts/fts_fixture.py --valgrind --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/stable-log-sampling/tests/*.yaml
```

Install the runner dependencies from `tools/fts/requirements.txt` into your Python environment first.

| Fixture | Case | Assertions |
| --- | --- | --- |
| [policy.yaml](tests/policy.yaml) | zero-budget-drops-keyed-info | kept=0, dropped=1, errors=0 |
| [policy.yaml](tests/policy.yaml) | preserve-errors | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | missing-key-control | kept=1, dropped=0, errors=0 |
| [keep-all.yaml](tests/keep-all.yaml) | full-budget-preserves-duplicates-and-control | kept=3, dropped=0, errors=0 |
| [half-budget.yaml](tests/half-budget.yaml) | half-budget-independent-xxh3-vectors | kept=4, dropped=3, errors=0 |

Expected output is authored independently in these fixtures. Linux runtime and Valgrind results are recorded in [verification evidence](../../verification.json). Validate your own source schema, build and pipeline before rollout.

## Instructions for agents

Keep policy decisions in Lua and reuse `fb.block` for core operations. Preserve unrelated fields, exact numeric types, signal identity and the stated failure behavior. Update the manifest, this README and independent success/control/failure fixtures together. Breaking changes require a new implementation version and an explicit migration. Never rewrite expected output to match a regression or put production credentials in a pack.

License: Apache-2.0; see the repository LICENSE file.
