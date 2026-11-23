# Kubernetes metadata hygiene

Consume already-enriched native Kubernetes logs. Remove labels/annotations while retaining
pod/namespace/container identity and message. Does not fetch Kubernetes metadata or configure
backend labels. Configure native Kubernetes enrichment before this policy.

The policy independently cleans `kubernetes` and `kubernetes_namespace`, including namespace-only records. With input processors, put the native `kubernetes` filter processor earlier in that same input chain. A pipeline-level Kubernetes filter runs after input processors; in that configuration place this policy on the output instead.

## Pack contract

Manifest: [pack.json](pack.json). Pack ID: `org.fluentbit.policy.kubernetes-hygiene`; implementation version: `1.0.1`.

Requires FTS author API **1**, manifest grammar **1**, and recipe grammar **1**.
Install the complete pack directory, including its Lua sources. Pin the deployment artifact by hash.

The [complete pipeline](fluent-bit.yaml) declares its input, parsers and inspection output.
Select your real source and destination before deployment.

### `apply`

Block ID: `org.fluentbit.policy.kubernetes-hygiene/apply`. Signal: **logs**.
Policy source: [blocks/apply.lua](blocks/apply.lua).

The example uses `error_mode: drop`. A callback failure drops its item and rolls back its edits.

This profile has no configurable block parameters. Its source mapping is fixed; change and version the pack to alter that contract.

Add this configuration under the input that carries the stated signal:

```yaml
processors:
  logs:
  - name: fts
    packs:
    - logs/kubernetes-hygiene/pack.json
    recipe_version: 1
    error_mode: drop
    recipe:
    - id: policy
      use: org.fluentbit.policy.kubernetes-hygiene/apply
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
(cd packs/fts/logs/kubernetes-hygiene && "$FTS_BINARY" --dry-run -c fluent-bit.yaml)
(cd packs/fts/logs/kubernetes-hygiene && "$FTS_BINARY" -c fluent-bit.yaml)
```

Replay every included fixture from the repository root with the [fixture runner](../../../../tools/fts/README.md):

```sh
python3 tools/fts/fts_fixture.py --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/kubernetes-hygiene/tests/*.yaml
python3 tools/fts/fts_fixture.py --valgrind --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/kubernetes-hygiene/tests/*.yaml
```

Install the runner dependencies from `tools/fts/requirements.txt` into your Python environment first.

| Fixture | Case | Assertions |
| --- | --- | --- |
| [policy.yaml](tests/policy.yaml) | remove-unbounded-metadata | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | non-kubernetes-control | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | wrong-shape | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | namespace-only | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | both-metadata | kept=1, dropped=0, errors=0 |

Expected output is authored independently in these fixtures. Linux runtime and Valgrind results are recorded in [verification evidence](../../verification.json). Validate your own source schema, build and pipeline before rollout.

## Instructions for agents

Keep policy decisions in Lua and reuse `fb.block` for core operations. Preserve unrelated fields, exact numeric types, signal identity and the stated failure behavior. Update the manifest, this README and independent success/control/failure fixtures together. Breaking changes require a new implementation version and an explicit migration. Never rewrite expected output to match a regression or put production credentials in a pack.

License: Apache-2.0; see the repository LICENSE file.
