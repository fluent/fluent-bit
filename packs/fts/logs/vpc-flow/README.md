# AWS VPC flow v2 normalization

Requires `layout: aws-default-v2`, an explicit declaration that the producer uses the documented 14-field default v2 layout, one line in message. Preserve raw record, REJECT
and log_status. Missing dash fields are omitted instead of coerced to zero. Do not use this pack for custom layouts: their field order cannot be inferred from a version or field count. Other version values pass unchanged; malformed declared v2 records keep the original record. Reference:
https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html

## Pack contract

Manifest: [pack.json](pack.json). Pack ID: `org.fluentbit.policy.vpc-flow`; implementation version: `2.0.0`.

Requires FTS author API **1**, manifest grammar **1**, and recipe grammar **1**.
Install the complete pack directory, including its Lua sources. Pin the deployment artifact by hash.

The [complete pipeline](fluent-bit.yaml) declares its input, parsers and inspection output.
Select your real source and destination before deployment.

### `apply`

Block ID: `org.fluentbit.policy.vpc-flow/apply`. Signal: **logs**.
Policy source: [blocks/apply.lua](blocks/apply.lua).

The example uses `error_mode: keep`. A callback failure preserves its original item and rolls back its edits.

| Parameter | Type | Required | Meaning |
| --- | --- | --- | --- |
| `layout` | string | Yes | Must be `aws-default-v2`; confirm the producer configuration before enabling. |

Migration from 1.x: add this required parameter. Action must be ACCEPT/REJECT and log status OK/NODATA/SKIPDATA when present; dash values remain omitted.

Add this configuration under the input that carries the stated signal:

```yaml
processors:
  logs:
  - name: fts
    packs:
    - logs/vpc-flow/pack.json
    recipe_version: 1
    error_mode: keep
    recipe:
    - id: policy
      use: org.fluentbit.policy.vpc-flow/apply
      with: {layout: aws-default-v2}
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
(cd packs/fts/logs/vpc-flow && "$FTS_BINARY" --dry-run -c fluent-bit.yaml)
(cd packs/fts/logs/vpc-flow && "$FTS_BINARY" -c fluent-bit.yaml)
```

Replay every included fixture from the repository root with the [fixture runner](../../../../tools/fts/README.md):

```sh
python3 tools/fts/fts_fixture.py --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/vpc-flow/tests/*.yaml
python3 tools/fts/fts_fixture.py --valgrind --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/vpc-flow/tests/*.yaml
```

Install the runner dependencies from `tools/fts/requirements.txt` into your Python environment first.

| Fixture | Case | Assertions |
| --- | --- | --- |
| [policy.yaml](tests/policy.yaml) | retain-rejected-flow | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | unsupported-layout-preserved | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | preserve-skipdata-missing-values | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | invalid-action | kept=0, dropped=0, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | invalid-status | kept=0, dropped=0, errors=1; classified error asserted |

Expected output is authored independently in these fixtures. Linux runtime and Valgrind results are recorded in [verification evidence](../../verification.json). Validate your own source schema, build and pipeline before rollout.

## Instructions for agents

Keep policy decisions in Lua and reuse `fb.block` for core operations. Preserve unrelated fields, exact numeric types, signal identity and the stated failure behavior. Update the manifest, this README and independent success/control/failure fixtures together. Breaking changes require a new implementation version and an explicit migration. Never rewrite expected output to match a regression or put production credentials in a pack.

License: Apache-2.0; see the repository LICENSE file.
