# GenAI structured content protection

Configured structured keys (ASCII case-insensitive) for declared application logging profiles.
Replace full message/prompt content while retaining existing usage/latency values; never
fabricate token counts. Does not inspect arbitrary raw transcript strings, attachments or
unknown SDK schema versions.

Configured keys are redacted recursively in both the structured log body and OTLP log attributes. Resource and instrumentation-scope attributes require a separate explicit redaction block. Unknown keys and free text remain outside this profile.

## Pack contract

Manifest: [pack.json](pack.json). Pack ID: `org.fluentbit.policy.genai-privacy`; implementation version: `1.0.1`.

Requires FTS author API **1**, manifest grammar **1**, and recipe grammar **1**.
Install the complete pack directory, including its Lua sources. Pin the deployment artifact by hash.

The [complete pipeline](fluent-bit.yaml) declares its input, parsers and inspection output.
Select your real source and destination before deployment.

### `apply`

Block ID: `org.fluentbit.policy.genai-privacy/apply`. Signal: **logs**.
Policy source: [blocks/apply.lua](blocks/apply.lua).

The example uses `error_mode: drop`. A callback failure drops its item and rolls back its edits.
This privacy block requires `error_mode: drop`.

| Parameter | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `keys` | `strings` | No | `["prompt","completion","content","gen_ai.prompt","gen_ai.completion","gen_ai.input.messages","gen_ai.output.messages"]` | Structured key names to redact. |

Add this configuration under the input that carries the stated signal:

```yaml
processors:
  logs:
  - name: fts
    packs:
    - logs/genai-privacy/pack.json
    recipe_version: 1
    error_mode: drop
    recipe:
    - id: policy
      use: org.fluentbit.policy.genai-privacy/apply
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
(cd packs/fts/logs/genai-privacy && "$FTS_BINARY" --dry-run -c fluent-bit.yaml)
(cd packs/fts/logs/genai-privacy && "$FTS_BINARY" -c fluent-bit.yaml)
```

Replay every included fixture from the repository root with the [fixture runner](../../../../tools/fts/README.md):

```sh
python3 tools/fts/fts_fixture.py --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/genai-privacy/tests/*.yaml
python3 tools/fts/fts_fixture.py --valgrind --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/genai-privacy/tests/*.yaml
```

Install the runner dependencies from `tools/fts/requirements.txt` into your Python environment first.

| Fixture | Case | Assertions |
| --- | --- | --- |
| [policy.yaml](tests/policy.yaml) | redact-content-preserve-usage | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | no-content-control | kept=1, dropped=0, errors=0 |
| [otlp-privacy.yaml](tests/otlp-privacy.yaml) | redact-otlp-attributes | kept=1, dropped=0, errors=0 |

Expected output is authored independently in these fixtures. Linux runtime and Valgrind results are recorded in [verification evidence](../../verification.json). Validate your own source schema, build and pipeline before rollout.

## Instructions for agents

Keep policy decisions in Lua and reuse `fb.block` for core operations. Preserve unrelated fields, exact numeric types, signal identity and the stated failure behavior. Update the manifest, this README and independent success/control/failure fixtures together. Breaking changes require a new implementation version and an explicit migration. Never rewrite expected output to match a regression or put production credentials in a pack.

License: Apache-2.0; see the repository LICENSE file.
