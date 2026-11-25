# Tenant/domain-scoped stable pseudonyms

HMAC-SHA-256 over a versioned byte-length-prefixed domain, trusted deployment tenant and scalar
string value. Preserves unrelated fields and removes the selected original after successful
hashing. This is not free-text PII detection, email validation, or tenant authentication.
Unicode is byte-sensitive without normalization. key_ref is a public, immutable key-version
identifier; rotate with a new reference. secret_refs maps references to environment VARIABLE
NAMES, resolved and copied in C at initialization. Key bytes are never passed to Lua; the FTS-
owned copy is wiped at teardown. The process environment/core env cache still contains its own
values. Configure FTS_PSEUDONYM_KEY_V1 outside the pack before live use; never deploy the public
test fixture keys. Missing keys fail preflight. Existing raw duplicate fields must be removed
upstream.

Key deployment: use a **process environment variable injected by the orchestrator**.
Fluent Bit also resolves names from its YAML `env:` block; putting a key there
stores it as plaintext in the configuration file and is unsuitable for these
examples. `secret_refs` contains only public variable names and key-version refs.
Keys use the raw non-NUL bytes of the environment string. Hex/base64 text is used
as those literal characters; it is not decoded. No `encoding` option is supported.
Provision the intended raw key bytes through the process environment and never
copy production keys into packs, fixtures, YAML `env:`, or schema artifacts.

## Pack contract

Manifest: [pack.json](pack.json). Pack ID: `org.fluentbit.policy.pseudonyms`; implementation version: `1.0.0`.

Requires FTS author API **1**, manifest grammar **1**, and recipe grammar **1**.
Install the complete pack directory, including its Lua sources. Pin the deployment artifact by hash.

The [complete pipeline](fluent-bit.yaml) declares its input, parsers and inspection output.
Select your real source and destination before deployment.

### `apply`

Block ID: `org.fluentbit.policy.pseudonyms/apply`. Signal: **logs**.
Policy source: [blocks/apply.lua](blocks/apply.lua).

The example uses `error_mode: drop`. A callback failure drops its item and rolls back its edits.
This privacy block requires `error_mode: drop`.

| Parameter | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `field` | `string` | No | `"email"` | Top-level source field in the structured log body. |
| `destination` | `string` | No | `"email.pseudonym"` | Top-level field receiving the versioned pseudonym. |
| `key_ref` | `string` | Yes | — | Public key-version reference resolved through processor.secret_refs. |
| `tenant` | `string` | Yes | — | Trusted deployment tenant included in the identity; this parameter does not authenticate callers. |
| `domain` | `string` | No | `"email"` | Deployment-controlled namespace included in the hash/HMAC identity. |

Add this configuration under the input that carries the stated signal:

```yaml
processors:
  logs:
  - name: fts
    recipe_version: 1
    packs:
    - logs/pseudonyms/pack.json
    error_mode: drop
    recipe:
    - id: policy
      use: org.fluentbit.policy.pseudonyms/apply
      with:
        key_ref: email-v1
        tenant: tenant-a
    secret_refs:
      email-v1: FTS_PSEUDONYM_KEY_V1
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
(cd packs/fts/logs/pseudonyms && "$FTS_BINARY" --dry-run -c fluent-bit.yaml)
(cd packs/fts/logs/pseudonyms && "$FTS_BINARY" -c fluent-bit.yaml)
```

Provision the environment variables named by `secret_refs` before preflight. Use deployment secrets; the fixture runner supplies its own public synthetic keys.

Replay every included fixture from the repository root with the [fixture runner](../../../../tools/fts/README.md):

```sh
python3 tools/fts/fts_fixture.py --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/pseudonyms/tests/*.yaml
python3 tools/fts/fts_fixture.py --valgrind --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/pseudonyms/tests/*.yaml
```

Install the runner dependencies from `tools/fts/requirements.txt` into your Python environment first.

| Fixture | Case | Assertions |
| --- | --- | --- |
| [policy.yaml](tests/policy.yaml) | remove-original-and-emit-versioned-pseudonym | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | missing-value-control | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | wrong-type-drops | kept=0, dropped=1, errors=1; classified error asserted |
| [tenant-b.yaml](tests/tenant-b.yaml) | tenant-separation | kept=1, dropped=0, errors=0 |
| [rotated.yaml](tests/rotated.yaml) | key-version-rotation | kept=1, dropped=0, errors=0 |

Expected output is authored independently in these fixtures. Linux runtime and Valgrind results are recorded in [verification evidence](../../verification.json). Validate your own source schema, build and pipeline before rollout.

## Instructions for agents

Keep policy decisions in Lua and reuse `fb.block` for core operations. Preserve unrelated fields, exact numeric types, signal identity and the stated failure behavior. Update the manifest, this README and independent success/control/failure fixtures together. Breaking changes require a new implementation version and an explicit migration. Never rewrite expected output to match a regression or put production credentials in a pack.

License: Apache-2.0; see the repository LICENSE file.
