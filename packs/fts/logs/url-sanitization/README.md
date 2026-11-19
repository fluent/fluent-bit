# Structured URL credential removal

For one declared structured HTTP(S) URL field, remove complete userinfo, query and fragment
using bounded delimiter parsing. Paths can still contain private data. This is not a general URL
validator or free-text PII scanner; invalid/ambiguous input drops transactionally.

The accepted authority profile is ASCII DNS labels, dotted IPv4, or bracketed hexadecimal IPv6, with an optional decimal port from 0 through 65535. IPv4-mapped IPv6, zone identifiers, encoded hostnames, backslashes, whitespace and ambiguous authorities are rejected. Origin-form paths must start with exactly one slash. The input limit is 8192 bytes. Paths can still carry private data; this policy removes userinfo, query and fragment only.

## Pack contract

Manifest: [pack.json](pack.json). Pack ID: `org.fluentbit.policy.url-sanitization`; implementation version: `1.0.1`.

Requires FTS author API **1**, manifest grammar **1**, and recipe grammar **1**.
Install the complete pack directory, including its Lua sources. Pin the deployment artifact by hash.

The [complete pipeline](fluent-bit.yaml) declares its input, parsers and inspection output.
Select your real source and destination before deployment.

### `apply`

Block ID: `org.fluentbit.policy.url-sanitization/apply`. Signal: **logs**.
Policy source: [blocks/apply.lua](blocks/apply.lua).

The example uses `error_mode: drop`. A callback failure drops its item and rolls back its edits.
This privacy block requires `error_mode: drop`.

| Parameter | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `field` | `string` | No | `"url"` | Top-level source field in the structured log body. |

Add this configuration under the input that carries the stated signal:

```yaml
processors:
  logs:
  - name: fts
    packs:
    - logs/url-sanitization/pack.json
    recipe_version: 1
    error_mode: drop
    recipe:
    - id: policy
      use: org.fluentbit.policy.url-sanitization/apply
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
(cd packs/fts/logs/url-sanitization && "$FTS_BINARY" --dry-run -c fluent-bit.yaml)
(cd packs/fts/logs/url-sanitization && "$FTS_BINARY" -c fluent-bit.yaml)
```

Replay every included fixture from the repository root with the [fixture runner](../../../../tools/fts/README.md):

```sh
python3 tools/fts/fts_fixture.py --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/url-sanitization/tests/*.yaml
python3 tools/fts/fts_fixture.py --valgrind --binary "$PWD/build/bin/fluent-bit" packs/fts/logs/url-sanitization/tests/*.yaml
```

Install the runner dependencies from `tools/fts/requirements.txt` into your Python environment first.

| Fixture | Case | Assertions |
| --- | --- | --- |
| [policy.yaml](tests/policy.yaml) | remove-userinfo-query-fragment | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | preserve-path-control | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | reject-ambiguous | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | origin-form-query | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | origin-form-control | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | origin-backslash | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | invalid-port | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | empty-authority | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | network-path | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | multiple-userinfo | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | encoded-host | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | ipv4-leading-dot | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | ipv4-range | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | bad-ipv6 | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | bad-dns | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | large-port | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | empty-port | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | bad-scheme | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | whitespace | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | oversized | kept=0, dropped=1, errors=1; classified error asserted |
| [policy.yaml](tests/policy.yaml) | ipv6 | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | ipv4 | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | max-bytes | kept=1, dropped=0, errors=0 |
| [policy.yaml](tests/policy.yaml) | wrong-type | kept=0, dropped=1, errors=1; classified error asserted |

Expected output is authored independently in these fixtures. Linux runtime and Valgrind results are recorded in [verification evidence](../../verification.json). Validate your own source schema, build and pipeline before rollout.

## Instructions for agents

Keep policy decisions in Lua and reuse `fb.block` for core operations. Preserve unrelated fields, exact numeric types, signal identity and the stated failure behavior. Update the manifest, this README and independent success/control/failure fixtures together. Breaking changes require a new implementation version and an explicit migration. Never rewrite expected output to match a regression or put production credentials in a pack.

License: Apache-2.0; see the repository LICENSE file.
