# Use FTS packs

An FTS pack provides reusable telemetry processing blocks. An operator installs
its files and selects blocks in YAML; the pack author maintains the Lua code.
A recipe runs those blocks in order on logs, metric families or spans.

Use a Fluent Bit build with the FTS recipe and pack APIs described in the
[processor documentation](../../plugins/processor_fts/README.md).

## 1. Choose a pack

Browse the [policy catalog](CATALOG.md) for log onboarding, secret
redaction, noise reduction, metrics and trace processing. Each pack README states
its input contract, parameters, failure behavior, examples and fixtures.

Additional examples are [observability basics](multisignal/observability-basics/README.md),
[temporal gauge rollup](metrics/gauge-rollup/README.md) and
[typed deployment labels](logs/nested-labels/README.md).

Packs are organized under `logs/`, `metrics/`, `traces/` and `multisignal/`.
A pack covering multiple signals is installed once; its blocks are selected in
separate signal recipes. Pending capability descriptions live under `pending/`.

## 2. Install its files

Copy a complete pack directory from this repository or your reviewed deployment
artifact to your Fluent Bit host. For example, from the repository root:

```sh
mkdir -p /opt/fluent-bit/packs/fts/logs
cp -R packs/fts/logs/structured-secrets /opt/fluent-bit/packs/fts/logs/
```

Choose an installation directory writable by your deployment tooling and readable
by Fluent Bit. Keep `pack.json` and its `blocks/` directory together. Packs are
trusted local configuration; Fluent Bit does not download or auto-update them.
Pin the installed artifact by hash and keep operator parameters in the pipeline
configuration so replacing the pack does not overwrite them.

## 3. Configure a block

Save this complete example as `pack-demo.yaml`. The synthetic input emits one
record, and the pack replaces selected structured secret values.

```yaml
service:
  flush: 1
  grace: 1
pipeline:
  inputs:
    - name: dummy
      tag: pack.demo
      samples: 1
      dummy: '{"message":"payment accepted","password":"example-only","count":1}'
      processors:
        logs:
          - name: fts
            packages_dir: /opt/fluent-bit/packs/fts
            packs: [logs/structured-secrets/pack.json]
            recipe_version: 1
            error_mode: drop
            recipe:
              - id: protect_secrets
                use: org.fluentbit.policy.structured-secrets/apply
                with:
                  keys: [password, authorization, api_key]
                  replacement: "[REDACTED]"
  outputs:
    - name: stdout
      match: '*'
      format: json_lines
```

The output record body is:

```json
{"message":"payment accepted","password":"[REDACTED]","count":1}
```

`packages_dir` is the absolute pack installation directory. Entries in `packs`
resolve relative to that directory. `use` is the block ID from the pack's README;
`with` supplies its parameters. The step `id` is your label for diagnostics.
This privacy block requires `error_mode: drop`, so a failed callback does not
forward the unsanitized original.

## 4. Validate and run

```sh
fluent-bit --dry-run -c pack-demo.yaml
fluent-bit -c pack-demo.yaml
```

Preflight checks configuration and local pack loading before ingestion starts.
Use your real input and output in deployment, then verify their schemas and
routing with representative data. The synthetic input and stdout above are for
trying the policy. Python, the fixture runner and a Lua command-line interpreter
are developer tools; they are not required to consume a pack in Fluent Bit.

## Compose blocks

Add steps to the same `recipe` to run them in order. Multiple local manifests can
be listed in `packs`; core blocks such as `fields.edit` can be used alongside
pack blocks. Put parsing and normalization before rules that depend on their
fields, and sanitize before retaining data in state or windows.

Attach a processor under `processors.logs`, `processors.metrics` or
`processors.traces` according to the block's declared signal. A metric callback
processes a family; a trace callback processes a span. Adding a metric block to a
log recipe does not convert logs into metrics.

Stateful blocks are input-only and terminal in their recipe. They require
`state_commit: local`, bounded `state_limit` and affinity of related observations
to the same processor instance. State is volatile on restart, reload and shutdown.
Read the [state/window contract](../../documentation/fts/state-and-windows.md)
before deploying retention or deduplication.

## Update or author a pack

Verify the new artifact and its fixtures before replacing an installed version.
Semantic version metadata describes the implementation; it does not pin mutable
files. Manifest grammar, FTS API and recipe versions have separate compatibility
contracts documented in each pack.

Authors and agents can use [the authoring guide](AUTHORING.md),
[typed fixture runner](../../tools/fts/README.md) and
[shared schemas](../../plugins/processor_fts/schemas/README.md). Keep policy logic
in Lua and expected fixture output independent from the implementation.
