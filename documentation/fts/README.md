# Fluent Bit Telemetry Scripting (FTS)

FTS processes typed logs, metrics and traces inside Fluent Bit. Operators consume
reusable blocks through YAML recipes; authors maintain the Lua policies, parameter
contracts and independent fixtures distributed in packs.

## Use a pack

Start with [install and use FTS packs](../../packs/fts/README.md). It walks through
installation, a complete runnable pipeline, expected output and preflight.
Choose a policy from the [catalog](../../packs/fts/CATALOG.md), then use its
README for source requirements, parameters and deployment examples.

The [processor reference](../../plugins/processor_fts/README.md) documents native
configuration options, typed APIs, recipe syntax, counters and error behavior.

## Write or extend a pack

- [Authoring guide](authoring.md): workflow, actual manifest/Lua/fixture examples,
  compatibility rules and explicit instructions for agents.
- [Core blocks](blocks.md): operations to reuse when composing a policy.
- [Authoring schemas](../../plugins/processor_fts/schemas/README.md): runtime-owned
  validation descriptors and exports for tools and agents.
- [Fixture runner](../../tools/fts/README.md): typed real-runtime replay and
  platform memory-checker verification.

## Understand the runtime

- [Architecture](architecture.md): composition, typed values, failure boundaries
  and versioning.
- [State and windows](state-and-windows.md): local commit, bounded ownership,
  timing, release, shutdown and supported signal semantics.
- [Design references](research.md): source-backed comparisons and design rationale.

The general [packs directory](../../packs/README.md) describes family and schema
ownership. FTS is its implemented family; it is not the owner of all future
pipeline or parser pack formats.
