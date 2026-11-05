# Fluent Bit packs

Packs distribute reusable telemetry processing content with documentation,
configuration examples and independent tests. This directory groups that content
by the capability that consumes it.

| Family | Consumer | Start here |
| --- | --- | --- |
| FTS blocks | `fts` processor | [Install and use FTS packs](fts/README.md) |

FTS packs are the implemented family today. Their manifests, Lua sources and
parameters are interpreted by `processor_fts`. Future families may distribute
pipeline configurations, parsers or other component-specific content; they need
their own supported loading and validation contracts before being advertised.

## Schema ownership

The component that consumes content owns its schema and semantic validation.
FTS block/recipe schemas belong to `processor_fts`; the
[FTS authoring model](../plugins/processor_fts/schemas/README.md) derives them from
the same descriptors used by the runtime. A future pipeline pack would belong to
the pipeline configuration subsystem and reuse the schemas of its referenced
inputs, processors and outputs.

A future common distribution envelope can describe identity, implementation
version, files, documentation and dependencies. That envelope must remain
independent of FTS and dispatch content validation by family and schema version.
There is no general pack loader or shared envelope implemented in this directory.
The current `pack_version` and `fts_api_version` fields describe FTS compatibility.

For every executable pack, include a README explaining its input contract,
parameters, output changes, failure behavior, deployment steps, fixtures and
upgrade considerations. Keep deployment-specific values outside installed pack
sources and pin deployed artifacts by content hash.
