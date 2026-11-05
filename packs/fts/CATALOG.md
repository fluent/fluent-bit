# FTS pack catalog

Choose a pack by signal, then read its source contract and parameters. Start with
[install and use a pack](README.md) for a complete runnable example.

Directory groups help navigation. Each block's `signals` declaration in its
manifest is authoritative. A multisignal pack contains blocks for several
signals; each recipe still processes one signal and does not convert between them.
Block IDs are stable across directory moves. The recipe defines execution order.

## Logs

| Pack | Purpose |
| --- | --- |
| [Application JSON onboarding](logs/application-json/README.md) | Parse a JSON object from log, normalize app.level, redact structured keys and remove the raw log string. Timestamp parsing is deliberately not inferred; add logs.parse_timestamp for a declared source field/format. |
| [CloudTrail investigation normalization](logs/cloudtrail/README.md) | One already-decoded CloudTrail event per record, eventVersion major 1 with additive minor versions. Parse explicit RFC3339 eventTime, retain original security fields and read events. Does not unroll Records arrays or collect S3. Unknown major versions pass unchanged. Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html |
| [Required fields and message budget](logs/event-quality/README.md) | Require a string event_id and bound message UTF-8 bytes with an explicit truncation marker. Other fields remain. This does not enforce total serialized event size or quarantine invalid events. |
| [Parsed firewall action normalization](logs/firewall/README.md) | Small post-parser PAN-style field contract: Type and Action strings from an explicitly configured upstream parser. Normalize known allow/deny/drop without suppressing threats, denials or unknown classes. Not a universal PAN-OS CSV parser or vendor-certified integration; validate the field mapping for your version. |
| [GenAI structured content protection](logs/genai-privacy/README.md) | Redact configured structured keys in log bodies and OTLP log attributes for declared application logging profiles. Replace full message/prompt content while retaining existing usage/latency values; never fabricate token counts. Does not inspect arbitrary raw transcript strings, attachments or unknown SDK schema versions. |
| [Kubernetes metadata hygiene](logs/kubernetes-hygiene/README.md) | Consume already-enriched native Kubernetes logs. Remove labels/annotations while retaining pod/namespace/container identity and message. Does not fetch Kubernetes metadata or configure backend labels. Configure native Kubernetes enrichment before this policy. |
| [Semantic log trace correlation](logs/log-trace-correlation/README.md) | OTLP structured map log bodies only. Promote trace/span hexadecimal strings to semantic log context through the existing typed helper. No ID generation, parent rewriting or inference from arbitrary strings. Invalid IDs fail and drop. |
| [Typed deployment log labels](logs/nested-labels/README.md) | A small author Lua pack demonstrating bounded recursive configuration and exact typed labels. |
| [Tenant-scoped stable pseudonyms](logs/pseudonyms/README.md) | HMAC-SHA-256 with opaque key references and a trusted tenant/domain namespace; rotation requires a versioned deployment plan. |
| [Trusted service identity defaults](logs/service-identity/README.md) | Fill absent native-log identity fields from trusted deployment parameters. Preserve existing values, including explicit null. Does not authenticate tenants or move per-request attributes into shared resource identity. |
| [Stable keyed log sampling](logs/stable-log-sampling/README.md) | Fixed-seed XXH3 over declared stable keys; preserves configured error levels and missing-key records. |
| [Structured secret protection](logs/structured-secrets/README.md) | Recursively redact configured exact keys in structured log bodies. No free-text detection, URL parsing, resource scanning or compliance certification. Bytes and unselected fields remain typed. |
| [Successful probe reduction](logs/successful-probes/README.md) | Drop only exact configured probe paths with integer status 200 and known latency below the threshold. Preserve failures, slow requests, missing fields and near-matching paths. Units must be milliseconds. |
| [Structured URL credential removal](logs/url-sanitization/README.md) | For one declared structured HTTP(S) URL field, remove complete userinfo, query and fragment using bounded delimiter parsing. Paths can still contain private data. This is not a general URL validator or free-text PII scanner; invalid/ambiguous input drops transactionally. |
| [AWS VPC flow v2 normalization](logs/vpc-flow/README.md) | Requires explicit layout=aws-default-v2 and a producer using the default 14-field AWS v2 flow-log layout. Preserve raw records, REJECT and log status; omit dash values. Custom layouts cannot be detected from field count and must use a different pack. Malformed declared v2 records fail transactionally. |
| [Windows security authentication normalization](logs/windows-security/README.md) | Declared decoded contract: ProviderName string and EventID integer, authentication events 4624/4625 only. Preserve all unknown events and source fields. XML, classic Message strings and alternate input field names require upstream parsing/mapping. Linux fixture replay does not certify a live Windows collector. |

## Metrics

| Pack | Purpose |
| --- | --- |
| [Temporal gauge rollup](metrics/gauge-rollup/README.md) | Lua reduction over bounded, processing-time metric-family windows. OTLP input only; volatile local ownership. |
| [Metric name and unit compatibility](metrics/metric-compatibility/README.md) | Explicit latency gauge compatibility profile: milliseconds to seconds, then rename, with declared double conversion. No implicit temporality changes. Histogram migration requires a separately declared bucket profile; rename collisions fail rather than merging distinct streams. |
| [Metric dimension reduction](metrics/metric-dimensions/README.md) | Sum selected gauge datapoints across dimensions within each callback family. Resource/scope remain distinct. This is in-batch aggregation, not temporal rollup or global uniqueness enforcement. Use only additive values with compatible timestamps and source ownership. |

## Traces

| Pack | Purpose |
| --- | --- |
| [Stable span operations](traces/span-operations/README.md) | Name server spans from trusted http.route and HTTP method, preserving IDs, parent, timestamps, attributes and resource/scope. Does not infer templates from raw URLs or intentionally filter spans. Callback errors can drop spans with error_mode=drop. |

## Multisignal

| Pack | Purpose |
| --- | --- |
| [Observability basics](multisignal/observability-basics/README.md) | Local author Lua blocks for logs, metric families and spans, with real-runtime fixtures. |

## Pending capabilities

These entries have dependency descriptions, not executable manifests or consumer
recipes. They are kept outside the signal directories until implemented.

- [OCSF mapping](pending/ocsf/README.md): pinned source/class mappings and schema conformance.
- [Authenticated tenant and egress governance](pending/tenant-egress/README.md): trusted input identity and native routing/output enforcement.

The curated [policy index](catalog.json) describes eighteen executable policies
and these two dependencies. The additional example packs above demonstrate
multisignal composition, temporal gauges and recursive typed parameters.
See [authoring instructions](AUTHORING.md) and [verification evidence](verification.json).
