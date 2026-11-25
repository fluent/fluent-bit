# FTS design references

These references explain the product and engineering choices behind reusable
blocks, pack distribution and typed fixtures. They do not establish usage,
market share or deployment-specific cost savings.

Research: [OTel transformations](https://opentelemetry.io/docs/collector/transforming-telemetry/),
[Cribl catalog](https://packs.cribl.io/),
[Datadog reduction](https://docs.datadoghq.com/observability_pipelines/guide/strategies_for_reducing_log_volume/),
[Grafana span metrics](https://grafana.com/docs/alloy/latest/reference/components/otelcol/otelcol.connector.spanmetrics/),
[OTel privacy](https://opentelemetry.io/docs/security/handling-sensitive-data/).
These establish workflow precedents; launch priorities are product judgments.

## Documented workflow patterns

Reviewed primary sources on 2026-11-04. This is a comparison of documented
capabilities and public examples, not measured market share, adoption, or promised
cost savings. The marketplace contains community, integration and search content;
its item count is not evidence that every pack is a production-tested policy.

| Evidence | Observed pattern | Consequence for FTS |
| --- | --- | --- |
| [Cribl Packs](https://docs.cribl.io/stream/packs/) | Portable pipelines, routes, knowledge objects, parameters, versions and bundled samples | Ship complete examples with manifest, author Lua and fixtures; runtime loading stays local |
| [Cribl publication standards](https://docs.cribl.io/stream/packs-standards/) | Readable explanations, sample data and testing are distribution requirements | Independent expected output and automated failure-path replay must accompany samples |
| [Public Cribl pack repositories](https://github.com/criblpacks) | Windows, CloudTrail, network flow and firewall packs recur as source-specific products | Keep source formats/versions explicit; do not sell a generic rename as security normalization |
| [OTel Transform Processor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/transformprocessor/README.md) | Ordered transformations across logs/metrics/traces, with documented metric identity and orphaning hazards | Lego composition needs signal-specific contracts and typed fixture comparisons |
| [Datadog processors](https://docs.datadoghq.com/observability_pipelines/processors/) | Privacy, parse/edit/filter, dedupe, reduce, quota and metric cardinality controls | Prioritize recurring outcomes, including bounded state, rather than a large function catalog |
| [Datadog reduction guide](https://docs.datadoghq.com/observability_pipelines/guide/strategies_for_reducing_log_volume/) | Sampling, filtering, field removal, reduction and deduplication address different waste | Give each shipped policy an explicit retention contract; reduction percentage is deployment-specific |
| [Vector unit tests](https://vector.dev/docs/reference/configuration/unit-tests/) | Configuration transformations can be checked with inputs and output assertions | Make fixture execution available outside Studio and against the real engine |
| [Vector dedupe](https://vector.dev/docs/reference/configuration/transforms/dedupe/) and [reduce](https://vector.dev/docs/reference/configuration/transforms/reduce/) | Immediate duplicate suppression and buffered reduction are separate stateful mechanisms | Keep immediate decisions separate from HOLD/release accounting and window lifecycle |
| [Grafana tail sampling](https://grafana.com/docs/tempo/latest/set-up-for-tracing/instrument-send/set-up-collector/tail-sampling/) | Decisions need a bounded collection period and trace-affine routing | A root span is not a complete trace; trace retention must use a trace-aware facility |

Public source-specific precedents worth inspecting are
[CloudTrail](https://github.com/criblpacks/cribl-aws-cloudtrail-logs),
[Windows events](https://github.com/criblpacks/cribl-windows-events),
[VPC flows](https://github.com/criblpacks/cribl-vpc-flow-for-security-teams), and
[Palo Alto Networks](https://github.com/criblpacks/cribl-palo-alto-networks).
These establish useful onboarding categories; their existence is not a claim
that FTS already implements their parsing, enrichment, routing or security semantics.

Product judgment: lead with private-data protection and application onboarding,
then recurring noise/cardinality/identity problems, then source-specific security
content. Logs should dominate the initial catalog, with metric family preservation
and span identity preservation built into the common fixture contract. Keep
source-specific policy in Lua packages. Extend native APIs for reusable typed,
cryptographic, transactional or ownership operations only when a demonstrated gap
requires them. Dedupe/throttle are native APIs exposed to pack authors.
