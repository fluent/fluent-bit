# Fluent Bit Configuration Required Field Roadmap

## Goal

Expose required/optional configuration metadata in the JSON helper output so
tools and AI agents can generate safer Fluent Bit configurations.

## Status

- [x] Config-map metadata extended with `FLB_CONFIG_MAP_REQUIRED`
- [x] JSON helper output updated with `required: true|false`
- [x] Config-map-backed global options emit `required: false`
- [x] Config-map-backed plugin sweep completed
- [x] Conditional requirements documented
- [x] Runtime helper-schema test added
- [x] Existing JSON helper schema version preserved for compatibility
- [ ] Service section metadata exposed
- [ ] Parser and multiline parser metadata exposed
- [ ] Conditional `required_when` metadata designed
- [ ] Maintainer review completed for ambiguous cases

## Required Field Semantics

`required: true` means the option must be explicitly provided by the user for
the component to initialize successfully.

`required: false` means the option is optional, has a default, can be inferred,
or is only conditionally required. Conditional requirements are tracked below
and should not be encoded as hard required values until the schema supports
condition metadata.

## Implementation Notes

The first implementation uses the existing `flags` field in
`struct flb_config_map`.

```c
#define FLB_CONFIG_MAP_REQUIRED    4
```

The JSON helper reads the flag and emits a boolean field named `required` for
every config-map entry.

The current source sweep covered 148 files with config-map arrays and 1,329
config-map entries under `plugins/`, `src/`, and `include/fluent-bit/`. It
marks 65 source entries as hard-required. Hard required fields were marked only
when the source has direct init-time validation or no safe fallback path.
Conditional and alternative requirements remain `required: false` until the
schema has condition metadata.

## Reviewed Required Fields

| Category | Component | Required fields | Source behavior |
|---|---|---|---|
| input | blob | `path` | init fails when `path` is not set |
| input | exec | `command` | init fails when no command is given |
| input | exec_wasi | `wasi_path` | init fails when no WASI command/path is given |
| input | kafka | `topics`, `brokers` | init fails when topics or brokers are missing |
| input | netif | `interface` | init fails when interface is not set |
| input | proc | `proc_name` | init fails when process name is not set |
| input | serial | `file`, `bitrate` | init fails when either value is missing |
| input | tail | `path` | init fails when no input path is given |
| input | unix_socket | `socket_path` | init has no safe default Unix socket path |
| filter | checklist | `file` | init fails when file is not set |
| filter | geoip2 | `database`, `lookup_key`, `record` | init fails without database, lookup, or output record mapping |
| filter | log_to_metrics | `metric_description`, `tag` | init fails when either value is missing |
| filter | lua | `call` | init fails when Lua function name is not set |
| filter | nest | `Operation` | init fails unless operation is `nest` or `lift` |
| filter | nightfall | `nightfall_api_key`, `policy_id` | init fails when either value is missing |
| filter | parser | `Key_Name`, `Parser` | init fails without key and at least one valid parser |
| filter | rewrite_tag | `rule` | init fails when no rule list is configured |
| filter | tensorflow | `model_file`, `input_field` | init fails when model or input field is missing |
| filter | wasm | `wasm_path`, `function_name` | init fails when program path or function is missing |
| processor | content_modifier | `action`, `key` | init fails when action or required key is missing |
| processor | sampling | `type` | init fails when sampling type is missing |
| processor | sql | `query` | init fails when no SQL query is provided |
| output | azure | `customer_id`, `shared_key` | init fails when either value is missing |
| output | azure_blob | `account_name`, `container_name` | init fails when either value is missing |
| output | azure_kusto | `ingestion_endpoint`, `database_name`, `table_name` | init fails when target is missing |
| output | azure_logs_ingestion | `client_id`, `client_secret`, `dce_url`, `dcr_id`, `table_name` | init fails when missing |
| output | bigquery | `dataset_id`, `table_id` | init fails when target dataset or table is missing |
| output | calyptia | `api_key`, `machine_id` | init fails when API key or machine ID is missing |
| output | chronicle | `customer_id`, `log_type` | init fails when either value is missing |
| output | cloudwatch_logs | `region`, `log_group_name` | init fails when either value is missing |
| output | datadog | `apikey` | init fails when API key is missing |
| output | kafka | `brokers` | shared Kafka config fails when brokers are missing |
| output | kinesis_firehose | `region`, `delivery_stream` | init fails when either value is missing |
| output | kinesis_streams | `region`, `stream` | init fails when either value is missing |
| output | logdna | `api_key` | init fails when API key is missing |
| output | oracle_log_analytics | `config_file_location` | init fails when OCI config file is missing |
| output | s3 | `bucket` | init fails when bucket is missing |
| output | slack | `webhook` | init fails when webhook is missing |
| output | td | `API`, `Database`, `Table` | init fails when credentials or target table are missing |

## Reviewed With No Unconditional Config-Map Required Fields

These components were part of the first source sweep and have no hard
`required: true` fields under the current semantics.

| Category | Components |
|---|---|
| global | input global options, filter global options, output global options, processor global options, TLS, upstream networking, downstream networking, HTTP server options, OAuth2 base maps |
| input | collectd, cpu, disk, docker, docker_events, dummy, elasticsearch, emitter, event_test, event_type, fluentbit_logs, fluentbit_metrics, forward, gpu_metrics, head, health, http, kmsg, kubernetes_events, lib, mem, mqtt, nginx_metrics, node_exporter_metrics, opentelemetry, podman_metrics, process_exporter_metrics, prometheus_remote_write, prometheus_scrape, prometheus_textfile, random, splunk, statsd, stdin, storage_backlog, stream_processor, syslog, systemd, tcp, thermal, udp, windows_exporter_metrics, winevtlog, winlog, winstat |
| filter | alter_size, aws, ecs, expect, grep, kubernetes, multiline, modify, record_modifier, stdout, sysinfo, throttle, throttle_size, type_converter |
| processor | buffered_trace, chunk_leaks, cumulative_to_delta, labels, metrics_selector, opentelemetry_envelope, tda, template |
| output | counter, es, exit, file, flowcounter, forward, gelf, http, influxdb, kafka-rest, lib, loki, nats, nrlogs, null, opensearch, opentelemetry, pgsql, plot, prometheus_exporter, prometheus_remote_write, retry, skywalking, splunk, stdout, syslog, tcp, udp, vivo_exporter, websocket |
| custom | calyptia |

## Conditional Requirements

| Component | Field | Condition | Notes |
|---|---|---|---|
| input health | `host` | always required by init, but currently exposed through synthetic network metadata | needs per-plugin synthetic option support |
| input calyptia_fleet | `host` | always required by init, but currently exposed through synthetic network metadata | needs per-plugin synthetic option support |
| input syslog | `path` | required for Unix socket modes | keep `required: false` until `required_when` exists |
| input tail | `parser_firstline` | required only for legacy multiline mode | legacy multiline path |
| input http | `oauth2.issuer`, `oauth2.jwks_url` | required when `oauth2.validate` is enabled | OAuth2 JWT map is not fully surfaced in helper output |
| input opentelemetry | `oauth2.issuer`, `oauth2.jwks_url` | required when `oauth2.validate` is enabled | OAuth2 JWT map is not fully surfaced in helper output |
| input forward | `shared_key` or `empty_shared_key` | required when `security.users` is configured | mutually exclusive/alternative requirement |
| input blob | `upload_success_suffix` | required when `upload_success_action=add_suffix` | action-specific |
| input blob | `upload_failure_suffix` | required when `upload_failure_action=add_suffix` | action-specific |
| filter lua | `script` or `code` | one is required; `script` is skipped when inline `code` is set | hard boolean cannot represent alternatives |
| filter multiline | `multiline.parser` | required when `mode=parser` | default mode is parser, but `partial_message` changes the requirement |
| filter multiline | `multiline.key_content` | required when `mode=partial_message` | conditional mode requirement |
| filter log_to_metrics | `value_field` | required for gauge and histogram modes | counter mode does not need it |
| filter type_converter | `int_key`, `uint_key`, `float_key`, or `str_key` | at least one conversion rule is required | alternative requirement |
| processor content_modifier | `value` | required for insert, upsert, and rename actions | action-specific |
| processor content_modifier | `pattern` | required for extract action | action-specific |
| processor content_modifier | `converted_type` | required for convert action | action-specific |
| processor metrics_selector | `metric_name` | required when `context` is omitted or `context=metric_name` | context-specific |
| output azure_blob | `shared_key` | required when `auth_type=key` | default auth mode is key |
| output azure_blob | `sas_token` | required when `auth_type=sas` | alternative auth mode |
| output azure_kusto | `tenant_id`, `client_id`, `client_secret` | required when `auth_type=service_principal` | default auth mode |
| output azure_kusto | `client_id` | required when `auth_type=managed_identity` | must be `system` or a client ID |
| output azure_kusto | `tenant_id`, `client_id` | required when `auth_type=workload_identity` | token file has a default |
| output azure_logs_ingestion | `tenant_id` | required unless `auth_url` overrides the token endpoint | conditional override |
| output bigquery | `google_service_credentials` or service account fields or identity federation fields | one credential mode is required | environment variables can satisfy manual service account fields |
| output bigquery | `aws_region`, `project_number`, `pool_id`, `provider_id`, `google_service_account` | required when `enable_identity_federation=true` | identity federation mode |
| output chronicle | `google_service_credentials` or service account fields | one credential mode is required | environment variables can satisfy manual fields |
| output cloudwatch_logs | `log_stream_name` or `log_stream_prefix` | exactly one is required | alternative requirement |
| output es | `id_key` or `generate_id` | required when `write_operation` is update or upsert | conditional write mode |
| output es | `aws_region` | required when `aws_auth=true` | AWS auth conditional |
| output http | `headers_key` and `body_key` | required together | pair requirement |
| output http | OAuth2 token/client fields | required when `oauth2.enable=true` | auth method changes exact fields |
| output http | `aws_service` | required when AWS auth is enabled | SigV4 conditional |
| output kafka | `raw_log_key` | required when `format=raw` | raw format extracts the payload from this key |
| output nrlogs | `api_key` or `license_key` | at least one is required | alternative requirement |
| output opensearch | `id_key` or `generate_id` | required when `write_operation` is update or upsert | conditional write mode |
| output opensearch | `aws_region` | required when `aws_auth=true` | AWS auth conditional |
| output opentelemetry | OAuth2 token/client fields | required when `oauth2.enable=true` | auth method changes exact fields |
| output oracle_log_analytics | `oci_la_log_source_name`, `oci_la_log_group_id` | required unless `oci_config_in_record=true` | record-provided config mode |
| output oracle_log_analytics | `region` | required unless output host is set | network override |
| output oracle_log_analytics | `namespace` | required unless URI is set | URI override |
| output s3 | `blob_database_file` | required to process BLOB event chunks | not required for normal logs/metrics |
| output s3 | `use_put_object` | required for some compression modes | compression-dependent |
| output splunk | `splunk_token` or `http_user` | one auth mode is required | alternative requirement |
| output stackdriver | resource labels | required for selected resource types | resource-specific |

## Ambiguous Cases

| Component | Field | Reason | Proposed action |
|---|---|---|---|
| input head | `file` | code uses the file path, but init does not emit a direct missing-property error before use | maintainer review and possible init validation |
| filter nest | `Wildcard`, `Nest_under`, `Nested_under` | operation-specific options appear semantically necessary, but init does not reject missing values | maintainer review and possible init validation |
| processor metrics_selector | `label` | `context=delete_label_value` behavior does not reject a missing label during init | confirm intended behavior |
| custom calyptia | `api_key` | custom plugin passes API key to child components, but local config-map init does not directly validate it | decide whether delegated failures should mark parent metadata |
| output stackdriver | `project_id` | required after credential and metadata discovery, but not represented as a normal config-map entry | expose or document synthetic metadata |
| service config | service keys | service/global config does not use `flb_config_map` today | design synthetic service metadata table |
| parsers | `name`, `format`, `regex` | parser config has direct validation but no config-map metadata | design parser schema section |
| multiline parsers | `name`, `type`, `rule` fields | multiline parser config has direct validation but no config-map metadata | design multiline parser schema section |

## Future Enhancements

- Add `required_when` metadata for conditional fields.
- Add alternative requirement groups, for example `one_of`.
- Add enum values for bounded string options.
- Add telemetry type compatibility for plugins and processors.
- Add stability level and deprecation metadata.
- Add examples for required options.
- Decide whether adding `required` should bump the public helper
  `schema_version`.
- Add AI hints for production safety, auth modes, and local-only defaults.
- Surface parser, multiline parser, and service/global config schemas.
