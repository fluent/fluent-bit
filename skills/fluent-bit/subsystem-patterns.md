# Fluent Bit Subsystem Patterns

Use this guide as a routing map for recurring Fluent Bit tasks. Revalidate exact
code in the current checkout before relying on any pattern.

## Config Map and Proxy Plugins

Search first:

```sh
rg -n "flb_config_map_create|flb_config_map_properties_check|flb_plugin_proxy|config_map" \
  src include plugins
```

Key rule: C-side `config_map` field wiring can participate in unknown-key
validation, but it may not be end-to-end for language bindings. Check whether
the binding surface can pass a real config map and whether custom plugin
registration plumbing uses it.

## Node Exporter Metrics File Logging

Search first:

```sh
rg -n "ne_utils|thermal|throttle|ENOENT|FLB_LOG_ERROR|FLB_LOG_DEBUG" \
  plugins/in_node_exporter_metrics
```

Key rule: missing optional sysfs files can be debug-only, but real `open()` or
`read()` failures should remain errors. A durable patch shape is centralized
errno-aware helper logic, with only `ENOENT` eligible for downgrade.

## Rewrite Tag and Emitter Backlog

Search first:

```sh
rg -n "pending_bytes|mem_buf_limit|is_queue_overlimit|in_emitter|rewrite_tag" \
  plugins tests
```

Key rule: verify whether the current branch already has bounded backlog and
overlimit handling before patching. If already fixed, rerun focused coverage and
stop without editing code.

## Kubernetes Filter on Fluent Bit Internal Logs

Search first:

```sh
rg -n "Kube_Namespace_File|kube_local_fluentbit_logs|fluentbit_logs|flb_kube_meta_get_local" \
  plugins tests
```

Key rule: keep internal logs as real `in_fluentbit_logs` input. Add metadata in
the Kubernetes filter path instead of pretending the records came from tail or a
different tag source.

## Scheduler and Shutdown Regressions

Search first:

```sh
rg -n "flb_sched_destroy|mk_event_channel_destroy|processor_private_inputs_use_main_loop" \
  src include tests
rg -n "ch_events" src include tests
```

Key rule: shutdown crashes often require tracing the exact event-channel,
file-descriptor, scheduler, and processor path. Architecture-specific failures
can expose real initialization or teardown bugs.

## in_ebpf OpenSSL Path Discovery

Search first:

```sh
rg -n "trace_openssl|FLB_IN_EBPF_LIBSSL_PATH|OPENSSL_SSL_LIBRARY|OpenSSL::SSL|bpf.c.in" \
  plugins/in_ebpf
```

Key rule: the `libssl` path is baked into generated BPF source at build time.
Fix path discovery in CMake/template generation rather than hardcoding
`libssl.so.3` in source.

## Kafka Avro and Schema Registry

Search first:

```sh
rg -n "schema_registry|flb_kafka_schema_registry_resolve|FLB_HAVE_AVRO_ENCODER|Confluent" \
  plugins/out_kafka tests/integration tests/internal
```

Key rule: parser-only internal coverage is not enough for live resolver
behavior. Use `tests/integration/scenarios/out_kafka` for mock schema-registry
coverage and distinguish remote resolution from true local-cache semantics.

## Avro Encoder Range Errors

Search first:

```sh
rg -n "msgpack2avro|FLB_AVRO_RANGE_ERROR|range|avro" src tests/internal
```

Key rule: nested map conversion must preserve earlier range failures. Add
focused internal regression coverage, including cases where the bad field is not
the final field.
