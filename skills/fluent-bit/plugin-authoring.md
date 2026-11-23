# Fluent Bit Plugin Authoring

Use this guide when adding a plugin or changing a plugin's callbacks, options,
or registration. Symbol names here were read from the tree; line numbers drift,
so search by symbol.

## Read Before Writing

Open these three things for the plugin type before editing. Do not write a
callback signature, config key, or test registration from memory.

| Type | Struct and header | Small example | Runtime test |
| --- | --- | --- | --- |
| input | `struct flb_input_plugin`, `flb_input.h` | `plugins/in_dummy/` | `tests/runtime/in_dummy.c` |
| filter | `struct flb_filter_plugin`, `flb_filter.h` | `plugins/filter_grep/` | `tests/runtime/filter_grep.c` |
| output | `struct flb_output_plugin`, `flb_output.h` | `plugins/out_stdout/` | `tests/runtime/out_stdout.c` |
| processor | `struct flb_processor_plugin`, `flb_processor.h` | `plugins/processor_labels/` (metrics), `plugins/processor_content_modifier/` (logs) | `tests/runtime/processor_labels.c` |
| custom | `struct flb_custom_plugin`, `flb_custom.h` | `plugins/custom_calyptia/` | `tests/runtime_shell/custom_calyptia.sh` |

Headers live in `include/fluent-bit/`. Plugin sources include the matching
`flb_<type>_plugin.h`. `DEVELOPER_GUIDE.md` explains memory, SDS, coroutines,
and config maps, but some of its links point at old releases; trust the headers.

## Registration

A new plugin needs all of these:

1. A directory `plugins/<type>_<name>/` with a `CMakeLists.txt`:

   ```cmake
   set(src
     <name>.c)

   FLB_PLUGIN(<type>_<name> "${src}" "")
   ```

2. A build option in `cmake/plugins_options.cmake`:
   `DEFINE_OPTION(FLB_<TYPE>_<NAME> "Enable ..." ON)`.
3. A `REGISTER_IN_PLUGIN`, `REGISTER_FILTER_PLUGIN`, `REGISTER_OUT_PLUGIN`,
   `REGISTER_PROCESSOR_PLUGIN`, or `REGISTER_CUSTOM_PLUGIN` call with the
   directory name in `plugins/CMakeLists.txt`, next to its peers and inside
   the same platform or dependency guards they use.
4. An exported struct named `<directory>_plugin`, for example
   `struct flb_input_plugin in_dummy_plugin`. The register macro declares that
   exact symbol as `extern`.
5. For inputs, filters, and outputs: a `set(FLB_<TYPE>_<NAME> Yes|No)` line in
   `cmake/windows-setup.cmake`, which lists those plugins explicitly.

Rerun `cmake -S . -B build ...` after adding the directory or the test file.

## Context and Config Map

Every type follows the same shape:

- `cb_init` allocates a context with `flb_calloc` or `flb_malloc`, calls the
  config-map setter, then stores the context:

  | Type | Config-map setter | Context setter |
  | --- | --- | --- |
  | input | `flb_input_config_map_set` | `flb_input_set_context` |
  | filter | `flb_filter_config_map_set` | `flb_filter_set_context` |
  | output | `flb_output_config_map_set` | `flb_output_set_context` |
  | processor | `flb_processor_instance_config_map_set` | `flb_processor_instance_set_context` |

- `cb_exit` releases everything `cb_init` created: `flb_free` for allocations,
  `flb_sds_destroy` for SDS strings, and the matching `*_destroy` for encoders,
  decoders, and upstreams. Every early-return path in `cb_init` must release
  what it already allocated.
- Options are a `static struct flb_config_map config_map[]` terminated by
  `{0}` and assigned to `.config_map`. Each entry is:

  ```c
  {
   FLB_CONFIG_MAP_INT, "samples", "0",
   0, FLB_TRUE, offsetof(struct flb_dummy, samples),
   "set a number of times to generate event."
  },
  ```

  The fields are type, key, default (string or `NULL`), flags, whether to
  write the value into the context, the context offset, and the description.
  Types and flags (`FLB_CONFIG_MAP_MULT`, `FLB_CONFIG_MAP_DYNAMIC_ENV`) are in
  `flb_config_map.h`. Use `FLB_FALSE, 0` when the plugin reads the property
  itself, as `out_stdout` does for `format`.
- Do not parse a property by hand that is missing from the map. Keys absent
  from the map are rejected at startup with `unknown configuration property`;
  `tests/runtime_shell/dry_run_invalid_property.sh` covers that.
- Log with `flb_plg_error`, `flb_plg_warn`, `flb_plg_info`, and
  `flb_plg_debug` on the plugin instance.

## Inputs

- Typical callbacks: `cb_init`, `cb_collect`, `cb_pause`, `cb_resume`,
  `cb_exit`. The struct comments in `flb_input.h` describe the rest, including
  `cb_pre_exit` for threaded inputs.
- Register how the input wakes up in `cb_init` with
  `flb_input_set_collector_time`, `flb_input_set_collector_event`, or
  `flb_input_set_collector_socket`. Keep the returned collector id;
  `cb_pause` and `cb_resume` pass it to `flb_input_collector_pause` and
  `flb_input_collector_resume`.
- Emit logs through a `struct flb_log_event_encoder`, as `in_dummy` does:
  `flb_log_event_encoder_begin_record`, `..._set_timestamp`, set metadata and
  body, `..._commit_record`, then
  `flb_input_log_append(ins, tag, tag_len, encoder->output_buffer,
  encoder->output_length)` and `flb_log_event_encoder_reset`. A `NULL` tag
  uses the instance tag.
- Other signals have their own entry points: `flb_input_metrics_append`,
  `flb_input_trace_append`, and `flb_input_profiles_append`.
- Input flags such as `FLB_INPUT_NET`, `FLB_INPUT_NET_SERVER`, and
  `FLB_INPUT_THREADED` are defined in `flb_input.h`. Copy the flags from the
  closest existing input instead of guessing.

## Filters

- Required callbacks: `cb_init`, `cb_filter`, `cb_exit`.
- `cb_filter` returns `FLB_FILTER_NOTOUCH` to keep the input buffer or
  `FLB_FILTER_MODIFIED` after setting `*out_buf` and `*out_size`.
- Read records with `flb_log_event_decoder_init`, `..._next`, `..._destroy`.
  Write records with a `struct flb_log_event_encoder`. When returning the
  encoder buffer as `*out_buf`, call
  `flb_log_event_encoder_claim_internal_buffer_ownership` before
  `flb_log_event_encoder_destroy`, as `filter_grep` does. Destroy both on
  every return path.
- Filters do not run in an output coroutine. A filter that performs network
  I/O must make its upstream synchronous with
  `flb_stream_disable_async_mode(&upstream->base)`; see `filter_kubernetes`,
  `filter_aws`, and `filter_ecs`.

## Outputs

- Required callbacks: `cb_init`, `cb_flush`, `cb_exit`.
- `cb_flush` runs in a coroutine. End every path with
  `FLB_OUTPUT_RETURN(FLB_OK)`, `FLB_OUTPUT_RETURN(FLB_RETRY)`, or
  `FLB_OUTPUT_RETURN(FLB_ERROR)`; never use a plain `return`. Release
  per-flush allocations before the macro, because it does not come back.
- Declare accepted signals in `.event_type` with `FLB_OUTPUT_LOGS`,
  `FLB_OUTPUT_METRICS`, `FLB_OUTPUT_TRACES`, `FLB_OUTPUT_PROFILES`, and
  `FLB_OUTPUT_BLOBS`. Branch on `event_chunk->type` (`FLB_EVENT_TYPE_*`) before
  decoding; a logs decoder must not be pointed at a metrics chunk.
- Handle an empty or fully filtered chunk without crashing.
- `.workers` sets the default worker threads. Output flags such as
  `FLB_OUTPUT_NET`, `FLB_OUTPUT_NO_MULTIPLEX`, and `FLB_OUTPUT_SYNCHRONOUS` are
  defined in `flb_output.h`.

## Processors

- `cb_init` receives the owning plugin instance and its type
  (`FLB_PLUGIN_INPUT` or `FLB_PLUGIN_OUTPUT`). A processor can run in either
  context; test both when behavior differs.
- Implement only the signals the processor supports and leave the other
  `cb_process_*` members `NULL`. Return `FLB_PROCESSOR_SUCCESS` or
  `FLB_PROCESSOR_FAILURE`.
- `cb_process_logs` receives a `struct flb_mp_chunk_cobj *`. Iterate with
  `flb_mp_chunk_cobj_record_next` until it stops returning
  `FLB_MP_CHUNK_RECORD_OK`; drop a record with
  `flb_mp_chunk_cobj_record_destroy`. See
  `plugins/processor_content_modifier/cm_logs.c`.
- `cb_process_metrics` and `cb_process_traces` receive an input context and
  set an output pointer; see `processor_labels` for the metrics ownership
  rules.
- `cb_process_logs_raw`, `cb_preflight`, and `cb_input_stop` are optional
  extensions gated by `FLB_PROCESSOR_FLAG_*`. Read their contracts in
  `flb_processor.h` before using them.
- Processors are configured in YAML only, under an input or output
  `processors:` key grouped by signal. The classic format parser
  (`src/config_format/flb_cf_fluentbit.c`) has no processor section.

## Configuration Examples

Both of these parse and run with the current tree. Classic:

```text
[INPUT]
    name    dummy
    tag     demo
    samples 3

[FILTER]
    name  grep
    match demo
    regex message dummy

[OUTPUT]
    name  stdout
    match *
```

YAML, with a processor attached to the input:

```yaml
pipeline:
  inputs:
    - name: dummy
      tag: demo
      samples: 3
      processors:
        logs:
          - name: content_modifier
            action: insert
            key: source
            value: demo

  outputs:
    - name: stdout
      match: '*'
```

More fixtures: `conf/`, `tests/runtime_shell/conf/`, and
`tests/internal/data/config_format/`.

## Tests

- Runtime test: add `tests/runtime/<type>_<name>.c` and register it in
  `tests/runtime/CMakeLists.txt` with
  `FLB_RT_TEST(FLB_<TYPE>_<NAME> "<type>_<name>.c")`. The binary is
  `flb-rt-<type>_<name>`. Tests drive the library API (`flb_create`,
  `flb_input`, `flb_filter`, `flb_output`, `flb_start`, `flb_lib_push`,
  `flb_stop`, `flb_destroy`) and list cases in `TEST_LIST`.
- Internal test for helper logic: add the file to `UNIT_TESTS_FILES` in
  `tests/internal/CMakeLists.txt`. The binary is `flb-it-<file>`.
- Binary-level behavior such as startup failures: add a script and config
  under `tests/runtime_shell/` and list it in its `CMakeLists.txt`.
- Protocol or fake-server behavior: add a scenario under
  `tests/integration/scenarios/`.
- Cover the failure path too: an invalid option, an empty chunk, and the
  retry or drop result where it applies.
- Run the result as described in `verify.md` and `testing.md`.

## Before Closing

- New option: note in the close-out that user documentation lives in
  `fluent/fluent-bit-docs` and needs a matching change.
- New source files carry the Apache 2.0 header used by the neighboring files.
- Plugin code, shared `src/` changes, and tests go in separate commits; see
  `patch-workflow.md`.
