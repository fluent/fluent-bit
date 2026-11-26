# YAML defaults, aliases and includes

Fluent Bit composes YAML includes structurally into one configuration before
interpreting runtime sections. Libyaml still parses the YAML syntax; Fluent Bit
resolves anchors, aliases and mapping merges. No library upgrade is required.

In `service-defaults.yaml`, define shared service and output settings:

```yaml
defaults:
  service: &service_defaults
    flush: 5
    grace: 2
    log_level: info
  output: &stdout_defaults
    name: stdout
    match: '*'
```

In `site-defaults.yaml`, define the site settings:

```yaml
defaults:
  site: &site_defaults
    flush: 3
    log_level: warn
```

`fluent-bit.yaml` includes both files and defines one service:

```yaml
includes:
  - service-defaults.yaml
  - site-defaults.yaml

service:
  <<:
    - *site_defaults
    - *service_defaults
  flush: 1

pipeline:
  inputs:
    - name: dummy
      samples: 1
  outputs:
    - <<: *stdout_defaults
      format: json_lines
```

The main service sets `flush: 1`. The first merge source supplies
`log_level: warn`, and the second supplies `grace: 2`.
Two explicit `service` entries, including entries in separate files, still fail.
Includes do not implicitly merge service sections.

## Composition order

- Includes expand at their position in the root mapping, in list order. Place
  includes before aliases that refer to anchors in those files. Nested includes
  and wildcard includes use the existing path resolution rules. Wildcard order
  is unspecified. List files explicitly when anchor binding depends on order.
  Each literal include-list item expands before the next item is parsed: anchors
  defined by an included file are available to later items in that list. An
  aliased include list retains the bindings made when that list was defined.
- Relative paths resolve against the including file's directory. Plain file
  paths fall back to the working directory only on ENOENT or ENOTDIR. A
  permission error at the first location is reported directly. On POSIX, a relative wildcard
  searches only the including file's directory and may have no matches. An
  absolute wildcard must match on POSIX, where an inaccessible glob directory
  is also an error. Repeated-file and file-identity cycle checks and the 256-file
  include-depth limit still apply.
- Anchors must precede their aliases in this composed order. Reusing an anchor
  name is allowed: subsequent aliases bind to the new definition; earlier
  aliases keep their original target. Included files share this namespace.
- `defaults` must be a root mapping. Its contents are validated but do not create
  runtime sections. Put scalar, sequence or mapping anchors inside it. A mapping
  alias is also accepted as its value.
- `includes` and `defaults` are literal root directives, not fields introduced
  through a root alias or root merge. Include paths may reference preceding
  scalar anchors, and the include sequence itself may be an alias.

## Merge semantics

An unquoted plain `<<` key (or an explicit `!!merge` key) performs a YAML 1.1
mapping merge by default. With an explicit YAML 1.2 directive, a plain
`<<` is a string key. The explicit merge tag still requests the merge extension.
The linked libyaml determines which version directives Fluent Bit can read.
For example, libyaml 0.2.2 accepts `%YAML 1.1` and reports an incompatible
document for `%YAML 1.2`. The two-file overlay example below uses no directive
and works with either parser behavior.

A merge value must be a mapping or a sequence of mappings. For example:

```yaml
defaults:
  first: &first
    flush: 5
    grace: 2
  second: &second
    flush: 10
    log_level: info
service:
  grace: 1
  <<:
    - *first
    - *second
```

This yields `flush: 5`, `grace: 1`, `log_level: info`. Explicit receiving-map
entries override inherited entries regardless of whether they precede or follow
`<<`. Earlier mappings in a merge sequence take precedence over later ones.
Merges are shallow; nested mappings are replaced as values, not recursively
combined. Quoted `"<<"` and `!!str <<` remain ordinary string keys. Root section
names match case-insensitively. Service properties match by their
runtime names, so an explicit `log_level` overrides inherited `logLevel`. Other
mappings compare keys case-sensitively.
Scalar styles and tags are preserved for the existing section interpreter.

## Errors and limits

Unresolved/forward aliases, recursive aliases, non-scalar mapping keys and
invalid merge operands are rejected with the source file, line and column.
Unused defaults are validated too. Diagnostics for inherited values identify
the file where the value was defined.

Composition permits at most 4,096 files (including the entry file and empty
files), 65,536 source nodes, 128 levels of YAML nesting or alias expansion,
64 MiB of total input, 64 MiB of stored scalar/name/tag data, 64 MiB of emitted
scalar data,
and 1,048,576 units of composition/replay work. Work includes graph-edge appends,
anchor/key comparisons and emitted nodes. These bounds also cover acyclic alias
amplification and large merge operations. Existing scalar conversion and runtime
section validation continue to apply after resolution.

## Overlaying runtime configuration files

Put the three files below in the same directory. Start Fluent Bit with
`fluent-bit -c main.yaml`. Each line beginning with `$overlay` in the
`includes` list names a file that changes settings in the main configuration.
Fluent Bit applies those files from top to bottom. Each file only needs to list
the settings it changes and the name and alias of any input it updates.

In `main.yaml`:

```yaml
includes:
  - $overlay service-defaults.yaml
  - $overlay site-defaults.yaml

service:
  flush: 5
  telemetry:
    metrics:
      logs:
        tag_records:
          enabled: true
          max_series: 100

pipeline:
  inputs:
    - name: dummy
      alias: app
      samples: 1
      tag: app.base
  outputs:
    - name: stdout
      match: 'app.*'
```

In `service-defaults.yaml`:

```yaml
service:
  flush: 2

pipeline:
  inputs:
    - name: dummy
      alias: app
      tag: app.service
```

In `site-defaults.yaml`:

```yaml
service:
  telemetry:
    metrics:
      logs:
        tag_records:
          max_series: 20

pipeline:
  inputs:
    - name: dummy
      alias: app
      tag: app.site
```

After both overlays, the effective service and input settings are:

```yaml
service:
  flush: 2
  telemetry:
    metrics:
      logs:
        tag_records:
          enabled: true
          max_series: 20

pipeline:
  inputs:
    - name: dummy
      alias: app
      samples: 1
      tag: app.site
```

The first overlay supplies `flush`. The second sets `max_series` and the final
input tag. Both update the same `dummy` input by its Fluent Bit alias `app`.
The base supplies `enabled` and `samples`.

### Nested overlays

Save the following four files in the paths shown and run
`fluent-bit -c main.yaml` from the directory containing `main.yaml`.

**`main.yaml`**

```yaml
includes:
  - $overlay sites/site3.yaml
  - $overlay final.yaml

service:
  flush: 5
  grace: 10
  log_level: info

pipeline:
  inputs:
    - name: dummy
      alias: app
      tag: app.base
      samples: 1
      dummy: '{"source":"main"}'
  outputs:
    - name: stdout
      match: app.final
      format: json_lines
```

**`sites/site3.yaml`**

```yaml
includes:
  - $overlay site4.yaml

service:
  flush: 3
  grace: 20

pipeline:
  inputs:
    - name: dummy
      alias: app
      tag: app.site3
      dummy: '{"source":"site3"}'
```

**`sites/site4.yaml`**

```yaml
service:
  flush: 4
  log_level: debug

pipeline:
  inputs:
    - name: dummy
      alias: app
      tag: app.site4
      dummy: '{"source":"site4"}'
```

**`final.yaml`**

```yaml
service:
  flush: 2

pipeline:
  inputs:
    - name: dummy
      alias: app
      tag: app.final
```

Fluent Bit applies `main.yaml` first, then `sites/site3.yaml`. It finds
`site4.yaml` relative to `site3.yaml` and applies it before returning to the
next entry in `main.yaml`, which is `final.yaml`. The last file to supply
each setting wins.

| Setting | Effective value | File that supplies it |
| --- | --- | --- |
| Service `flush` | `2` seconds | `final.yaml` changes the value from `4` to `2`. |
| Service `grace` | `20` seconds | `site3.yaml` changes it from `10`. |
| Service `log_level` | `debug` | `site4.yaml` changes it from `info`. |
| Input `tag` | `app.final` | `final.yaml` sets the last tag. |
| Input `dummy` payload | `{"source":"site4"}` | `site4.yaml` sets the last payload. |
| Input `samples` | `1` | Only `main.yaml` sets it. |

All four files specify the same `dummy` input with alias `app`. That input
emits one record with `"source":"site4"`. Its final tag, `app.final`, matches
the `stdout` output in `main.yaml`.

### Overlay rules

- Each overlay is a single YAML document with its own anchor namespace.
  The entry file and each overlay can list both ordinary paths and overlay
  entries. Ordinary included fragments share their containing layer and can
  include other ordinary fragments. Fluent Bit
  recognizes the prefix in the parsed string, including a quoted or aliased
  string. Use `./$overlay site.yaml` for a literal filename beginning with
  `$overlay` followed by a space. Paths and wildcard patterns resolve like
  ordinary includes. Use individual paths for deterministic precedence.
  Write ordinary includes in the base configuration when you need to compose
  fragments that share anchors. Each document in an ordinary included file
  starts with the anchors that were visible when Fluent Bit opened that file.
- Reconciliation happens on the parsed Fluent Bit settings. Within each file,
  the existing YAML alias and shallow merge-key rules still apply. Two explicit
  service declarations in one configuration layer are an error.
- Service mappings merge recursively. Scalars and sequences replace the
  previous value. Changing between a mapping and another type replaces the whole
  value. Top-level service properties use Fluent Bit's runtime spelling rules.
  Keys inside nested maps are case-sensitive.
- Input aliases match exactly by their configured string before environment
  substitution. A match keeps the input in its original position and requires
  the same plugin name. Supplied input properties and groups replace their
  counterparts. An unmatched or unaliased input appends a new instance.
  With overlays enabled, each alias must be unique within each layer, including
  the base. Successive layers may update the same alias.
- On a routed input, a flat `processors` list runs in order before routing.
  Fluent Bit installs the list once for each routed signal type, so two log
  routes share one input processor chain.
- Overlay files support `service` and `pipeline.inputs`. Declare outputs,
  filters, and environment variables in the base configuration.
