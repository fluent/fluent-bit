# YAML defaults, aliases and includes

Fluent Bit composes YAML includes structurally into one configuration before
interpreting runtime sections. Libyaml still parses the YAML syntax; Fluent Bit
resolves anchors, aliases and mapping merges. No library upgrade is required.

For example, `defaults.yaml` contains reusable values, not a runtime service:

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

`fluent-bit.yaml` includes them and defines one service:

```yaml
includes:
  - defaults.yaml

service:
  <<: *service_defaults
  flush: 1

pipeline:
  inputs:
    - name: dummy
      samples: 1
  outputs:
    - <<: *stdout_defaults
      format: json_lines
```

The effective service has `flush: 1`, `grace: 2` and `log_level: info`.
Two explicit `service` entries, including entries in separate files, still fail.
Includes do not implicitly merge service sections.

## Composition order

- Includes expand at their position in the root mapping, in list order. Place
  includes before aliases that refer to anchors in those files. Nested includes
  and wildcard includes use the existing path resolution and ordering rules.
  Each literal include-list item expands before the next item is parsed: anchors
  defined by an included file are available to later items in that list. An
  aliased include list retains the bindings made when that list was defined.
- Relative paths resolve against the including file's directory. Plain file
  paths fall back to the working directory. On POSIX, a relative wildcard
  searches only the including file's directory. An unmatched pattern is optional.
  An inaccessible directory is an error. Repeated-file and file-identity cycle
  checks and the 256-file include-depth limit still apply.
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
mapping merge. Its value must be a mapping or a sequence of mappings. For example:

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
