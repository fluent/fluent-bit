# AGENTS

This file is the local operating guide for agents working in this repository.
It focuses on two things:

- how the Monkey source tree is organized
- how commits are written in the existing Git history

## Repository map

Monkey is a small HTTP server written in C. The tree is split by subsystem.

- `mk_core/`
  Core utilities used by the server and plugins.
  Includes memory helpers, strings, files, thread helpers, event loops,
  I/O vectors, config parsing, and generic utilities.

- `mk_server/`
  The HTTP server implementation.
  This is where connection handling, request parsing, header generation,
  virtual hosts, MIME resolution, scheduler integration, streams, plugins,
  and server lifecycle live.

- `mk_bin/`
  The standalone `monkey` executable entrypoints and signal handling.

- `include/monkey/`
  Public and internal headers for the core, server, parser, plugins,
  config, events, streams, and API types.

- `plugins/`
  Optional server features.
  Examples in this tree include `liana`, `mandril`, `dirlisting`, `cgi`,
  `fastcgi`, `auth`, `logger`, `tls`, and `cheetah`.

- `api/`
  Small API-focused programs and tests.

- `test/`
  Native unit/integration-style test targets used by CMake.

- `fuzz/`
  Fuzzing entrypoints and helpers for parser and request handling.

- `conf/`
  Config templates installed or copied at build/install time.

- `htdocs/`
  Default static site content used by the standalone server.

- `cmake/`
  CMake helper modules and build logic.

- `deps/`
  Bundled third-party dependencies such as regex, rbtree, libco,
  and mbedtls sources.

- `qa/`
  Extra request fixtures and local QA artifacts.

## Main runtime flow

When debugging behavior, the usual path is:

1. `mk_bin/monkey.c`
   Starts the binary.
2. `mk_server/monkey.c`, `mk_server/mk_server.c`
   Initializes the server and worker threads.
3. `mk_server/mk_scheduler.c`
   Drives socket events into protocol handlers.
4. `mk_server/mk_http.c`
   Owns HTTP session lifecycle, request preparation, response handling,
   range parsing, file serving, keepalive, and teardown.
5. `mk_server/mk_http_parser.c`
   Parses the request line, headers, body state, and chunked transfer coding.
6. `mk_server/mk_header.c`, `mk_server/mk_stream.c`
   Build and send responses.

Useful supporting code:

- `mk_server/mk_vhost.c`
  Virtual host lookup, per-vhost file descriptor table.
- `mk_server/mk_mimetype.c`
  File extension to MIME mapping.
- `mk_server/mk_user.c`
  `~user` URI handling.
- `mk_server/mk_plugin.c`
  Plugin registration and API exposure.
- `mk_core/mk_event_*.c`
  Backend-specific event loop implementations.

## Build and verification

Typical local build entrypoint:

```bash
cmake --build build
```

If a fresh build tree is needed, inspect `CMakeLists.txt` and the generated
`build/` layout before changing build flags. The project currently requires
CMake 3.20 and produces `build/bin/monkey`.

## Commit style used in this repository

Follow the existing Git history, not the older wording in `CONTRIBUTING.md`.

### Subject format

Use a short, lowercase, scope-prefixed subject. The common patterns are:

- `build: bump to v1.8.7`
- `server: clean thread destroy on worker loop exit`
- `server: http: move initialization of request headers to request init`
- `core: event: Plug descriptor leaks in an error case.`
- `parser: fixed header loss issue caused by duplicated headers`
- `logger: set log file permissions to 0600, closes CVE-2013-1771 (#413)`

### Prefix rules

Pick the narrowest stable prefix that matches the area being changed.

- `build:` for version bumps, CMake, workflows, packaging
- `core:` for `mk_core/` functionality
- `server:` for `mk_server/` functionality
- `server: http:` for `mk_server/mk_http.c` and closely related request flow
- `server: parser:` or `server: http_parser:` for parser-specific work
- `plugin:` or a plugin-specific prefix when the change is isolated there
- `test:` for tests
- `logger:`, `scheduler:`, `mimetype:`, `config:` when the change is clearly
  isolated to that subsystem and history already uses that style
- backend-specific prefixes like `mk_event_kqueue:` are acceptable when the
  change is narrow and entirely local to that backend

### Subject style rules

- keep it concise
- prefer lowercase after the prefix
- use colon-separated scopes, not bracket tags
- do not invent long marketing titles
- keep the subject under 80 characters
- match existing nouns already used in history where possible

Good examples for this tree:

- `server: http: reject malformed range delimiters`
- `server: http: avoid reusing invalid request state`
- `server: parser: validate chunk length tokens strictly`
- `core: memory: handle null mk_ptr_to_buf input`

Bad examples for this tree:

- `Fix CVEs`
- `Monkey: important security fixes`
- `HTTP: Add Various Improvements`
- `misc: cleanup`

## Commit body rules

The older contribution guide still applies well here.

- include a body for non-trivial changes
- wrap body lines at about 80 columns
- explain the bug, the fix, and any verification done
- if the change is security-related, describe the faulty path precisely
- if multiple root causes exist, prefer separate commits

When I am asked to commit in this repository, default behavior should be:

1. split unrelated changes into separate commits
2. choose the narrowest prefix from the existing history
3. write a short lowercase subject
4. add a body for anything beyond trivial cleanup
5. use `git commit -s` unless the user explicitly asks otherwise

## Working rules for this repository

- Do not touch unrelated untracked files in the worktree.
- Be careful around parser and request lifecycle code. Many bugs surface later
  in teardown, not at the first invalid input.
- Prefer minimal targeted fixes over broad refactors unless requested.
- When a bug crosses files, still group the commit by root cause, not by file.
- For security fixes, verify behavior on the built binary, not only by code
  inspection.
