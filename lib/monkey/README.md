# Monkey HTTP Server

Monkey is a lightweight HTTP server for Linux written in C. It keeps the core
small, favors predictable resource usage, and exposes a plugin-oriented
architecture that works both as a standalone web server and as a reusable
runtime foundation for HTTP-facing components.

The repository ships the `monkey` executable, the shared runtime in
`mk_core/`, the HTTP server implementation in `mk_server/`, optional plugins,
test targets, fuzzing entrypoints, and the default configuration and site
assets used by local builds.

## Why Monkey

- Small C codebase with a focused HTTP/1.1 server implementation
- Event-driven scheduler with worker threads
- Virtual hosts, keepalive, range requests, and static file serving
- Optional plugins for TLS, CGI, FastCGI, logging, auth, shell access, and
  directory listing
- Build-time feature switches through CMake instead of a large external stack
- Suitable for direct server use or embedding-oriented integration work

## Quick Start

Requirements:

- Linux
- CMake 3.20 or newer
- A C compiler with GNU99 support
- POSIX threads

Build:

```bash
cmake -S . -B build
cmake --build build
```

Run from the source tree with the bundled configuration:

```bash
./build/bin/monkey -c conf
```

Serve a directory without editing config files:

```bash
./build/bin/monkey -o htdocs
```

The generated binary is:

```text
build/bin/monkey
```

## Build Options

Useful CMake toggles from the current build system:

- `MK_TLS=On|Off` enable or disable TLS support
- `MK_TLS_BACKEND=auto|openssl|mbedtls` choose the TLS backend
- `MK_PLUGIN_CGI=On`
- `MK_PLUGIN_FASTCGI=On`
- `MK_PLUGIN_LOGGER=On`
- `MK_PLUGIN_CHEETAH=On`
- `MK_TESTS=On` build native test targets
- `MK_HTTP2=On` enable in-development HTTP/2 code paths
- `MK_DEBUG=On` build with debug symbols

Example:

```bash
cmake -S . -B build \
  -DMK_TESTS=On \
  -DMK_PLUGIN_LOGGER=On \
  -DMK_TLS=On
cmake --build build
```

## Runtime Notes

Common command-line options:

- `-c, --configdir` set the configuration directory
- `-s, --serverconf` choose the main server config file
- `-p, --port` override the listen port
- `-w, --workers` override the worker count
- `-D, --daemon` run in the background
- `--https` enable HTTPS on configured listeners
- `-b, --build` print build information
- `-h, --help` show the full command reference

Configuration templates live under `conf/`. The default static site content for
local runs lives under `htdocs/`.

## Repository Layout

- `mk_core/` core utilities, memory, events, files, strings, and threading
- `mk_server/` HTTP server, scheduler, request lifecycle, headers, streams,
  virtual hosts, and plugin integration
- `mk_bin/` executable entrypoints and signal handling
- `include/monkey/` public and internal headers
- `plugins/` optional runtime features
- `test/` native tests used by CMake
- `fuzz/` fuzzing entrypoints and helpers
- `qa/` request fixtures and QA material
- `conf/` configuration templates
- `htdocs/` default site assets

## Development

Build test targets:

```bash
cmake -S . -B build -DMK_TESTS=On
cmake --build build
```

Additional notes:

- Fuzzing notes live in [FUZZ.md](FUZZ.md)
- Arduino YUN cross-build notes live in [ARDUINO_YUN.md](ARDUINO_YUN.md)
- Contribution rules live in [CONTRIBUTING.md](CONTRIBUTING.md)
- Local repository conventions for agents live in [AGENTS.md](AGENTS.md)

## Project Links

- Repository: https://github.com/monkey/monkey
- Issues: https://github.com/monkey/monkey/issues
- Project site: https://monkeywebserver.com
- Documentation: https://monkeywebserver.com/documentation/

## Contributing

Send changes through GitHub pull requests. Before opening one, read
[CONTRIBUTING.md](CONTRIBUTING.md) and follow the commit style already used in
the repository history: narrow scope prefixes, short lowercase subjects, and a
proper body for non-trivial changes.

## License

Monkey source files are licensed under the Apache License, Version 2.0.
