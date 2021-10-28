# Fluent Bit Collectx Output Plugin API

This shared library implements API for pushing data into Collectx event loop.
It is paired with fluent_aggr provider of the Collectx.

This allows Collectx to run collectx_out FluentBit plugin internally.

# Description
When data arrives to Fluent collectx_out plugin, it signals to Collectx to start
processing the data.
Collectx replies with 3 possible statuses:
- Done. This means that Fluent buffer can be released.
- Progressing. Fluent will not release buffer and will send another message to progress.
- Busy. Collectx is busy with progressing previous chunk. Current chunk flush will be retried later.


# API
API consists only of initialize and finilize functions.
| Component        | Description       |
| ------------     | ---------------------------------- |
| void* initialize(uint16_t port, int fluent_aggr_sock_fd, const char* collector_sock_name)                   | Initializes FluentBit instance with forward input and custom collectx_out plugin. *port* is a port for input plugin, *fluent_aggr_sock_fd* and *collector_sock_name* are Unix domain sockets for signaling. Returns void* to API context.|                     |
| int finalize(void* api_ctx)        | Releases context *api_ctx* and FluentBit instance. |

# Build
Build the Fluent Bit:
  - ```cd build```
  - ```cmake3 ..```
  - ```make```

to find "libcollectx_plugin_api.so" in "build/lib" folder
