# Fluent Bit Chunks (internals)

When using Fluent Bit you might read about `chunks`. A Chunk is a unit of
data that groups multiple records of the same type under the same Tag.

As part of the data ingestion workflow in the pipeline, input plugins who are in
charge to collect information from different sources, encode the data as `records`
in a MessagePack buffer and associate them with a Tag (a tag is used for routing).

Internally, Fluent Bit offer two APIs to _ingest_ the records into the pipeline
depending of the message type to ingest.

- flb_input_chunk_append_raw(): logs ingestion, defined in flb_input_chunk.c
- flb_input_metrics_append(): metrics ingestion, defined in flb_input_metric.c

When invoking any of the functions mentioned above, the API will make sure to
find a pre-existing Chunk of the same type that contains the exact same Tag specified
by the caller, if no available Chunk exists, a new one is created.

For reliability and flexibility reasons, an input plugin might specify that all
Chunks associated to it will be only located in memory, others might enable
```storage.type filesystem``` so the Chunk will be located also in filesystem.

## Chunk I/O: Low level

In the low level side, all the Chunks management magic happens on a thin library called
[Chunk I/O](https://github.com/edsiper/chunkio). This library helps to provide
different backend types such as memory and filesystem, checksums and care of file system
data synchronization.

The Chunks at the file system level has it own format, but it's totally agnostic from the
content that Fluent Bit stores on it.

The following is the layout of a Chunk in the file system:

```
+--------------+----------------+
|     0xC1     |     0x00       +--> Header 2 bytes
+--------------+----------------+
|    4 BYTES CRC32 + 16 BYTES   +--> CRC32(Content) + Padding
+-------------------------------+
|            Content            |
|  +------------------------+  |
|  |         2 BYTES         +-----> Metadata Length
|  +-------------------------+  |
|  +-------------------------+  |
|  |                         |  |
|  |        Metadata         +-----> Optional Metadata (up to 65535 bytes)
|  |                         |  |
|  +-------------------------+  |
|  +-------------------------+  |
|  |                         |  |
|  |       Content Data      +-----> User Data
|  |                         |  |
|  +-------------------------+  |
+-------------------------------+
```

For Fluent Bit, the important areas of information are _Metadata_ and _Content Data_.

## Metadata and Content Data

On Fluent Bit the metadata and content handling has changed a bit, specifically from the
original version implemented as of v1.8 and the changes on the new v1.9 series:

### Fluent Bit >= v1.9

Metadata on this version introduces 4 bytes at the beginning that identifies the
format version by setting bytes 0xF1 and 0x77. The third byte called ```type```
specifies the type of records the Chunk is storing, for Logs this value is ```0x0``` and for Metrics is ```0x1```. The four byte is unused for now.

The following diagrams shows the data format:


```
                --   +---------+-------+
               /     |  0xF1   | 0x77  |  <- Magic Bytes
              /      +---------+-------+
Metadata     <       |  Type   | 0x00  |  <- Chunk type and unused byte
              \      +---------+-------+
               \     |      Tag        |  <- Tag associated to records in the content
                --   +-----------------+
               /     |  +-----------+  |
              /      |  |           |  |
Content Data <       |  |  records  |  |
              \      |  |           |  |
               \     |  +-----------+  |
                --   +-----------------+
```

Fluent Bit API provides backward compatibility with the previous metadata and content
format found on series v1.8.

Starting with the Fluent Bit release that introduces direct route persistence, the
fourth metadata byte now carries feature flags. A zero value preserves the legacy
layout, while a non-zero value indicates that additional structures follow the tag.
When the ``FLB_CHUNK_FLAG_DIRECT_ROUTES`` bit is set the tag is terminated with a
single ``\0`` byte and a routing payload is appended.  Fluent Bit v4.2 and later
also set the ``FLB_CHUNK_FLAG_DIRECT_ROUTE_LABELS`` bit to store each destination's
alias (or generated name) alongside its numeric identifier so routes can survive
configuration changes that renumber outputs.  If any stored identifier exceeds
65535 the ``FLB_CHUNK_FLAG_DIRECT_ROUTE_WIDE_IDS`` bit is enabled and each ID is
encoded using four bytes so large configurations remain routable after a restart.
When plugin names are stored, the ``FLB_CHUNK_FLAG_DIRECT_ROUTE_PLUGIN_IDS`` bit is
set to enable type-safe routing by matching plugin names:

```
                          +--------------------------+-------+
                          |         0xF1             | 0x77  |  <- Magic Bytes
                          +--------------------------+-------+
                          |         Type             | Flags |  <- Chunk type and flag bits
                          +--------------------------+--------------------------+
                          |         Tag string (no size prefix)                 |  <- Tag associated to records
                          +-----------------------------------------------------+
                          |         0x00 (Tag terminator)                       |  <- Present when flags != 0
Routing Payload Start ----+-----------------------------------------------------+
                          |         Routing Length (uint16_t big endian)        |  <- Total size of routing
                          |                                                     |     payload (excluding this
                          |                                                     |     2-byte field)
                          +-----------------------------------------------------+
                          |         Route Count (uint16_t big endian)           |  <- Number of output
                          |                                                     |     destinations stored
                          +-----------------------------------------------------+
                          |         Output IDs (route_count entries)            |  <- Each stored as uint16_t
                          |                                                     |     (big endian) or uint32_t
                          |                                                     |     when FLB_CHUNK_FLAG_
                          |                                                     |     DIRECT_ROUTE_WIDE_IDS
                          +-----------------------------------------------------+
                          |         Label Lengths (route_count entries)         |  <- Present when FLB_CHUNK_
                          |                                                     |     FLAG_DIRECT_ROUTE_LABELS
                          |                                                     |     Each uint16_t big endian
                          |                                                     |     with bit 15 encoding alias
                          |                                                     |     flag (0x8000) and bits
                          |                                                     |     0-14 the length (0x7FFF)
                          +-----------------------------------------------------+
                          |         Label Strings (concatenated, no null)       |  <- Present when FLB_CHUNK_
                          |                                                     |     FLAG_DIRECT_ROUTE_LABELS
                          |                                                     |     Variable length
                          +-----------------------------------------------------+
                          |         Plugin Name Lengths (route_count entries)   | <- Present when FLB_CHUNK_
                          |                                                     |     FLAG_DIRECT_ROUTE_PLUGIN_IDS
                          |                                                     |     Each uint16_t big endian
                          +-----------------------------------------------------+
                          |         Plugin Name Strings (concatenated, no null) |  <- Present when FLB_CHUNK_
                          |                                                     |     FLAG_DIRECT_ROUTE_PLUGIN_IDS
                          |                                                     |     Variable length
                          |                                                     |
Routing Payload End  -----+-----------------------------------------------------+
```

The routing payload captures the direct route mapping so that filesystem chunks
loaded by the storage backlog re-use the same outputs after a restart. Chunks
without direct routes keep the legacy layout (flags byte set to zero) and remain
fully backwards compatible across Fluent Bit versions. When labels are stored the
reader first reconstructs routes by matching aliases or numbered names and only
falls back to numeric identifiers if the textual metadata cannot be matched. This
ensures that chunks continue to flow to the intended destinations even when the
output configuration is re-ordered.

**Routing Payload Structure**: The routing payload begins immediately after the tag
terminator and extends for the number of bytes specified by the Routing Length
field. The Routing Length field stores the total size of all routing data (excluding
the 2-byte Routing Length field itself), including the Route Count field, all
Output IDs, Label Lengths (if present), Label Bytes (if present), Plugin Lengths
(if present), and Plugin Bytes (if present). The Route Count field indicates how
many output destinations are encoded in the routing payload. Each route entry
consists of one Output ID, optionally followed by one Label Length entry and its
corresponding Label Bytes, and optionally followed by one Plugin Length entry and
its corresponding Plugin Bytes. All routes are stored sequentially, with arrays
of lengths preceding their corresponding string data blocks.

**Labels**: Labels are textual identifiers used to match output instances when
restoring routes from chunk metadata. They provide a stable way to identify
outputs that survives configuration changes, unlike numeric IDs which can be
reassigned when outputs are reordered. Labels come in two forms: aliases and
generated names. An alias is a user-provided identifier set via the ``Alias``
configuration property, explicitly chosen by the user to identify a specific
output instance. A generated name is automatically created when no alias is
provided, following the pattern ``{plugin_name}.{sequence_number}`` (e.g.,
``stdout.0``, ``stdout.1``, ``http.0``). The system stores the alias if one
exists, otherwise falls back to the generated name. When restoring routes, the
reader first attempts to match stored labels against current output aliases,
then against current generated names, and only falls back to numeric ID matching
if no label was stored. This label-based matching ensures that chunks continue
routing to the correct outputs even when output IDs change due to configuration
reordering, making the routing resilient to configuration changes.

**Label Length Encoding**: When labels are present, each label length is stored as
a 16-bit big-endian value with the most significant bit (0x8000) encoding whether
the label represents an alias (1) or a generated name (0). The actual length is
encoded in the lower 15 bits (0x7FFF). This allows the reader to distinguish
between user-provided aliases and auto-generated names when matching routes.

**Plugin Names**: When plugin names are stored (``FLB_CHUNK_FLAG_DIRECT_ROUTE_PLUGIN_IDS``),
each route includes the plugin type name (e.g., "stdout", "http") to enable type-safe
matching. This prevents routing to outputs of different plugin types that might share
the same alias or name. Plugin name lengths are stored as 16-bit big-endian values
followed by the concatenated plugin name strings without null terminators.

### Fluent Bit <= v1.8

Up to Fluent Bit <= 1.8.x, the metadata and content data is simple, where metadata
only stores the Tag and content data the msgpack records.

```
                     +-----------------+
Metadata     <       |      Tag        |  <- Tag associated to records in the content
                --   +-----------------+
               /     |  +-----------+  |
              /      |  |           |  |
Content Data <       |  |  records  |  |
              \      |  |           |  |
               \     |  +-----------+  |
                --   +-----------------+
```
