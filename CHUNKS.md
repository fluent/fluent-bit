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
|  +-------------------------+  |
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
