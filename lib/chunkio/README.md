# Chunk I/O

Chunk I/O is a library to manage chunks of data in the file system and load in memory upon demand. It's designed to support:

- Fixed path in the file system to organize data (root_path)
- Streams: categorize data into streams
- Multiple data files per stream
- Data file or chunks are composed by:
  - Optional CRC32 content checksum. CRC32 is stored in network-byte-order (big-endian)
  - Metadata (optional, up to 65535 bytes)
  - User data

## File System Structure

The library uses a _root path_ to store the content, where different streams can be defined to store data files called chunks, e.g:

```
root_path/
root_path/stream_1/
root_path/stream_1/chunk1
root_path/stream_1/chunk2
root_path/stream_1/chunkN
root_path/stream_N
```

It's up to the caller program how to define the names, basically it needs to set streams and associate chunks to it:

| concept   | description                                                  |
| --------- | ------------------------------------------------------------ |
| root_path | storage area, file system directory that exists or can be created |
| stream    | directory or parent group of chunks of files. The stream name is customizable, it can be anything allowed by the file system. |
| chunk     | regular file that contains the data.                         |

Creating a file system structure like the proposed one requires several checks and usage of I/O interfaces, Chunk I/O aims to abstract the internals of I/O interfaces providing helpers that behind the scenes relies on mmap(2), msync(2), munmap(2) and ftruncate(2).

### File Layout

Each chunk file created by the library have the following layout:

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

## cio - client tool

This repository provides a client tool called _cio_ for testing and managing purposes. a quick start for testing could be to stream a file over STDIN and flush it under a specific stream and chunk name, e.g:

```bash
$ cat somefile | tools/cio -i -s stdin -f somefile -vvv
```

the command above specify to gather data from the standard input (_-i_), use a stream called _stdin_ (_-s stdin_) and store the data into the chunk called _data_ (_-f data_)  and enabling some verbose messages (_-vvv_)

```bash
[chunkio] created root path /home/edsiper/.cio          => src/chunkio.c:48
[chunkio] [cio scan] opening path /home/edsiper/.cio    => src/cio_scan.c:100
[  cli  ] root_path => /home/edsiper/.cio               => tools/cio.c:340
[chunkio] created stream path /home/edsiper/.cio/stdin  => src/cio_stream.c:62
[chunkio] [cio stream] new stream registered: stdin     => src/cio_stream.c:117
[chunkio] stdin:somefile mapped OK                      => src/cio_file.c:357
[chunkio] [cio file] synced at: stdin/somefile          => src/cio_file.c:508
[  cli  ] stdin total bytes => 153 (153b)               => tools/cio.c:248
```

now that the chunk file has been generated you can list the content with the _-l_ option:

```bash
$ tools/cio -l
 stream:stdin                 1 chunks
        stdin/somefile        alloc_size=4096, data_size=4072, crc=6dd73d2e
```

### Performance Test

The _cli_ tool offers a simple performance test which can be used to measure how fast data can be processed and stored under different setups. The following options are available:

| option | value                                                  | description                                                  | default |
| ------ | ------------------------------------------------------ | ------------------------------------------------------------ | ------- |
| -p     | path to a file that will be used to perform I/O tests. | Enable performance mode setting up a file that will be used for the test. |         |
| -e     | integer value                                          | Set number of files to create.                               | 1000    |
| -w     | integer value                                          | For each file being created, this option set the number of times the content will be written to each file. | 5       |

The following example will take the data sample file provided in chunkio source code of 400KB, run the performance test creating 1000 files of 2MB each (5 writes of 400KB per file):

```
$ tools/cio -p ../tests/data/400kb.txt
=== perf write === 
-  crc32 checksum : disabled
-  fs sync mode   : normal
-  file size      : 400.0K (409600 bytes)
-  total files    : 1000
-  file writes    : 5
-  bytes written  : 1.9G (2048000000 bytes)
-  elapsed time   : 1.46 seconds
-  rate           : 1.3G per second (1398600425.33 bytes)
```

Enabling the checksum mode with the option __-k__ will calculate the CRC32 checksum of the content. This option will make it run slower but it provides an integrity check option inside each created file:

```
$ tools/cio -k -p ../tests/data/400kb.txt
=== perf write === 
-  crc32 checksum : enabled
-  fs sync mode   : normal
-  file size      : 400.0K (409600 bytes)
-  total files    : 1000
-  file writes    : 5
-  bytes written  : 1.9G (2048000000 bytes)
-  elapsed time   : 3.75 seconds
-  rate           : 520.2M per second (545507660.63 bytes)
```

By default the synchronization mode to flush the changes to the file system is __normal__ (based on MAP_ASYNC). In technical terms we let the Kernel decide when to flush the memory pages to disk based on it I/O strategy. If the program is killed or it crash while some pages have not been flushed, that file will be incomplete or corrupted. Depending of the use case, a user would prefer data safety over performance, for such scenario a synchronization mode called __full__ (based on MAP_SYNC) is available through the __-F__ option:

```
$ tools/cio -F -k -p ../tests/data/400kb.txt
=== perf write === 
-  crc32 checksum : enabled
-  fs sync mode   : full
-  file size      : 400.0K (409600 bytes)
-  total files    : 1000
-  file writes    : 5
-  bytes written  : 1.9G (2048000000 bytes)
-  elapsed time   : 24.40 seconds
-  rate           : 80.1M per second (83950015.02 bytes)
```

For most of scenarios running synchronization in __normal__ mode is good enough, but we let the user to decide it own strategy. 

## TODO

- [ ] Document C API: dev is still in progress, so constant changes are expected
- [ ] Restricted memory mapping: load in memory up to a limit, not all the content of a root_path
- [ ] Export metrics

## License

Chunk I/O is under the terms of [Apache License v2.0](LICENSE)
