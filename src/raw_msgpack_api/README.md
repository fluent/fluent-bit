 <!-- Modified Work:

  Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.

  This software product is a proprietary product of NVIDIA CORPORATION &
  AFFILIATES (the "Company") and all right, title, and interest in and to the
  software product, including all associated intellectual property rights, are
  and shall remain exclusively with the Company.

  This software product is governed by the End User License Agreement
  provided with the software product. -->
  # Fluent Bit / Pass Raw MessagePack data

This shared library implements API for passing raw MessagePack data through:
API -> ```in_raw_msgapck``` input plugin --> output plugin.



# API for Collectx
This library has simple API, consisting of 3 function:


| Component        | Description       |
| ------------     | ---------------------------------- |
| void* init(const char* *output_plugin_name*, const char * *host*, const char * *port*, const char * *socket_prefix*)                  | Initializes FluentBit instance with custom input plugin and *output_plugin_name* output plugin. *host* and *port* are set to output plugin. *socket_prefix* is used as a prefix for Unix domain sockets. Returns void* to API context.|                     |
| int add_data(void* api_ctx, void* data, int len)      | Main routine to pass the data. Inputs pointer to API context *api_ctx* MessagePack packed raw *data*, copies it into local buffer and signals to input plugin that buffer is ready. Signaling exploits Unix socket.            |
| int finalize(void* api_ctx)        | Releases context *api_ctx*, FluentBit instance and Unix sockets                     |

# Build
Build the Fluent Bit:
  - ```cd build```
  - ```cmake3 ..```
  - ```make```

to find "libraw_msgpack_api.so" in "build/lib" folder

# Usage with python:


Then, use ctypes to load and call the library:
```
from ctypes import *
import msgpack

# load API library
path_to_lib ="fluent-bit/build/lib/libraw_msgpack_api.so"
lib = CDLL(path_to_lib)
print(lib)

# set I/O types
lib.init.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
lib.init.restype  = c_void_p

lib.add_data.argtypes = [c_void_p, c_void_p, c_int]
lib.finalize.argtypes = [c_void_p]

# init API context
api_ctx = lib.init("forward", "localhost", "24284", "")

# generate and send data to Fluent Bit
for i in range(1000):
    # pack some data with MessagePack
    buf = msgpack.packb([i,[i+1,i+2]], use_bin_type=True)

    y = lib.add_data(api_ctx, buf, len(buf))

# clear memory
lib.finalize(api_ctx)
```
