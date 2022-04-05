# Fluent Bit / Pass Raw MessagePack data

This example implements API for passing raw MessagePack data through:
```raw_msgapck``` input plugin --> ```forward``` output plugin.



# API for Collectx
This library has simple API, consisting of 3 function:


| Component        | Description       |
| ------------     | ---------------------------------- |
| int init()                             | Initializes FluentBit instance with custom input plugin and *forward* output plugin. |                     |
| int add_data(void* data, int len)      | Main routine to pass the data. Inputs MessagePack packed raw *data*, copies it into local buffer and signals to input plugin that buffer is ready. Signaling exploits Unix socket.            |
| int finalize()        | Releases FluentBit instance and Unix socket                     |

# Build
1. build the Fluent Bit:
    - ```cd build```
    - ```cmake3 ..```
    - ```make```
2. run script "build_so_api.sh" to build the shared library "librawmsgpack.so" into "fluent-bit/build/examples/clx_raw_msgpack/" folder.

# Usage with python:

Type the following:
```
export LD_LIBRARY_PATH=path/to/fluent-bit/build/lib;$LD_LIBRARY_PATH
```

Then, use ctypes to load and call the library:
```
import ctypes
import msgpack

path_to_lib ="./examples/clx_raw_msgpack/librawmsgpack.so"
lib = ctypes.CDLL(path_to_lib)
print(lib)

# init
lib.init.restypes = ctypes.c_int
lib.init()

# prepare arg and res types for "add_data"
lib.add_data.argtypes = [ctypes.c_void_p, ctypes.c_int]
lib.add_data.restypes = ctypes.c_int

# generate and send data to Fluent Bit
for i in range(1000):
    # pack some data with MessagePack
    buf = msgpack.packb([i,[i+1,i+2]], use_bin_type=True)

    y = lib.add_data(buf, len(buf))

# clear memory
lib.hw_exit()
```