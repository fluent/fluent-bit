WAMR Go binding: Embedding WAMR in Go guideline
===============================================

This Go library uses CGO to consume the runtime APIs of the WAMR project which are defined in [core/iwasm/include/wasm_export.h](../../core/iwasm/include/wasm_export.h). The API details are available in the header files.

## Installation

### Installing from the source code

Installing from local source tree is in _development mode_.

Run `./build.sh` in this folder to build the package, which builds the WAMR runtime library firstly and then builds the Go binding library.

Run `./build.sh` under `samples` folder to build and test the sample.

```bash
cd samples
./build.sh
```

## Supported APIs

All the embedding APIs supported are defined under folder [wamr](./wamr).

### Runtime APIs

```Go
func Runtime() *_Runtime
func (self *_Runtime) FullInit(alloc_with_pool bool, heap_buf []byte,
                               max_thread_num uint) error
func (self *_Runtime) Init() error
func (self *_Runtime) Destroy()
func (self *_Runtime) SetLogLevel(level LogLevel)
func (self *_Runtime) Malloc(size uint32) *uint8
func (self *_Runtime) Free(ptr *uint8)
```

### Module APIs

```Go
func NewModule(wasmBytes []byte) (*Module, error)
func (self *Module) Destroy()
func (self *Module) SetWasiArgs(dirList [][]byte, mapDirList [][]byte,
                                env [][]byte, argv[][]byte)
func (self *Module) SetWasiArgsEx(dirList [][]byte, mapDirList [][]byte,
                                env [][]byte, argv[][]byte,
                                stdinfd int, stdoutfd int, stderrfd int)
func (self *Module) SetWasiAddrPool(addrPool [][]byte)
```

### Instance APIs

```Go
func NewInstance(module *Module,
                 stackSize uint, heapSize uint) (*Instance, error)
func (self *Instance) Destroy()
func (self *Instance) CallFunc(funcName string,
                               argc uint32, args []uint32) error
func (self *Instance) CallFuncV(funcName string,
                                num_results uint32, results []interface{},
                                args ... interface{}) error
func (self *Instance) GetException() string
func (self Instance) ModuleMalloc(size uint32) (uint32, *uint8)
func (self Instance) ModuleFree(offset uint32)
func (self Instance) ValidateAppAddr(app_offset uint32, size uint32) bool
func (self Instance) ValidateNativeAddr(native_ptr *uint8, size uint32) bool
func (self Instance) AddrAppToNative(app_offset uint32) *uint8
func (self Instance) AddrNativeToApp(native_ptr *uint8) uint32
func (self Instance) GetAppAddrRange(app_offset uint32) (bool, uint32, uint32)
func (self Instance) GetNativeAddrRange(native_ptr *uint8) (bool, *uint8, *uint8)
func (self Instance) DumpMemoryConsumption()
func (self Instance) DumpCallStack()
```

## Sample codes

```Go
    var module *wamr.Module
    var instance *wamr.Instance
    var results []interface{}
    var err error

    /* Runtime initialization */
    err = wamr.Runtime().FullInit(false, nil, 1)

    /* Read WASM/AOT file into a memory buffer */
    wasmBytes := read_wasm_binary_to_buffer(...)

    /* Load WASM/AOT module from the memory buffer */
    module, err = wamr.NewModule(wasmBytes)

    /* Create WASM/AOT instance from the module */
    instance, err = wamr.NewInstance(module, 16384, 16384)

    /* Call the `fib` function */
    results = make([]interface{}, 1, 1)
    err = instance.CallFuncV("fib", 1, results, (int32)32)
    fmt.Printf("fib(32) return: %d\n", results[0].(int32));

    /* Destroy runtime */
    wamr.Runtime().Destroy()
```

More samples can be found in [test.go](./samples/test.go)
