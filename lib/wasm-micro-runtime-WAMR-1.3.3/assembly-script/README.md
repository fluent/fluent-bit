# AssemblyScript_on_WAMR
This project is based on [Wasm Micro Runtime](https://github.com/bytecodealliance/wasm-micro-runtime) (WAMR) and [AssemblyScript](https://github.com/AssemblyScript/assemblyscript). It implements some of the `wamr app framework` in *assemblyscript*, which allows you to write some applications in *assemblyscript* and dynamically installed on *WAMR Runtime*

## Building
To build the samples in this repo, you need `npm` on your system
``` bash
sudo apt install npm
```

Then install all the dependencies under the repo's root dir
``` bash
cd $repo_root
npm install
```

Use the command to build all samples:
``` bash
npm run build:all
```
or you can build every sample individually:
``` bash
npm run build:timer
npm run build:publisher
npm run build:subscriber
# ...
```
You will get the compiled wasm file under `build` folder

Please refer to [package.json](./package.json) for more commands.

## Run
These applications require WAMR's application framework, you need to build WAMR first.

``` bash
cd ${WAMR_ROOT}/samples/simple
./build.sh
```

You will get two executable files under `out` folder:

`simple`: The wamr runtime with application framework

`host_tool`: The tool used to dynamically install/uninstall applications

1. Start the runtime:
    ``` bash
    ./simple -s
    ```

2. Install the compiled wasm file using `host_tool`:
    ``` bash
    ./host_tool -i app_name -f your_compiled_wasm_file.wasm
    ```
You can also use the WAMR's AoT compiler `wamrc` to compile the wasm bytecode into native code before you run them. Please refer to this [guide](../README.md#build-wamrc-aot-compiler) to build and install `WAMR AoT compiler`.

After installing `wamrc`, you can compile the wasm file using command:
``` bash
wamrc -o file_name.aot file_name.wasm
```
and you can install the AoT file to the runtime:
``` bash
./host_tool -i app_name -f your_compiled_aot_file.aot
```

## Development
You can develop your own application based on the `wamr_app_lib` APIs.

### Console APIs
``` typescript
function log(a: string): void;
function log_number(a: number): void;
```

### Timer APIs
``` typescript
function setTimeout(cb: () => void, timeout: i32): user_timer;
function setInterval(cb: () => void, timeout: i32): user_timer;
function timer_cancel(timer: user_timer): void;
function timer_restart(timer: user_timer, interval: number): void;
function now(): i32;

// export to runtime
function on_timer_callback(on_timer_id: i32): void;
```

### Request APIs
``` typescript
// register handler
function register_resource_handler(url: string,
                                   request_handle: request_handler_f): void;
// request
function post(url: string, payload: ArrayBuffer, payload_len: number,
              tag: string, cb: (resp: wamr_response) => void): void;
function get(url: string, tag: string,
             cb: (resp: wamr_response) => void): void;
function put(url: string, payload: ArrayBuffer, payload_len: number, tag: string,
             cb: (resp: wamr_response) => void): void;
function del(url: string, tag: string,
             cb: (resp: wamr_response) => void): void;

// response
function make_response_for_request(req: wamr_request): wamr_response;
function api_response_send(resp: wamr_response): void;

// event
function publish_event(url: string, fmt: number,
                       payload: ArrayBuffer, payload_len: number): void;
function subscribe_event(url: string, cb: request_handler_f): void;

// export to runtime
function on_request(buffer_offset: i32, size: i32): void;
function on_response(buffer_offset : i32, size: i32): void;
```

You should export the `on_timer_callback`, `on_request` and `on_response` in your application entry file, refer to the samples for example.

To build your application, you can use `asc`:
``` bash
asc app.ts -b build/app.wasm -t build/app.wat --sourceMap --validate --optimize
```
or you can add a command into [package.json](./package.json):
``` json
"build:app": "asc app.ts -b build/app.wasm -t build/app.wat --sourceMap --validate --optimize",
```
