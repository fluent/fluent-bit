

"simple" sample introduction
==============

This sample demonstrates following scenarios:

- Use tool "host_tool" to remotely install/uninstall wasm applications from the WAMR runtime over either TCP socket or UART cable
- Inter-app communication programming models
- Communication between WASM applications and the remote app host_tool
- A number of WASM applications built on top of WAMR application framework API sets



Directory structure
------------------------------
```
simple/
├── build.sh
├── CMakeLists.txt
├── README.md
├── src
│   ├── ext_lib_export.c
│   ├── iwasm_main.c
│   └── main.c
└── wasm-apps
    ├── connection.c
    ├── event_publisher.c
    ├── event_subscriber.c
    ├── request_handler.c
    ├── request_sender.c
    ├── sensor.c
    └── timer.c
```

- src/ext_lib_export.c<br/>
  This file is used to export native APIs. See the `The mechanism of exporting Native API to WASM application` section in WAMR README.md for detail.
- src/iwam_main.c<br/>
  This file is the implementation by platform integrator. It implements the interfaces that enable the application manager communicating with the host side. See `{WAMR_ROOT}/core/app-mgr/app-mgr-shared/app_manager_export.h` for the definition of the host interface.
## Set physical communication between device and remote



```
/* Interfaces of host communication */
typedef struct host_interface {
    host_init_func init;
    host_send_fun send;
    host_destroy_fun destroy;
} host_interface;

```
The `host_init_func` is called when the application manager starts up. And `host_send_fun` is called by the application manager to send data to the host.

Define a global variable "interface" of the data structure:

```

host_interface interface = {
    .init = host_init,
    .send = host_send,
    .destroy = host_destroy
};
```
This interface is passed to application manager during the runtime startup:
```
app_manager_startup(&interface);
```

>

**Note:** The connection between simple and host_tool is TCP by default. The simple application works as a server and the host_tool works as a client. You can also use UART connection. To achieve this you have to uncomment the below line in CMakeLists.txt and rebuild. 

```
#add_definitions (-DCONNECTION_UART)`
```

To run the UART based test, you have to set up a UART hardware connection between host_tool and the simple application. See the help of host_tool for how to specify UART device parameters.


Build the sample
==============
Execute the build.sh script then all binaries including wasm application files would be generated in 'out' directory. 

```
$ ./build.sh 
Enter build target profile (default=host-interp) -->
arm-interp
host-aot
host-interp
\>:

```

Enter the profile name for starting your build. "host-***" profiles build the sample for executing on your development machine, and "arm-interp" profile will do cross building for ARM target platform. If "arm-interp" is entered, please ensure the ARM cross compiler toolchain is already installed in your development machine. Your should set *ARM_A7_COMPILER_DIR* and *ARM_A7_SDKTARGETSYSROOT* environment variable in your ~/.bashrc correctly. refer to the file [profiles/arm-interp/toolchain.cmake](./profiles/arm-interp/toolchain.cmake).

```
~/.bashrc:
export ARM_A7_COMPILER_DIR="/home/beihai/cross-toolchains/gcc-linaro-arm-linux-gnueabihf-4.7-2013.03-20130313_linux/bin"
export ARM_A7_SDKTARGETSYSROOT="/home/beihai/cross-toolchains/gcc-linaro-arm-linux-gnueabihf-4.7-2013.03-20130313_linux/arm-linux-gnueabihf/libc"

notes: please set the value to the actual path of your cross toolchain.
```

If you need to create additional profile for customizing your runtime, application framework or the target platforms, a new subfolder can be created under the *profiles* folder, and place your own version of "toolchain.cmake" and "wamr_config_simple.cmake" in it.

```
$wamr-root/samples/simple/profiles$ ls
arm-interp  host-aot  host-interp
$wamr-root/samples/simple/profiles$ ls arm-interp/
toolchain.cmake  wamr_config_simple.cmake

```





**Out directory structure**

```
out/
├── host_tool
├── simple
└── wasm-apps
    ├── connection.wasm
    ├── event_publisher.wasm
    ├── event_subscriber.wasm
    ├── request_handler.wasm
    ├── request_sender.wasm
    ├── sensor.wasm
    └── timer.wasm
```

- host_tool:
  A small testing tool to interact with WAMR. See the usage of this tool by executing "./host_tool -h".
  `./host_tool -h`

- simple:
  A simple testing tool running on the host side that interact with WAMR. It is used to install, uninstall and query WASM applications in WAMR, and send request or subscribe event, etc. See the usage of this application by executing "./simple -h".
  `./simple -h`
>

Run the sample
==========================
- Enter the out directory
```
$ cd ./out/
```

- Startup the 'simple' process works in TCP server mode and you would see "App Manager started." is printed.
```
$ ./simple -s
App Manager started.
```

- Query all installed applications
```
$ ./host_tool -q

response status 69
{
    "num":    0
}
```

The `69` stands for response code SUCCESS. The payload is printed with JSON format where the `num` stands for application installations number and value `0` means currently no application is installed yet.

- Install the request handler wasm application<br/>
```
$ ./host_tool -i request_handler -f ./wasm-apps/request_handler.wasm

response status 65
```
Now the request handler application is running and waiting for host or other wasm application to send a request.

- Query again
```
$ ./host_tool -q 

response status 69
{
    "num":    1,
    "applet1":    "request_handler",
    "heap1":    49152
}
```
In the payload, we can see `num` is 1 which means 1 application is installed. `applet1`stands for the name of the 1st application. `heap1` stands for the heap size of the 1st application.

- Send request from host to specific wasm application
```
$ ./host_tool -r /app/request_handler/url1 -A GET

response status 69
{
    "key1":    "value1",
    "key2":    "value2"
}
```

We can see a response with status `69` and a payload is received.

Output of simple application:
```
connection established!
Send request to applet: request_handler
Send request to app request_handler success.
App request_handler got request, url url1, action 1
[resp] ### user resource 1 handler called
sent 150 bytes to host
Wasm app process request success.
```

- Send a general request from host (not specify target application name)<br/>
```
$ ./host_tool -r /url1 -A GET

response status 69
{
    "key1":    "value1",
    "key2":    "value2"
}
```

Output of simple application:
```
connection established!
Send request to app request_handler success.
App request_handler got request, url /url1, action 1
[resp] ### user resource 1 handler called
sent 150 bytes to host
Wasm app process request success.
```

- Install the event publisher wasm application
```
$ ./host_tool -i pub -f ./wasm-apps/event_publisher.wasm

response status 65
```

- Subscribe event by host_tool<br/>
```
$ ./host_tool -s /alert/overheat -a 3000

response status 69

received an event alert/overheat
{
    "warning":    "temperature is over high"
}
received an event alert/overheat
{
    "warning":    "temperature is over high"
}
received an event alert/overheat
{
    "warning":    "temperature is over high"
}
received an event alert/overheat
{
    "warning":    "temperature is over high"
}
```
We can see 4 `alert/overheat` events are received in 3 seconds which is published by the `pub` application.

Output of simple
```
connection established!
am_register_event adding url:(alert/overheat)
client: -3 registered event (alert/overheat)
sent 16 bytes to host
sent 142 bytes to host
sent 142 bytes to host
sent 142 bytes to host
sent 142 bytes to host
```
- Install the event subscriber wasm application<br/>
```
$ ./host_tool -i sub -f ./wasm-apps/event_subscriber.wasm

response status 65
```
The `sub` application is installed.

Output of simple
```
connection established!
Install WASM app success!
WASM app 'sub' started
am_register_event adding url:(alert/overheat)
client: 3 registered event (alert/overheat)
sent 16 bytes to host
Send request to app sub success.
App sub got request, url alert/overheat, action 6
### user over heat event handler called
Attribute container dump:
Tag: 
Attribute list:
  key: warning, type: string, value: temperature is over high

Wasm app process request success.
```

We can see the `sub` application receives the `alert/overheat` event and dumps it out.<br/>
At device side, the event is represented by an attribute container which contains key-value pairs like below:
```
Attribute container dump:
Tag:
Attribute list:
  key: warning, type: string, value: temperature is over high
```
`warning` is the key's name. `string` means this is a string value and `temperature is over high` is the value.

- Uninstall the wasm application<br/>
```
$ ./host_tool -u request_handler

response status 66

$ ./host_tool -u pub

response status 66

$ ./host_tool -u sub

response status 66
```

- Query again<br/>
```
$ ./host_tool -q

response status 69
{
    "num":    0
}
```

  >**Note:** Here we only installed part of the sample WASM applications. You can try others by yourself.

  >**Note:** You have to manually kill the simple process by Ctrl+C after use.
