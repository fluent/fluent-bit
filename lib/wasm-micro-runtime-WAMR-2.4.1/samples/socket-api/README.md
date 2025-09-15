# "socket-api" sample introduction

This sample demonstrates how to use WAMR socket-api to develop wasm network applications.
Two wasm applications are provided: tcp-server and tcp-client, and this sample demonstrates
how they communicate with each other.

## Preparation

Please install WASI SDK, download the [wasi-sdk release](https://github.com/WebAssembly/wasi-sdk/releases) and extract the archive to default path `/opt/wasi-sdk`.
And install wabt, download the [wabt release](https://github.com/WebAssembly/wabt/releases) and extract the archive to default path `/opt/wabt`

## Build the sample

```bash
mkdir build
cd build
cmake ..
make
```

`iwasm` and the following Wasm modules (along with their corresponding native version) will be generated:
 * `addr_resolve.wasm`, `addr_resolve`
 * `send_recv.wasm`, `send_recv`
 * `socket_opts.wasm`, `socket_opts`
 * `tcp_client.wasm`, `tcp_client`
 * `tcp_server.wasm`, `tcp_server`
 * `udp_client.wasm`, `udp_client`
 * `udp_server.wasm`, `udp_server`

> Note that iwasm is built with libc-wasi and lib-pthread enabled.

## Run workload

### TCP client/server

Start the tcp server, which opens port 1234 and waits for clients to connect.

```bash
cd build
./iwasm --addr-pool=0.0.0.0/15 tcp_server.wasm
```

Start the tcp client, which connects the server and receives message.

```bash
cd build
./iwasm --addr-pool=127.0.0.1/15 tcp_client.wasm
```

The output of client is like:

```bash
[Client] Create socket
[Client] Connect socket
[Client] Client receive
[Client] 115 bytes received:
Buffer received:
Say Hi from the Server
Say Hi from the Server
Say Hi from the Server
Say Hi from the Server
Say Hi from the Server

[Client] BYE
```

`send_recv.wasm` contains a thread as a server and a thread as a client. They
send and receive data via 127.0.0.1:1234.

```bash
$ ./iwasm --addr-pool=127.0.0.1/0 ./send_recv.wasm
```

The output is:

```bash
Server is online ...
Client is running...
Start receiving.
Start sending.
Send 106 bytes successfully!
Receive 106 bytes successfully!
Data:
  The stars shine down
  It brings us light
  Light comes down
  To make us paths
  It watches us
  And mourns for us
```

### Socket options

`socket_opts.wasm` shows an example of getting and setting various supported socket options
```bash
$ ./iwasm socket_opts.wasm
```
The output is:
```bash
[Client] Create TCP socket
[Client] Create UDP socket
[Client] Create UDP IPv6 socket
setsockopt SO_RCVTIMEO result is expected
getsockopt SO_RCVTIMEO result is expected
...
[Client] Close sockets
```

The `timeout_client.wasm` and `timeout_server.wasm` examples demonstrate socket send and receive timeouts using the socket options. Start the server, then start the client.

```bash
$ ./iwasm --addr-pool=0.0.0.0/15 timeout_server.wasm
```

The output is:

```bash
Wait for client to connect
Client connected, sleeping for 10s
Shutting down
```

```bash
$ ./iwasm --addr-pool=127.0.0.1/15 timeout_client.wasm
```

The output is:

```bash
Waiting on recv, which should timeout
Waiting on send, which should timeout
Success. Closing socket 
```

The `multicast_client` and `multicast_server` examples demonstrate receiving multicast packets in WASM. Start the client and then the server with a multicast IP address and port. 

```bash
$ ./iwasm --addr-pool=0.0.0.0/0,::/0 multicast_client.wasm <Multicast IP> <Port>
$ ./iwasm --addr-pool=0.0.0.0/0,::/0 multicast_client.wasm 224.0.0.1
$ ./iwasm --addr-pool=0.0.0.0/0,::/0 multicast_client.wasm FF02:113D:6FDD:2C17:A643:FFE2:1BD1:3CD2
```

The output should be

```bash
Joined multicast group. Waiting for datagram...
Reading datagram message...OK.
The message from multicast server is: "Test message"
```

```bash
$ ./multicast_server <Multicast IP> <Port>
$ ./multicast_server 224.0.0.1
$ ./multicast_server FF02:113D:6FDD:2C17:A643:FFE2:1BD1:3CD2
```

The output should be

```bash
Datagram sent
```

### Domain name server resolution

`addr_resolve.wasm` demonstrates the usage of resolving a domain name
```
$ ./iwasm --allow-resolve=*.com addr_resolve.wasm github.com
```

The command displays the host name and its corresponding IP address:
```
Host: github.com
IPv4 address: 140.82.121.4 (TCP)
```

### UDP client/server

Start the UDP server, which opens port 1234 and waits for clients to send a message.

```bash
cd build
./iwasm --addr-pool=0.0.0.0/15 udp_server.wasm
```

Start the tcp client, which sends a message to the server and waits for the response.

```bash
cd build
./iwasm --addr-pool=127.0.0.1/15 udp_client.wasm
```

The output of client is like:

```bash
[Client] Create socket
[Client] Client send
[Client] Client receive
[Client] Buffer received: Hello from server
[Client] BYE
```

The output of the server is like:
```
[Server] Create socket
[Server] Bind socket
[Server] Wait for clients to connect ..
[Server] received 17 bytes from 127.0.0.1:60927: Hello from client
```

## Documentation

Refer to [socket api document](../../doc/socket_api.md) for more details.
