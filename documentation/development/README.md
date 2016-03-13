# Fluent Bit for Developers

[Fluent Bit](http://fluentbit.io) have been designed and built to be used not only as a standalone tool, it can also be embedded in your C or C++ applications. The following section presents details about how you can use it inside your own programs. We assume that you have some basic knowledge of C language, ideally experience compiling programs on Unix/Linux environments.

## Internals (to be deprecated)

When Fluent Bit is built, it creates the final binary but also it creates a shared library version called _libfluent-bit.so_ which can be linked in your projects. The library allows you to enqueue data into the engine and return as quickly as possible, all hard job is done in _one_ posix thread who works in asynchronous mode, your caller process or thread will not be blocked.

The workflow to use the library is pretty straigh forward and involve the following calls in the given order:

| step | function & prototype            | optional |
|------|---------------------------------|----------|
| 1    | flb_lib_init(char *output)      |  No      |
| 2    | flb_config_verbose(int enabled) |  Yes     |
| 3    | flb_lib_config_file(struct flb_lib_ctx *ctx, char *path) | Yes |
| 4    | flb_lib_start(struct flb_lib_ctx *ctx) | No |
| 5    | flb_lib_push(struct flb_lib_ctx *ctx, void *data, size_t len) | Yes |
| 6    | flb_lib_stop(struct flb_lib *ctx) | No |
| 7    | flb_lib_exit(struct flb_lib *ctx) | No |


Below a description of each specific function involved:

#### 1. flb_lib_init

This is the principal function that creates a library context. It takes as an argument the desired output plugin in a string format.

```C
struct flb_lib_ctx *flb_lib_init(char *output);
```

Upon successful completion it returns a library context of type _struct flb\_lib\_ctx_, on error it returns NULL.


#### 2. flb_config_verbose

The library support a verbose mode to track specific events when enqueuing and processing data, by default default messages are disabled and this function can be used to turn it on or off. It prototype is the following:

```C
int flb_config_verbose(int enabled);
```

The _enabled_ argument can be _FLB\_TRUE_ or _FLB\_FALSE_ depending of the desired behavior. Upon successful completion it returns zero, otherwise it returns a negative value.

#### 3. flb_lib_config_file

Some output interfaces requires a configuration file, this interface allows to load a configuration file, some configuration files can be found on the [conf/](https://github.com/fluent/fluent-bit/tree/master/conf) directory. It prototype is the following:


```C
int flb_lib_config_file(struct flb_lib_ctx *ctx, char *path);
```

The first argument is the library context created on step _#1_. The second argument _path_ is an __absolute path__ to the location of the configuration file. Upon successful completion it returns zero, otherwise it returns a negative value.

#### 4. flb_lib_start

This function takes care of initialize the background service or main thread that will be collecting data events. It spawn a posix thread and make able an interface to push data into the engine. This function is safe to use and will only return once the [Fluent Bit](http://fluentbit.io) engine is ready to process messages. It prototype is the following:

```C
int flb_lib_start(struct flb_lib_ctx *ctx);
```

The only argument this function requires is the library context created on step _#1_. Upon successful completion it returns zero, otherwise it returns a negative value.

#### 5. flb_lib_push

This function allows you to ingest data into [Fluent Bit](http://fluentbit.io) engine. It prototype is the following:

```C
int flb_lib_push(struct flb_lib_ctx *ctx, char *data, size_t len);
```

The _ctx_ argument represents the library context created on step _#1_. The _data_ argument is a string buffer that contains a valid JSON message in the expected format as described at bottom in the __JSON Message Format__ section. The _len_ variable specify the string length of the JSON message.

Upon successful completion it returns the number of bytes processed, otherwise it returns a negative value.

#### 6. flb_lib_stop

This function instruct the Engine to stop processing events and perform a cleanup of the internal data. Before to return it will force a data flush to the output plugin in question to avoid data loss, after 5 seconds the worker thread will be stopped. It prototype is the following:

```C
int flb_lib_stop(struct flb_lib_ctx *ctx);
```

The function only takes one argument which is the library context created on step _#1_.  Upon successful completion it returns zero, otherwise it returns a negative value.

#### 7. flb_lib_exit

This function cleanup and release all resources associated on a library context created on step _#1_.

```C
void flb_lib_exit(struct flb_lib_ctx *ctx);
```

The function only takes one argument which is the library context created on step _#1_. It do not return any value.

## Example

Here is an example where we create a instance to enqueue some random JSON messages and we instruct it to write them (after processing) to the standard output:

```C
#include <fluent-bit.h>

#define DATA1   "[1449505010, {\"key1\": \"some value\"}]"
#define DATA2   "[1449505620, {\"key1\": \"some new value\"}]"

int main()
{
    struct flb_lib_ctx *ctx;

    /* Create a library context */
    ctx = flb_lib_init("stdout");
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Start the background worker */
    flb_lib_start(ctx);

    /* Push some data */
    flb_lib_push(ctx, DATA1, sizeof(DATA1) - 1);
    flb_lib_push(ctx, DATA2, sizeof(DATA2) - 1);

    /* Stop */
    flb_lib_stop(ctx);

/* Exit */
    flb_lib_exit(ctx);

    return 0;
}
```

As you can see we only need to include the __fluent-bit.h__ header and use the functions documented in the right order. For more details about how to make this code work please look at the examples directory where we have [examples](https://github.com/fluent/fluent-bit/tree/master/examples) in C and C++ languages. We also include an example on how to push data to [Treasure Data](http://www.treasuredata.com) service.

## JSON Message Format

When ingesting data, [Fluent Bit](http://fluentbit.io) expects the incoming JSON messages comes in the following format:

```
[UNIX_TIMESTAMP, MAP]
```

Every record must be a JSON array that contains at least two entries. The first one is the _UNIX\_TIMESTAMP_ which is a number representing time associated to the event generation (Epoch time) and the second entry is a JSON map with a list of key/values. A valid entry can be the following:

```
[1449505010, {"key1": "some value", "key2": false}]
```
