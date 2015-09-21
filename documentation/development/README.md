# Fluent Bit for Developers

[Fluent Bit](http://fluentbit.io) have been designed and built to be used not just as a standalone tool, it can also be embedded in your C or C++ applications.

The following section presents details about how you can use [Fluent Bit](http://fluentbit.io) inside your own application.

## Internals

When Fluent Bit is built, it creates the final binary but also it creates a shared library version called _libfluent-bit.so_ which can be linked in your projects. The library allows you to enqueue data into the engine and return as quickly as possible, all hard job is done in _one_ posix thread who works in asynchronous mode, your caller process or thread will not be blocked.

The workflow to use the library is pretty straigh forward and involve the following calls in the given order:

| step | function & prototype            | optional |
|------|---------------------------------|----------|
| 1    | flb_config_init()               |  No      |
| 2    | flb_config_verbose(int enabled) |  Yes     |
| 3    | flb_lib_config_file(struct flb_config *config, char *path) | Yes |
| 4    | flb_lib_init(struct flb_config *config, char *output) | No |
| 5    | flb_lib_start(struct flb_config *config) | No |
| 6    | flb_lib_push(struct flb_config *config, void *data, size_t len) | Yes |
| 7    | flb_lib_stop(struct flb_config *config) | No |


Below a description of each specific function involved:

#### 1. flb_config_init

The purpose of this function is to create a library configuration context that you will use on all the further calls. It prototype is the following:

```C
struct flb_config *flb_config_init();
```

the function do not take any argument. Upon successful completion it returns a configuration context of _struct flb\_config_ data type, on error it returns NULL.


#### 2. flb_config_verbose

The library support a verbose mode to track specific events when enqueuing and processing data, by default default messages are disabled and this function can be used to turn it on or off. It prototype is the following:

```C
int flb_config_verbose(int enabled);
```

The _enabled_ argument can be _FLB\_TRUE_ or _FLB\_FALSE_ depending of the desired behavior. Upon successful completion it returns zero, otherwise it returns a negative value.

#### 3. flb_lib_config_file

Some output interfaces requires a configuration file, this interface allows to load a configuration file, some configuration files can be found on the [conf/](https://github.com/fluent/fluent-bit/tree/master/conf) directory. It prototype is the following:


```C
int flb_lib_config_file(struct flb_config *config, char *path);
```

The first argument is the configuration context created on step _#1_. The second argument _path_ is an __absolute path__ to the location of the configuration file. Upon successful completion it returns zero, otherwise it returns a negative value.

#### 4. flb_lib_init

This function start the library configuration allowing to setup the desired output interface. Remember that Fluent Bit support many output interfaces and depending of how it was built you will have all or some of them available (for more details refer to the [installation](../getting_started/installation) section. It prototype is the following:

```C
int flb_lib_init(struct flb_config *config, char *output);
```

The first argument _config_ represents the configuration context retrieved on step _#1_. The _output_ argument refers to the output plugin that you may want to use. Upon successful completion it returns zero, otherwise it returns a negative value.

#### 5. flb_lib_start

This function takes care to initialize the background service or main thread that will be listening for data. It spawn a posix thread and make able an interface to push data into the engine. This function is safe to use and will only return once the [Fluent Bit](http://fluentbit.io) engine is ready to process messages. It prototype is the following:

```C
int flb_lib_start(struct flb_config *config);
```

The only argument this function requires is the main configuration context created on step _#1_. Upon successful completion it returns zero, otherwise it returns a negative value.

#### 6. flb_lib_push

This function is the one you should use in your main program to push data into the [Fluent Bit](http://fluentbit.io) engine. It prototype is the following:

```C
int flb_lib_push(struct flb_config *config, void *data, size_t len);
```

The first argument represents the configuration context created on step _#1_. The _data_ argument is a buffer which references the data that you want to be processed, it expect that you pass a __valid JSON__ message, it's recomendable that per call you don't pass a string larger than 64KB to avoid performance penalties. The third argument _len_ indicate the amount of bytes to read from the _data_ pointer reference, make sure that _len_ is always a valid value.

Upon successful completion it returns the number of bytes processed, otherwise it returns a negative value.

#### 7. flb_lib_stop

This function instruct the Engine to stop processing events and perform a cleanup of the internal data. Before to return it will force a data flush to the output plugin in question to avoid data loss, after 5 seconds the worker thread will be stopped. It prototype is the following:

```C
int flb_lib_stop(struct flb_config *config);
```

It only takes one argument which is the configuration context created on step _#1_.  Upon successful completion it returns zero, otherwise it returns a negative value.

## Example

Here is an example where we create a instance to enqueue some random JSON messages and we instruct it to write them (after processing) to the standard output:

```C
#include <fluent-bit.h>

int main()
{
    int i;
    int n;
    int ret;
    char tmp[256];
    struct flb_config *config;

    /* Create configuration context */
    config = flb_config_init();
    if (!config) {
        exit(EXIT_FAILURE);
    }

    /* Initialize library */
    ret = flb_lib_init(config, "stdout");
    if (ret != 0) {
        exit(EXIT_FAILURE);
    }

    /* Start the background worker */
    flb_lib_start(config);

    /* Push some data */
    for (i = 0; i < 100; i++) {
        n = snprintf(tmp, sizeof(tmp) - 1, "{\"key\": \"val %i\"}", i);
        flb_lib_push(config, tmp, n);
    }

    /* Stop and cleanup */
    flb_lib_stop(config);

    return 0;
}
```

As you can see we only need to include the __fluent-bit.h__ header and use the functions documented in the right order. For more details about how to make this code work please look at the examples directory where we have [examples](https://github.com/fluent/fluent-bit/tree/master/examples) in C and C++ languages. We also include an example on how to push data to [Treasure Data](http://www.treasuredata.com) service.
