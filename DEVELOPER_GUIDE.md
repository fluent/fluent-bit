# Beginners Guide to Contributing to Fluent Bit

Assuming you have some basic knowledge of C, this guide should help you understand how to make code
changes to Fluent Bit.

## Table of Contents

- [Beginners Guide to Contributing to Fluent Bit](#beginners-guide-to-contributing-to-fluent-bit)
  - [Table of Contents](#table-of-contents)
  - [Development Environment](#development-environment)
    - [Devcontainer](#devcontainer)
    - [Vagrant](#vagrant)
  - [Libraries](#libraries)
    - [Memory Management](#memory-management)
    - [Strings](#strings)
    - [HTTP Client](#http-client)
    - [Linked Lists](#linked-lists)
    - [Message Pack](#message-pack)
  - [Concurrency](#concurrency)
    - [Coroutine Code: How does it work?](#coroutine-code-how-does-it-work)
    - [Practical Advice: How coroutines will affect your code](#practical-advice-how-coroutines-will-affect-your-code)
      - [Filter Plugins](#filter-plugins)
      - [Output plugins](#output-plugins)
  - [Plugin API](#plugin-api)
    - [Input](#input)
    - [Filter](#filter)
    - [Output](#output)
    - [Config Maps](#config-maps)
  - [Testing](#testing)
    - [Building and Testing on Windows](#building-and-testing-on-windows)
    - [Valgrind](#valgrind)
  - [Need more help?](#need-more-help)

## Development Environment

Development environments allow to work without any dependency locally.

### Devcontainer

A Development Container (or Dev Container for short) allows you to use a container as a full-featured development environment.

Thanks to [Visual Studio Code integration](https://code.visualstudio.com/docs/devcontainers/containers), devcontainers are managed easily.

#### Prerequirements

Please refer to the [devcontainer documentation](https://code.visualstudio.com/docs/devcontainers/containers#_system-requirements) for full details on pre-requisites and installation.

#### Using without optional tools

```shell
docker run \
    --name devcontainer-fluent-bit \
    --volume $PWD/:/workspaces/fluent-bit \
    --user $UID:$GID \
    --tty \
    --detach \
    fluent/fluent-bit:latest-debug

docker exec --user root devcontainer-fluent-bit addgroup --system --gid $GID fluent-bit
docker exec --user root devcontainer-fluent-bit useradd --create-home --system --uid $UID --gid $GID fluent-bit
docker exec --user root devcontainer-fluent-bit sh -c 'mkdir -p /etc/sudoers.d; echo "fluent-bit   ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers.d/fluent-bit'
docker exec -it devcontainer-fluent-bit bash

cd /workspaces/fluent-bit
```

If local applications need to access fluent-bit server or tcp/udp inputs, the ports must be publish with --publish flag. ex:

```text
docker run \
--publish 2020:2020 \
--publish 80:80 \
...
```

### Vagrant
Vagrant enables the creation and configuration of lightweight, reproducible, and portable development environments.

#### Prerequirements
- [vagrant](https://www.vagrantup.com)
- [vagrant providers](https://developer.hashicorp.com/vagrant/docs/providers)

#### Using

```shell
vagrant up
vagrant ssh
```

## Libraries

Most external libraries are embedded in the project in the [/lib](/lib) folder. To keep its footprint low and make cross-platform builds simple, Fluent Bit attempts keep its dependency graph small.

The external library you are mostly likely to interact with is [msgpack](https://github.com/msgpack/msgpack-c).

For crypto, Fluent Bit uses [mbedtls](https://github.com/ARMmbed/mbedtls).

### Memory Management

When you write Fluent Bit code, you will use Fluent Bit's versions of the standard C functions for working with memory:

- [`flb_malloc()`](include/fluent-bit/flb_mem.h) - equivalent to `malloc`, allocates memory.
- [`flb_calloc()`](include/fluent-bit/flb_mem.h)  - equivalent to `calloc`, allocates memory and initializes it to zero.
- [`flb_realloc()`](include/fluent-bit/flb_mem.h) - equivalent to `realloc`.
- [`flb_free()`](include/fluent-bit/flb_mem.h) - equivalent to `free`, releases allocated memory.

Note that many types have a specialized create and destroy function. For example,
[`flb_sds_create()` and `flb_sds_destroy()`](include/fluent-bit/flb_sds.h) (more about this in the next section).

### Strings

Fluent Bit has a stripped down version of the popular [SDS](https://github.com/antirez/sds) string library. See [flb_sds.h](include/fluent-bit/flb_sds.h) for the API.

In general, you should use SDS strings in any string processing code. SDS strings are fully compatible with any C function that accepts a null-terminated sequence of characters; to understand how they work, see the [explanation on Github](https://github.com/antirez/sds#how-sds-strings-work).

### HTTP Client

Fluent Bit has its own network connection library. The key types and functions are defined in the following header files:

- [flb_upstream.h](include/fluent-bit/flb_upstream.h)
- [flb_http_client.h](include/fluent-bit/flb_http_client.h)
- [flb_io.h](include/fluent-bit/flb_io.h)

The following code demonstrates making an HTTP request in Fluent Bit:

```c
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>

#define HOST  "127.0.0.1"
#define PORT  80

static flb_sds_t make_request(struct flb_config *config)
{
    struct flb_upstream *upstream;
    struct flb_http_client *client;
    size_t b_sent;
    int ret;
    struct flb_upstream_conn *u_conn;
    flb_sds_t resp;

    /* Create an 'upstream' context */
    upstream = flb_upstream_create(config, HOST, PORT, FLB_IO_TCP, NULL);
    if (!upstream) {
        flb_error("[example] connection initialization error");
        return -1;
    }

    /* Retrieve a TCP connection from the 'upstream' context */
    u_conn = flb_upstream_conn_get(upstream);
    if (!u_conn) {
        flb_error("[example] connection initialization error");
        flb_upstream_destroy(upstream);
        return -1;
    }

    /* Create HTTP Client request/context */
    client = flb_http_client(u_conn,
                             FLB_HTTP_GET, metadata_path,
                             NULL, 0,
                             FLB_FILTER_AWS_IMDS_V2_HOST, 80,
                             NULL, 0);

    if (!client) {
        flb_error("[example] count not create http client");
        flb_upstream_conn_release(u_conn);
        flb_upstream_destroy(upstream);
        return -1;
    }

    /* Perform the HTTP request */
 ret = flb_http_do(client, &b_sent)

    /* Validate return status and HTTP status if set */
    if (ret != 0 || client->resp.status != 200) {
        if (client->resp.payload_size > 0) {
            flb_debug("[example] Request failed and returned: \n%s",
                      client->resp.payload);
        }
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        flb_upstream_destroy(upstream);
        return -1;
    }

    /* Copy payload response to an output SDS buffer */
    data = flb_sds_create_len(client->resp.payload,
                              client->resp.payload_size);

    flb_http_client_destroy(client);
    flb_upstream_conn_release(u_conn);
    flb_upstream_destroy(upstream);

    return resp;
}
```

An `flb_upstream` structure represents a host/endpoint that you want to call. Normally, you'd store this structure somewhere so that it can be re-used. An `flb_upstream_conn` represents a connection to that host for a single HTTP request. The connection structure should not be used for more than one request.

### Linked Lists

Fluent Bit contains a library for constructing linked lists- [mk_list](lib/monkey/include/monkey/mk_core/mk_list.h). The type stores data as a circular linked list.

The [`mk_list.h`](lib/monkey/include/monkey/mk_core/mk_list.h) header file contains several macros and functions for use with the lists. The example below shows how to create a list, iterate through it, and delete an element.

```c
#include <monkey/mk_core/mk_list.h>
#include <fluent-bit/flb_info.h>

struct item {
    char some_data;

    struct mk_list _head;
};

static int example()
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list items;
    int i;
    int len;
    char characters[] = "abcdefghijk";
    struct item *an_item;

    len = strlen(characters);

    /* construct a list */
    mk_list_init(&items);

    for (i = 0; i < len; i++) {
        an_item = flb_malloc(sizeof(struct item));
        if (!an_item) {
            flb_errno();
            return -1;
        }
        an_item->some_data = characters[i];
        mk_list_add(&an_item->_head, &items);
    }

    /* iterate through the list */
    flb_info("Iterating through list");
    mk_list_foreach_safe(head, tmp, &items) {
        an_item = mk_list_entry(head, struct item, _head);
        flb_info("list item data value: %c", an_item->some_data);
    }

    /* remove an item */
    mk_list_foreach_safe(head, tmp, &items) {
        an_item = mk_list_entry(head, struct item, _head);
        if (an_item->some_data == 'b') {
            mk_list_del(&an_item->_head);
            flb_free(an_item);
        }
    }
}
```

### Message Pack

Fluent Bit uses [msgpack](https://msgpack.org/index.html) to internally store data. If you write code for Fluent Bit, it is almost certain that you will interact with msgpack.

Fluent Bit embeds the [msgpack-c](https://github.com/msgpack/msgpack-c) library. The example below shows manipulating message pack to add a new key-value pair to a record. In Fluent Bit, the [filter_record_modifier](plugins/filter_record_modifier) plugin adds or deletes keys from records. See its code for more.

```c
#define A_NEW_KEY        "key"
#define A_NEW_KEY_LEN    3
#define A_NEW_VALUE      "value"
#define A_NEW_VALUE_LEN  5

static int cb_filter(const void *data, size_t bytes,
                     const char *tag, int tag_len,
                     void **out_buf, size_t *out_size,
                     struct flb_filter_instance *f_ins,
                     void *context,
                     struct flb_config *config)
{
    (void) f_ins;
    (void) config;
    size_t off = 0;
    int i = 0;
    int ret;
    struct flb_time tm;
    int total_records;
    int new_keys = 1;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_unpacked result;
    msgpack_object  *obj;
    msgpack_object_kv *kv;

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate over each item */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        /*
         * Each record is a msgpack array [timestamp, map] of the
         * timestamp and record map. We 'unpack' each record, and then re-pack
         * it with the new fields added.
         */

        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        /* unpack the array of [timestamp, map] */
        flb_time_pop_from_msgpack(&tm, &result, &obj);

        /* obj should now be the record map */
        if (obj->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        /* re-pack the array into a new buffer */
        msgpack_pack_array(&tmp_pck, 2);
        flb_time_append_to_msgpack(&tm, &tmp_pck, 0);

        /* new record map size is old size + the new keys we will add */
        total_records = obj->via.map.size + new_keys;
        msgpack_pack_map(&tmp_pck, total_records);

        /* iterate through the old record map and add it to the new buffer */
        kv = obj->via.map.ptr;
        for(i=0; i < obj->via.map.size; i++) {
            msgpack_pack_object(&tmp_pck, (kv+i)->key);
            msgpack_pack_object(&tmp_pck, (kv+i)->val);
        }

        /* append new keys */
        msgpack_pack_str(&tmp_pck, A_NEW_KEY_LEN);
        msgpack_pack_str_body(&tmp_pck, A_NEW_KEY, A_NEW_KEY_LEN);
        msgpack_pack_str(&tmp_pck, A_NEW_VALUE_LEN);
        msgpack_pack_str_body(&tmp_pck, A_NEW_VALUE, A_NEW_VALUE_LEN);

    }
    msgpack_unpacked_destroy(&result);

    /* link new buffers */
    *out_buf  = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;
    return FLB_FILTER_MODIFIED;
```

Please also check out the message pack examples on the [msgpack-c GitHub repo](https://github.com/msgpack/msgpack-c).

## Concurrency

Fluent Bit uses ["coroutines"](https://en.wikipedia.org/wiki/Coroutine); a concurrent programming model in which subroutines can be paused and resumed. Co-routines are cooperative routines- instead of blocking, they cooperatively pass execution between each other. Coroutines are implemented as part of Fluent Bit's core network IO libraries. When a blocking network IO operation is made (for example, waiting for a response on a socket), a routine will cooperatively yield (pause itself) and pass execution to Fluent Bit engine, which will schedule (activate) other routines. Once the blocking IO operation is complete, the sleeping coroutine will be scheduled again (resumed). This model allows Fluent Bit to achieve performance benefits without the headaches that often come from having multiple active threads.

This Fluent Bit engine consists of an event loop that is built upon [github.com/monkey/monkey](https://github.com/monkey/monkey). The monkey project is a server and library designed for low resource usage. It was primarily implemented by Eduardo Silva, who also created Fluent Bit.

### Coroutine Code: How does it work?

To understand how this works, let's walkthrough an example in the code.

The elasticsearch plugin makes an HTTP request to an elasticsearch cluster, when the following [line of code runs](https://github.com/fluent/fluent-bit/blob/1.3/plugins/out_es/es.c#L581):

```c
ret = flb_http_do(c, &b_sent);
```

This calls the http request function, in [`flb_http_client.c`, which makes a TCP write call](https://github.com/fluent/fluent-bit/blob/1.3/src/flb_http_client.c#L840):

```c
ret = flb_io_net_write(c->u_conn,
                       c->body_buf, c->body_len,
                       &bytes_body);
```

That activates code in Fluent Bit's core TCP library, which is where the coroutine magic happens. This code is in [flb_io.c](https://github.com/fluent/fluent-bit/blob/1.3/src/flb_io.c#L241). After opening a socket, the code inserts an item on the event loop:

```c
ret = mk_event_add(u->evl,
                   u_conn->fd,
                   FLB_ENGINE_EV_THREAD,
                   MK_EVENT_WRITE, &u_conn->event);
```

This instructs the event loop to watch our socket's file descriptor. Then, [a few lines below, we yield back to the engine thread](https://github.com/fluent/fluent-bit/blob/1.3/src/flb_io.c#L304):

```c
/*
 * Return the control to the parent caller, we need to wait for
 * the event loop to get back to us.
 */
flb_thread_yield(th, FLB_FALSE);
```

Remember, only one thread is active at a time. If the current coroutine did not yield back to engine, it would monopolize execution until the socket IO operation was complete. Since IO operations may take a long time, we can increase performance by allowing another routine to perform work.

The core routine in Fluent Bit is the engine in `flb_engine.c`. Here we can find the [code that will resume the elasticsearch plugin](https://github.com/fluent/fluent-bit/blob/1.3/src/flb_engine.c#L553) once it's IO operation is complete:

```c
if (event->type == FLB_ENGINE_EV_THREAD) {
    struct flb_upstream_conn *u_conn;
    struct flb_thread *th;

    /*
     * Check if we have some co-routine associated to this event,
     * if so, resume the co-routine
     */
    u_conn = (struct flb_upstream_conn *) event;
    th = u_conn->thread;
    flb_trace("[engine] resuming thread=%p", th);
    flb_thread_resume(th);
}
```

This will return execution to the code right after the [flb_thread_yield](https://github.com/fluent/fluent-bit/blob/1.3/src/flb_io.c#L304) call in the IO library.

### Practical Advice: How coroutines will affect your code

#### Filter Plugins

Filter plugins do not support coroutines, consequently you must disable async mode if your filter makes an HTTP request:

```c
/* Remove async flag from upstream */
upstream->flags &= ~(FLB_IO_ASYNC);
```

#### Output plugins

Output plugins use coroutines. Plugins have a context structure which is available in all calls and can be used to store state. In general, you can write code without ever considering concurrency. This is because only one coroutine is active at a time. Thus, synchronization primitives like mutex locks or semaphores are not needed.

There are some cases where you need to consider concurrency; consider the following code (this is fluent bit c pseudo-code, not a full example):

```c
/* output plugin flush method for sending records */
static void cb_my_plugin_flush(...)
{
    /* context structure that allows the plugin to store state */
    struct flb_my_plugin *ctx = out_context;
    ...
    /* write something to context */
    ctx->flag = somevalue;

    /* make an async http call */
    ret = flb_http_do(c, &b_sent);

    /*
     * do something with the context flag; the value of flag is indeterminate
     * because we just made an async call.
     */
    somecall(ctx->flag);
}
```

When the http call is made, the current coroutine may be paused and another can be scheduled. That other coroutine may also call `cb_my_plugin_flush`. If that happens, the value of the `flag` on the context may be changed. This could potentially lead to a race condition when the first coroutine resumes. Consequently, you must be extremely careful when storing state on the context. In general, context values should be set when a plugin is initialized, and then should only be read from afterwards.

Remember, if needed, you can ensure that an HTTP call is made synchronously by modifying your flb_upstream:

```c
/* Remove async flag from upstream */
upstream->flags &= ~(FLB_IO_ASYNC);
```

This can be re-enabled at any time:

```c
/* re-enable async for future calls */
upstream->flags |= FLB_IO_ASYNC;
```

## Plugin API

Each plugin is a shared object which is [loaded into Fluent Bit](https://github.com/fluent/fluent-bit/blob/1.3/src/flb_plugin.c#L70) using dlopen and dlsym.

### Input

The input plugin structure is defined in [flb_input.h](https://github.com/fluent/fluent-bit/blob/master/include/fluent-bit/flb_input.h#L62). There are a number of functions which a plugin can implement, most only implement `cb_init`, `cb_collect`, and `cb_exit`.

The [`"dummy"` input plugin](plugins/in_dummy) very simple and is an excellent example to review to understand more.

### Filter

The structure for filter plugins is defined in [flb_filter.h](https://github.com/fluent/fluent-bit/blob/master/include/fluent-bit/flb_filter.h#L44). Each plugin must implement `cb_init`, `cb_filter`, and `cb_exit`.

The [filter_record_modifier](plugins/filter_record_modifier) is a good example of a filter plugin.

Note that filter plugins can not asynchronously make HTTP requests. If your plugin needs to make a request, add the following code when you initialize your `flb_upstream`:

```c
/* Remove async flag from upstream */
upstream->flags &= ~(FLB_IO_ASYNC);
```

### Output

Output plugins are defined in [flb_output.h](https://github.com/fluent/fluent-bit/blob/master/include/fluent-bit/flb_output.h#L57). Each plugin must implement `cb_init`, `cb_flush`, and `cb_exit`.

The [stdout plugin](plugins/out_stdout) is very simple; review its code to understand how output plugins work.

### Config Maps

Config maps are an improvement to the previous Fluent Bit API that was used by plugins to read configuration values. The new config maps feature warns the user if there is an unknown configuration key and reduces risk of bad configuration due to typos or deprecated property names. They will also allow dynamic configuration reloading to be implemented in the future.

There are various types of supported configuration types. Full list available [here](https://github.com/fluent/fluent-bit/blob/v1.4.2/include/fluent-bit/flb_config_map.h#L29). The most used ones are:

| Type                   | Description           |
| -----------------------|:---------------------:|
| FLB_CONFIG_MAP_INT     | Represents integer data type |
| FLB_CONFIG_MAP_BOOL    | Represents boolean data type |
| FLB_CONFIG_MAP_DOUBLE  | Represents a double |
| FLB_CONFIG_MAP_SIZE    | Provides size_type as an integer datatype large enough to represent any possible string size. |
| FLB_CONFIG_MAP_STR     | Represents string data type |
| FLB_CONFIG_MAP_CLIST   | Comma separated list of strings |
| FLB_CONFIG_MAP_SLIST   | Empty space separated list of strings |

A config map expects certain public fields at registration.

| Public Fields | Description           |
| --------------|:---------------------|
| Type          | This field is the data type of the property that we are writing to the config map. If the property is of type `int` we use `FLB_CONFIG_MAP_INT`, if `string` `FLB_CONFIG_MAP_STR` etc. |
| Name          | This field is the name of the configuration property. For example for the property flush count we use `flush_count`|
| Default Value | This field allows the user to set the default value of the property. For example, for a property of type `FLB_CONFIG_MAP_BOOL` (boolean), the default value may be false. Then we have to give `false` as default value. If there is no default value, `NULL` is given.|
| Flags         | This field allows the user to set option flags. For example, it specifies in certain cases if multiple entries are allowed. |
| Set Property  | This field decides if the property needs to be written to plugin context or just validated. If the property needs to be written to the plugin context, the value of this field needs to `FLB_TRUE` or else the value will be `FLB_FALSE`.|
| Offset        | This field represents the member offset. It is 0 if the property is not written to the plugin context and if the property is being written to the plugin context it is ```offsetof(struct name_of_plugin_structure, name_of_property)```. The macro offsetof() returns the offset of the field *member* from the start of the structure type.|
| Description   | This field is so that the user can give a short description of the property. It is `NULL` if no description is needed or given. |

For example for [stdout](https://github.com/fluent/fluent-bit/blob/v1.4.2/plugins/out_stdout/stdout.c#L158) plugin the config map is something like:

```c
/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "format", NULL,
     0, FLB_FALSE, 0,
     "Specifies the data format to be printed. Supported formats are msgpack json, json_lines and json_stream."
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_format", NULL,
     0, FLB_FALSE, 0,
     "Specifies the name of the date field in output."
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_stdout, json_date_key),
     "Specifies the format of the date. Supported formats are double,  iso8601, java_sql_timestamp and epoch."
    },

    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_stdout_plugin = {
    .name         = "stdout",
    .description  = "Prints events to STDOUT",
    .cb_init      = cb_stdout_init,
    .cb_flush     = cb_stdout_flush,
    .cb_exit      = cb_stdout_exit,
    .flags        = 0,
    .config_map   = config_map
};

```

In the above code snippet, the property *format* is of type string which supports formats like json, msgpack etc. It has default value NULL(in which case it uses msgpack), no flags, and it is being only validated by the config map and hence set_property field is `FLB_FALSE` with member offset 0. No description is written for *format* property at present.
Similarly, for the property *json_date_key*, type is string, default value is date, and it is being written to context so the set_property field is `FLB_TRUE` with a member offset. Again, no description is written for it.

Upon initilization the engine loads the config map like [this](https://github.com/fluent/fluent-bit/blob/v1.4.2/plugins/out_stdout/stdout.c#L48):

```c
    ret = flb_output_config_map_set(ins, (void *) ctx);
```

[flb_output_config_map_set](https://github.com/fluent/fluent-bit/blob/v1.4.2/include/fluent-bit/flb_output.h#L510) returns [flb_config_map_set](https://github.com/fluent/fluent-bit/blob/v1.4.2/src/flb_config_map.c#L513) which is a function used by plugins that needs to populate their context structure with the configuration properties already mapped.

Some points to keep in mind while migrating an existing plugin to a config map interface:

- All memory allocations and releases of properties on exit are handled by the config map interface.
- The config map does not parse host and port properties since these properties are handled automatically for plugins that perform network operations.
- Some plugins might also have an empty config_map. This is so that it would show an error when someone tried to use a non-existent parameter.

## Testing

During development, you can build Fluent Bit as follows:

```shell
cd build
cmake -DFLB_DEV=On ../
make
```

Note that Fluent Bit uses Cmake 3 and on some systems you may need to invoke it as `cmake3`.

To set up and build your environment, please refer to the packaging containers for a dependency list: <https://github.com/fluent/fluent-bit/tree/master/packaging/distros>.

See [Building and Testing on Windows](#building-and-testing-on-windows) for Windows instructions.

A simple container-based script [`run_code_analysis.sh`](./run_code_analysis.sh) is provided to run unit tests using <https://github.com/marketplace/actions/cmake-swiss-army-knife>.

```shell
$ ./run_code_analysis.sh
...
+ ctest --output-on-failure .
Test project /tmp/source
        Start   1: flb-rt-core-timeout
  1/109 Test   #1: flb-rt-core-timeout ........................   Passed   10.31 sec
        Start   2: flb-rt-in_event_test
  2/109 Test   #2: flb-rt-in_event_test .......................   Passed    9.01 sec
        Start   3: flb-rt-in_cpu
...

```

Refer to <https://github.com/marketplace/actions/cmake-swiss-army-knife> for full details but this can run with sanitizers, valgrind and other tooling too by setting the `TEST_PRESENT` environment variable.

A [`Vagrantfile`](./Vagrantfile) is provided to simplify building on a VM, this will set up a VM using Vagrant you can then build in.

```shell
vagrant up
vagrant ssh
cd build
rm -rf *
cmake ...
make
```

It also acts as a reference for the tooling required to be installed on a local PC if you want to build things.

The VM created by Vagrant uses `rsync` to synchronize the files with rather than directly mounting the local directory.
The reason is to handle any permission issues and isolate the underlying host filesystem.
Refer to the Vagrant documentation for syncing changes: <https://www.vagrantup.com/docs/cli/rsync-auto>

To enable the unit tests run:

```shell
cmake -DFLB_DEV=On -DFLB_TESTS_RUNTIME=On -DFLB_TESTS_INTERNAL=On ../
make
```

Internal tests are for the internal libraries of Fluent Bit. Runtime tests are for the plugins.

You can run the unit tests with `make test`, however, this is inconvenient in practice. Each test file will create an executable in the `build/bin` directory which you can run directly. For example, if you want to run the SDS tests, you can invoke them as follows:

```shell
$ ./bin/flb-it-sds
Test sds_usage...                               [   OK   ]
Test sds_printf...                              [   OK   ]
SUCCESS: All unit tests have passed.
```

### Building and testing on Windows

Fluent Bit is built with MSVC and CMake on Windows.

Windows builds of Fluent Bit override the set of enabled plugins. See
[`cmake/windows-setup.cmake`](./cmake/windows-setup.cmake) for the override
list and other Windows-specific build rules.

#### Using a Github Action

For developers without convenient access to a Windows build machine the easiest
way to build a branch of Fluent Bit on Windows is to fork the `fluent-bit`
repository and enable workflow runs. The
[`.github/workflows/pr-windows-build.yaml`](.github/workflows/pr-windows-build.yaml)
workflow can then be invoked in your branch via the Actions tab on your forked
repository to build your patch.

This workflow will not run automatically on pull requests opened against the
`fluent/fluent-bit` repository so it's best you run it yourself in your fork. 

The resulting binaries are uploaded as a Github workflow artifact which can be
found on the workflow run page.

At time of writing this workflow *does not run any of the Fluent Bit test suite*
- so it only checks that the target branch can be compiled. To run tests, a local
build will be required.

#### Using Docker for Windows

For Windows users with Hyper-V capable machines the simplest way to build a
branch of Fluent Bit is to use
[Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)
to build
[`./dockerfiles/Dockerfile.windows`](./dockerfiles/Dockerfile.windows).

This method does not require manual installation of any build dependencies.

The Dockerfile build does *not* run any Fluent Bit test suites. To run tests you
will need to use a different method.

Most OS virtualisation tools and virtual machine hosting services do not enable
nested virtualisation, so it is generally not possible to use this method on
virtualized windows machines.

#### Locally on a Windows machine

Local compilation on a Windows machine takes the longest to set up, but is the
most convenient for iterating development work.

At time of writing this is the only way to run the Fluent Bit tests on Windows.

In lieu of full Windows dev environment setup instructions, see these CI automation
resources for how to set up a Windows build of fluent-bit:

* [`dockerfiles/Dockerfile.windows`](./dockerfiles/Dockerfile.windows) - only build-able using Docker for Windows
* [`appveyor.yml`](./appveyor.yml)
* [`.github/workflows/call-build-windows.yaml`](.github/workflows/call-build-windows.yaml) - github automation that runs the build on a Windows worker.

The dependencies must be present:

* Microsoft Visual Studio C/C++ toolchain. The CI automation uses MSVC 2019 at time of writing. MSVC Community Edition works fine.
* [CMake](https://cmake.org/) 3.x on the `PATH`
* A build of [OpenSSL](https://www.openssl.org/) as static libraries, pointed to by the `-DOPENSSL_ROOT_DIR` CMake variable.
* The CI automation uses vcpkg to install dependencies [](https://github.com/fluent/fluent-bit/blob/master/.github/workflows/call-build-windows.yaml#L148)
* `flex.exe` and `bison.exe` must be present on the `PATH`. The CI automation uses https://github.com/lexxmark/winflexbison.

Assuming that `cmake` is on the `PATH`, Visual Studio is installed,
WinFlexBison is present at `%SYSTEMDRIVE%\WinFlexBison` and OpenSSL is present
at `%PROGRAMFILES%\OpenSSL-Win64`, the following Powershell commands should
produce a basic Fluent Bit build:

```powershell
$env:PATH += "$env:SystemDrive\WinFlexBison"
mkdir build
cd build
cmake -DOPENSSL_ROOT_DIR="$env:ProgramFiles\OpenSSL-Win64" -S .. -B .
cmake --build .
```

The build output will be `bin\Debug\fluent-bit.exe`.

If in doubt, check the CI and build automation files referenced above for specifics.

### Building on a Windows Server 2022

The following steps have been tested on a Windows Server 2022 Datacenter edition on top of GCP.

1. **Download and Install Visual Studio 2022** (Community Edition)
    - **Download**: Go to [Visual Studio Download Page](https://visualstudio.microsoft.com/downloads/).
    - **Install**:
        - Select **Community Edition** and check the following components during installation:
            - **Desktop development with C++**
            - **Linux development with C++**

2. **Install Flex and Bison**
    1. Create a new file called `setup-flex-bison.ps1` and paste the following script:

    ```powershell
    # Define variables for Flex and Bison
    $flexBisonUrl = "https://sourceforge.net/projects/winflexbison/files/win_flex_bison3-latest.zip/download"
    $downloadPath = "$env:TEMP\win_flex_bison.zip"
    $extractPath = "C:\win_flex_bison"
    $flexExe = "flex.exe"
    $bisonExe = "bison.exe"

    # Step 2: Download and Setup Flex and Bison
    Write-Output "Downloading win_flex_bison..."
    Invoke-WebRequest -Uri $flexBisonUrl -OutFile $downloadPath

    # Create the extract directory if it does not exist
    If (!(Test-Path -Path $extractPath)) {
        New-Item -ItemType Directory -Path $extractPath
    }

    # Extract the zip file
    Write-Output "Extracting win_flex_bison..."
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($downloadPath, $extractPath)

    # Rename the executables
    Write-Output "Renaming executables..."
    Rename-Item "$extractPath\win_flex.exe" "$extractPath\$flexExe" -Force
    Rename-Item "$extractPath\win_bison.exe" "$extractPath\$bisonExe" -Force

    # Add Flex and Bison path to system environment variables
    Write-Output "Adding Flex and Bison path to environment variables..."
    $envPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    If ($envPath -notlike "*$extractPath*") {
        [System.Environment]::SetEnvironmentVariable("Path", "$envPath;$extractPath", "Machine")
        Write-Output "Path updated. Please restart your command prompt to apply changes."
    } else {
        Write-Output "Path already contains the Flex and Bison directory."
    }

    # Cleanup
    Remove-Item $downloadPath

    Write-Output "Flex and Bison setup complete."
    ```

    2. Run the Script: Open PowerShell as administrator.

    ```powershell
    .\setup-flex-bison.ps1
    ```

    3. Restart the command prompt: After the script completes, restart your command prompt or Visual Studio for the changes to take effect.

3. **Create `vcpkg.json` file for the dependencies**

    In the root of your project, create a `vcpkg.json` file with the following content:

    ```json
    {
        "name": "fluent-bit",
        "version": "3.2.0",
        "dependencies": [
            {
                "name": "openssl",
                "default-features": false
            },
            {
                "name": "libyaml",
                "default-features": false
            }
        ],
        "builtin-baseline": "9f5925e81bbcd9c8c34cc7a8bd25e3c557b582b2"
    }
    ```

4. **Install dependencies using `vcpkg`**

    ```bash
    vcpkg install --triplet x64-windows-static
    ```

    You should see output like:

    ```bash
    libyaml:x64-windows-static      0.2.5#5      A C library for parsing and emitting YAML.
    openssl:x64-windows-static      3.3.2#1      OpenSSL is an open source project that provides SSL and TLS.
    ```

5. **Link `vcpkg` with Visual Studio**

    ```bash
    vcpkg integrate install
    ```

6. **Generate the Visual Studio solution of Fluent Bit using CMake**

    ```bash
    cd build
    cmake -G "Visual Studio 17 2022" -DFLB_TESTS_INTERNAL=Off -DFLB_TESTS_RUNTIME=Off -DCMAKE_TOOLCHAIN_FILE="C:/Program Files/Microsoft Visual Studio/2022/Community/VC/vcpkg/scripts/buildsystems/vcpkg.cmake" -DOPENSSL_ROOT_DIR=C:/path/to/your/vcpkg_installed/x64-windows-static -DFLB_LIBYAML_DIR=C:/path/to/your/vcpkg_installed/x64-windows-static ..
    ```

    **Notes**:
    - Replace `C:/path/to/your/vcpkg_installed/x64-windows-static` with the actual path where `vcpkg` installed OpenSSL and LibYAML.
    - When installing with `vcpkg`, you can also specify a different install root using `--x-install-root`.
    - This will generate a Visual Studio solution file, which you can open and compile.

7. **Run the binary build**

    ```bash
    cmake --build . --config Release --parallel 4 --clean-first
    ```

    **Notes**:
    - You can choose to omit the `--parallel` option.
    - The `--clean-first` option will clear cache and start a fresh clean build.

### Valgrind

[Valgrind](https://valgrind.org/) is a tool that will help you detect and diagnose memory issues in your code. It will check for memory leaks and invalid memory accesses.

When you use Valgrind, you should compile Fluent Bit with the following options:

```
$ cmake -DFLB_DEV=On -DFLB_VALGRIND=On ../
$ make
```

To use it while developing, invoke it before Fluent Bit:

```shell
valgrind ./bin/fluent-bit {args for fluent bit}
```

Valgrind becomes especially powerful when you run it on your unit tests. We recommend writing unit tests that cover a large fraction of code paths in your contribution. You can then check your code for memory issues by invoking the test binaries with Valgrind:

```shell
valgrind ./bin/flb-rt-your-test
```

This will allow you to check for memory issues in code paths (ex error cases) which are hard to trigger through manual testing.

See above for using the `run_code_analysis.sh` script as well to run Valgrind on unit tests with the simple tooling in a container:

```shell
$ export TEST_PRESET=valgrind
$ ./run_code_analysis.sh
...
```

## Need more help?

The best way to learn how Fluent Bit code works is to read it. If you need help understanding the code, reach out to the community, or open a PR with changes that are a work in progress.
