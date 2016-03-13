# Library API

[Fluent Bit](http://fluentbit.io) library it's written in C language and can be used from any C or C++ application. Before to digging into the specification is recommended to understand the workflow involved in the runtime.

## Workflow

[Fluent Bit](http://fluentbit.io) runs as a service, meaning that the API exposed for developers provide interfaces to create and manage a context, specify inputs/outputs, set configuration parameters and set routing paths for the event/records. A typical usage of the library involves:

- Create library instance/context.
- Enable _input_ plugin(s) instances and set properties.
- Enable _output_ plugin(s) instances and set properties.
- Start the library runtime.
- Optionally ingest records manually.
- Stop the library runtime.
- Destroy library instance/context.

## Data Types

There are three main data types exposed by the library. All of them including further functions are prefixed with __flb\___. The following table describes them:


| Type    | Description          |
|--------------|----------------------|
| flb_ctx_t    | Main library context. It aim to reference the context returned by _flb\_create();_|
| flb_input_t  | Reference an enabled _input_ plugin instance. Used to store the output of _flb\_input(...);_ function. |
| flb_output_t | Reference an enabled _output_ plugin instance. Used to store the output of _flb\_output(...);_ function. |

## API Reference

### Library Context Creation

As described earlier, the first step to use the library is to create a context of it, for the purpose the function __flb_create()__ is used.

__Prototype__

```C
flb_ctx_t *flb_create();
```


__Return Value__

On success, __flb_create()__ returns the library context; on error, it returns NULL.

__Usage__

```C
flb_ctx_t *ctx;

ctx = flb_create();
if (!ctx) {
    return NULL;
}
```

### Enable Input Plugin Instance

When built, [Fluent Bit](http://fluentbit.io) library contains a certain number of built-in _input_ plugins. In order to enable an _input_ plugin, the function __flb_input__() is used to create an instance of it.

> For plugins, an _instance_ means a context of the plugin enabled. You can create multiples instances of the same plugin.

__Prototype__

```C
flb_input_t *flb_input(flb_ctx_t *ctx, char *name, void *data);
```

The argument __ctx__ represents the library context created by __flb_create()__, then __name__ is the name of the input plugin that is required to enable.

The third argument __data__ can be used to pass a custom reference to the plugin instance, this is mostly used by custom or third party plugins, for generic plugins passing _NULL_ is OK.

__Return Value__

On success, __flb_input()__ returns the input plugin instance; on error, it returns NULL.

__Usage__

```C
flb_input_t *in;

in = flb_input(ctx, "cpu", NULL);
```

### Set Input Plugin Properties

A plugin instance created through __flb_input()__, may provide some configuration properties. Using the __flb_input_set()__ function is possible to set these properties.

__Prototype__

```C
int flb_input_set(flb_input_t *in, ...);
```

__Return Value__

On success it returns 0; on error it returns a negative number.

__Usage__

The __flb_input_set()__ allow to set one or more properties in a key/value string mode, e.g:

```C
int ret;

ret = flb_input_set(in,
                    "tag", "my_records",
                    "ssl", "false",
                    NULL);
```

The above example specified the values for the properties __tag__ and __ssl__, note that the value is always a string (char *) and once there is no more parameters a NULL argument must be added at the end of the list.

The properties allowed per input plugin are specified on each specific plugin documentation.

### Enable Output Plugin Instance

When built, [Fluent Bit](http://fluentbit.io) library contains a certain number of built-in _output_ plugins. In order to enable an _output_ plugin, the function __flb_output__() is used to create an instance of it.

> For plugins, an _instance_ means a context of the plugin enabled. You can create multiples instances of the same plugin.

__Prototype__

```C
flb_output_t *flb_output(flb_ctx_t *ctx, char *name, void *data);
```

The argument __ctx__ represents the library context created by __flb_create()__, then __name__ is the name of the output plugin that is required to enable.

The third argument __data__ can be used to pass a custom reference to the plugin instance, this is mostly used by custom or third party plugins, for generic plugins passing _NULL_ is OK.

__Return Value__

On success, __flb_output()__ returns the output plugin instance; on error, it returns NULL.

__Usage__

```C
flb_output_t *out;

out = flb_output(ctx, "stdout", NULL);
```

### Set Output Plugin Properties

A plugin instance created through __flb_output()__, may provide some configuration properties. Using the __flb_output_set()__ function is possible to set these properties.

__Prototype__

```C
int flb_output_set(flb_output_t *in, ...);
```

__Return Value__

On success it returns 0; on error it returns a negative number.

__Usage__

The __flb_output_set()__ allow to set one or more properties in a key/value string mode, e.g:

```C
int ret;

ret = flb_output_set(in,
                    "tag", "my_records",
                    "ssl", "false",
                    NULL);
```

The above example specified the values for the properties __tag__ and __ssl__, note that the value is always a string (char *) and once there is no more parameters a NULL argument must be added at the end of the list.

The properties allowed per output plugin are specified on each specific plugin documentation.

## Start Fluent Bit Engine

Once the library context have been created and the input/output plugin instances are set, the next step is to start the engine. When started, the engine runs inside a new thread (POSIX thread) without blocking the caller application. To start the engine the function __flb_start()__ is used.

__Prototype__

```C
int flb_start(flb_ctx_t *ctx);
```

__Return Value__

On success it returns 0; on error it returns a negative number.

__Usage__

This simple call only needs as argument __ctx__ which is the reference to the context created at the beginning with __flb_create()__:

```C
int ret;

ret = flb_start(ctx);
```

## Stop Fluent Bit Engine

To stop a running Fluent Bit engine, we provide the call __flb_stop()__ for that purpose.

__Prototype__

```C
int flb_stop(flb_ctx_t *ctx);
```

The argument __ctx__ is a reference to the context created at the beginnning with __flb_create()__ and previously started with __flb_start()__.

When the call is invoked, the engine will wait a maximum of five seconds to flush buffers and release the resources in use. A stopped context can be re-started any time but without any data on it.

__Return Value__

On success it returns 0; on error it returns a negative number.

__Usage__

```C
int ret;

ret = flb_stop(ctx);
```

## Destroy Library Context

A library context must be destroyed after is not longer necessary, note that a previous __flb_stop()__ call is mandatory. When destroyed all resources associated are released.

__Prototype__

```C
void flb_destroy(flb_ctx_t *ctx);
```

The argument __ctx__ is a reference to the context created at the beginnning with __flb_create()__.

__Return Value__

No return value.

__Usage__

```C
flb_destroy(ctx);
```

## Ingest Data Manually

There are some cases where the caller application may want to ingest data into Fluent Bit, for this purpose exists the function __flb_lib_push()__.

__Prototype__

```C
int flb_lib_push(flb_input_t *input, void *data, size_t len);
```

The first argument __input__ is a reference to an input instance of the __lib__ plugin, __data__ is a reference to the message to be ingested and __len__ the number of bytes to take from it.

__Return Value__

On success, it returns the number of bytes written; on error it returns -1.

__Usage__

For more details and an example about how to use this function properly please refer to the next section [Ingest Records Manually](ingest_records_manually.md).
