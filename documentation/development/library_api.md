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
