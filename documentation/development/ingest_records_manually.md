# Ingest Records Manually

There are some cases where Fluent Bit library is used to send records from the caller application to some destination, this process is called _manual data ingestion_.

For this purpose a specific input plugin called __lib__ exists and can be using in conjunction with the __flb_lib_push()__ API function.

## Data Format

The __lib__ input plugin expect the data comes in a fixed JSON format as follows:

```
[UNIX_TIMESTAMP, MAP]
```

Every record must be a JSON array that contains at least two entries. The first one is the _UNIX\_TIMESTAMP_ which is a number representing time associated to the event generation (Epoch time) and the second entry is a JSON map with a list of key/values. A valid entry can be the following:

```json
[1449505010, {"key1": "some value", "key2": false}]
```

## Usage

The following C code snippet shows how to insert a few JSON records into a running Fluent Bit engine:

```C
#include <fluent-bit.h>

#define JSON_1   "[1449505010, {\"key1\": \"some value\"}]"
#define JSON_2   "[1449505620, {\"key1\": \"some new value\"}]"

int main()
{
    int ret;
    flb_ctx_t *ctx;
    flb_input_t *in;
    flb_output_t *out;

    /* Create library context */
    ctx = flb_create();
    if (!ctx) {
        return -1;
    }

    /* Enable the input plugin for manual data ingestion */
    in = flb_input(ctx, "lib", NULL);
    if (!in) {
        flb_destroy(ctx);
        return -1;
    }

    /* Enable output plugin 'stdout' (print records to the standard output) */
    out = flb_output(ctx, "stdout", NULL);
    if (!out) {
        flb_destroy(ctx);
        return -1;
    }

    /* Start the engine */
    ret = flb_start(ctx);
    if (ret == -1) {
        flb_destroy(ctx);
        return -1;
    }

    /* Ingest data manually */
    flb_lib_push(in, JSON_1, sizeof(JSON_1) - 1);
    flb_lib_push(in, JSON_2, sizeof(JSON_2) - 1);

    /* Stop the engine (5 seconds to flush remaining data) */
    flb_stop(ctx);

    /* Destroy library context, release all resources */
    flb_destroy(ctx);

    return 0;
}
```
