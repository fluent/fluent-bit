#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_parser.h>
#include <msgpack.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_strptime.h>

#include "flb_fuzz_header.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 40) {
        return 0;
    }

    /* Set fuzzer-malloc chance of failure */
    flb_malloc_mod = 25000;
    flb_malloc_p = 0;

    char *fmt = get_null_terminated(size - 30, &data, &size);
    char *buf = get_null_terminated(size, &data, &size);

    struct tm tt;
    flb_strptime(buf, fmt, &tt);

    flb_free(buf);
    flb_free(fmt);
    return 0;
}
