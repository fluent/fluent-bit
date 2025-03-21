#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>
#include <msgpack.h>
#include "flb_fuzz_header.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Limit size to 32KB */
    if (size > 32768 || size < 6) {
        return 0;
    }

    char *outbuf = NULL;
    char *ra_str = NULL;
    size_t outsize;
    int type;
    int len;
    size_t off = 0;
    msgpack_object map;

    /* Set flb_malloc_mod to be fuzzer-data dependent */
    flb_malloc_p = 0;
    flb_malloc_mod = *(int*)data;
    data += 4;
    size -= 4;

    /* Avoid division by zero for modulo operations */
    if (flb_malloc_mod == 0) {
        flb_malloc_mod = 1;
    }

    if (size < 100) {
       return 0;
    }

    struct flb_record_accessor *ra = NULL;
    
    /* Sample JSON message */
    len = 60;
    char *json_raw = get_null_terminated(len, &data, &size);

    /* Convert to msgpack */
    int ret = flb_pack_json(json_raw, len, &outbuf, &outsize, &type, NULL);
    if (ret == -1) {
        flb_free(json_raw);
        return 0;
    }
    flb_free(json_raw);

    char *null_terminated = get_null_terminated(size, &data, &size);

    ra_str = flb_sds_create(null_terminated);
    if (ra_str != NULL) {
        ra = flb_ra_create(ra_str, FLB_FALSE);
        if (!ra) {
            flb_sds_destroy(ra_str);
            flb_free(null_terminated);
            flb_free(outbuf);
            return 0;
        }

        flb_ra_is_static(ra);

        msgpack_unpacked result;
        msgpack_unpacked_init(&result);
        msgpack_unpack_next(&result, outbuf, outsize, &off);
        map = result.data;

        flb_sds_t str = flb_ra_translate(ra, NULL, -1, map, NULL);
        if (!str) {
            flb_ra_destroy(ra);
            flb_sds_destroy(ra_str);
            msgpack_unpacked_destroy(&result);

            /* General cleanup */
            flb_free(null_terminated);
            flb_free(outbuf);
            return 0;
        }
        flb_ra_dump(ra);


        flb_sds_destroy(str);
        flb_ra_destroy(ra);
        flb_sds_destroy(ra_str);
        msgpack_unpacked_destroy(&result);
    }

    if (outbuf != NULL) {
        flb_free(outbuf);
    }
    if (null_terminated != NULL) {
        flb_free(null_terminated);
    }
    return 0;
}
