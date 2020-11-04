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
    char *outbuf;
    size_t outsize;
    int type;
    int len;
    char *json;
    size_t off = 0;
    msgpack_object map;

    if (size < 100) {
       return 0;
    }

    struct flb_record_accessor *ra = NULL;
    
    /* Sample JSON message */
    json ="{\"key1\": \"something\", \"kubernetes\": {\"annotations\": {\"fluentbit.io/tag\": \"thetag\"}}}";

    /* Convert to msgpack */
    len = strlen(json);
    int ret = flb_pack_json(json, len, &outbuf, &outsize, &type);
    if (ret == -1) {
        return 0;
    }

    char *null_terminated = get_null_terminated(size, &data, &size);

    char *ra_str = flb_sds_create(null_terminated);
    ra = flb_ra_create(ra_str, FLB_FALSE);
    if (!ra) {
        flb_free(null_terminated);
        return 0;
    }

    msgpack_unpacked result;
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, outbuf, outsize, &off);
    map = result.data;

    flb_sds_t str = flb_ra_translate(ra, NULL, -1, map, NULL);
    if (!str) {
        flb_ra_destroy(ra);
        flb_sds_destroy(ra_str);

        /* General cleanup */
        flb_free(null_terminated);
        return 0;
    }

    flb_sds_destroy(str);
    flb_ra_destroy(ra);
    flb_sds_destroy(ra_str);

    /* General cleanup */
    flb_free(null_terminated);
    return 0;
}