#include <stdint.h>
#include <stdlib.h>
#include <msgpack.h>
#include <fluent-bit/flb_pack.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    flb_malloc_p = 0;
    if (size != 512)
        return 0;

    /* target the conversion of raw msgpack to json */
    flb_sds_t record;
    record = flb_msgpack_raw_to_json_sds(data, size);
    flb_sds_destroy(record);

    return 0;
}
