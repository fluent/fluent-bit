#include <stdint.h>
#include <string.h>
#include <msgpack.h>
#include <fluent-bit/flb_pack.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    /* Set fuzzer-malloc chance of failure */
    flb_malloc_mod = 25000;
    flb_malloc_p = 0;
    if (size != 512)
        return 0;

    /* Target the conversion of raw msgpack to gelf */
    flb_sds_t record;
    struct flb_time tm = {0};
    struct flb_gelf_fields fields = {0};
    fields.short_message_key = flb_sds_create("AAAAAAAAAA");
    record = flb_msgpack_raw_to_gelf((char*)data, size, &tm, &fields);

    /* cleanup */
    flb_sds_destroy(record);
    flb_sds_destroy(fields.short_message_key);

    return 0;
}
