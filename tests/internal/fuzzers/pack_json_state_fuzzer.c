#include <stdint.h>
#include <stdlib.h>
#include <fluent-bit/flb_pack.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    int out_size= 0;
    char *out_buf = NULL;
    struct flb_pack_state state;

    /* Target json packer */
    flb_pack_state_init(&state);
    flb_pack_json_state(data, size, &out_buf, &out_size, &state);
    flb_pack_state_reset(&state);
    if (out_buf != NULL)
        flb_free(out_buf);

    return 0;
}
