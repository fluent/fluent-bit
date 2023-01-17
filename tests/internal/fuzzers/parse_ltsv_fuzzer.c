#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_parser.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    struct flb_config *fuzz_config;
    struct flb_parser *fuzz_parser;

    /* Set fuzzer-malloc chance of failure */
    flb_malloc_mod = 25000;
    flb_malloc_p = 0;

    /* ltsvc parser */
    fuzz_config = flb_config_init();
    fuzz_parser = flb_parser_create("fuzzer", "ltsv", NULL, FLB_TRUE,
                                    NULL, NULL, NULL, MK_FALSE, 
                                    MK_TRUE, FLB_FALSE, NULL, 0, NULL,
                                    fuzz_config);
    flb_parser_do(fuzz_parser, (char*)data, size,
                  &out_buf, &out_size, &out_time);

    if (out_buf != NULL) {
        free(out_buf);
    }

    flb_parser_destroy(fuzz_parser);
    flb_config_exit(fuzz_config);

    return 0;
}
