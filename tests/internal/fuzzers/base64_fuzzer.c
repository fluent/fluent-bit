#include <unistd.h>
#include <stdint.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_mem.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char out[100];
    size_t olen;

    /* Set fuzzer-malloc chance of failure */
    flb_malloc_p = 0;
    flb_malloc_mod = 25000;

    flb_base64_encode((unsigned char *) out, 100,
                      &olen, (unsigned char *)data, size);
    flb_base64_decode((unsigned char *) out, 100,
                      &olen, (unsigned char *)data, size);
    return 0;
}
