#include <fluent-bit/flb_http_retry_after.h>

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint64_t delay_ms;
    size_t invalid_count;

    flb_http_retry_after_parse((const char *) data, size, 0, &delay_ms);
    flb_http_retry_after_parse_headers((const char *) data, size, 0,
                                       &delay_ms, &invalid_count);

    return 0;
}
