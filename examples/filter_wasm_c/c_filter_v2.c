/* SPDX-License-Identifier: Apache-2.0 */
#include <stdint.h>

/* Value is a wasm32 linear-memory offset; length excludes any NUL terminator. */
static uint64_t value_length(const char *value, uint32_t length)
{
    return ((uint64_t) length << 32) | (uint32_t) (uintptr_t) value;
}

/* Return the original body as a value-length pair. */
uint64_t c_filter_v2(const char *tag, uint32_t tag_length,
                     uint32_t seconds, uint32_t nanoseconds,
                     const char *record, uint32_t record_length)
{
    /* Borrowed input: Fluent Bit copies this before releasing the buffer. */
    return value_length(record, record_length);
}
