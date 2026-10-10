/* SPDX-License-Identifier: Apache-2.0 */
#include <stdint.h>

/* No libc or allocator required: output borrows input or static storage. */
static uint64_t value_length(const void *value, uint32_t length)
{
    return ((uint64_t) length << 32) | (uint32_t) (uintptr_t) value;
}

#define ARGS const char *tag, uint32_t tag_len, uint32_t sec, uint32_t nsec, \
             const char *record, uint32_t record_len

uint64_t record_value(ARGS)
{
    if (tag_len != 9 || tag[0] != 't' || tag[8] != 'm' || tag[tag_len] != 0 ||
        sec != 123 || nsec != 0 || record[record_len] != 0) {
        __builtin_trap();
    }
    return value_length(record, record_len);
}

uint64_t binary_value(ARGS)
{
    static const unsigned char body[] = {0x82, 0xa1, 'n', 0, 0xa1, 's', 0xa3, 'a', 0, 'b'};
    return value_length(body, sizeof(body));
}

uint64_t json_value(ARGS)
{
    /* No NUL terminator: bytes after the declared length must be ignored. */
    static const char body[] = {'{', '"', 'n', '"', ':', '0', '}', '!'};
    return value_length(body, sizeof(body) - 1);
}

uint64_t drop_value(ARGS)
{
    return 0;
}

uint64_t invalid_value(ARGS)
{
    return ((uint64_t) 16 << 32) | 0xfffffff0;
}

uint64_t invalid_length(ARGS)
{
    return value_length(record, UINT32_MAX);
}

uint64_t null_value(ARGS)
{
    return (uint64_t) 10 << 32;
}

uint64_t empty_value(ARGS)
{
    return value_length(record, 0);
}

uint64_t trap_value(ARGS)
{
    __builtin_trap();
}

uint64_t malformed_value(ARGS)
{
    static const char body[] = "not a map";
    return value_length(body, sizeof(body) - 1);
}

uint32_t wrong_result(ARGS)
{
    return 0;
}

uint64_t wrong_arguments(void)
{
    return 0;
}

uint64_t grow_value(ARGS)
{
    __builtin_wasm_memory_grow(0, 1);
    return json_value(tag, tag_len, sec, nsec, record, record_len);
}

uint64_t multiple_values(ARGS)
{
    static const char body[] = "{}{}";
    return value_length(body, sizeof(body) - 1);
}

uint64_t array_value(ARGS)
{
    static const char body[] = "[]";
    return value_length(body, sizeof(body) - 1);
}
