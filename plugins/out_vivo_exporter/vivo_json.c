/* Fluent Bit - Copyright (C) 2015-2026 The Fluent Bit Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_base64.h>

#include <math.h>

#include "vivo.h"

/* Preserve extension type and bytes without the generic encoder's invalid \x escapes. */
static int pack_extension(msgpack_packer *packer, msgpack_object *value)
{
    unsigned char *encoded;
    size_t capacity;
    size_t length;
    int result;

    capacity = ((size_t) value->via.ext.size + 2) / 3 * 4 + 1;
    encoded = flb_malloc(capacity);
    if (!encoded) {
        return -1;
    }
    result = flb_base64_encode(encoded, capacity, &length,
                               (const unsigned char *) value->via.ext.ptr, value->via.ext.size);
    if (result == 0) {
        result = msgpack_pack_map(packer, 3) ||
                 msgpack_pack_str_with_body(packer, "fluentbit.type", sizeof("fluentbit.type") - 1) ||
                 msgpack_pack_str_with_body(packer, "msgpack.ext", sizeof("msgpack.ext") - 1) ||
                 msgpack_pack_str_with_body(packer, "fluentbit.ext_type", sizeof("fluentbit.ext_type") - 1) ||
                 msgpack_pack_int(packer, value->via.ext.type) ||
                 msgpack_pack_str_with_body(packer, "fluentbit.value", sizeof("fluentbit.value") - 1) ||
                 msgpack_pack_str_with_body(packer, encoded, length);
    }
    flb_free(encoded);
    return result;
}

/* Repack recursively so numeric text lives in the owned output buffer. */
static int pack_value(msgpack_packer *packer, msgpack_object *value)
{
    size_t index;
    int length;
    const char *special;

    if (value->type == MSGPACK_OBJECT_MAP) {
        if (msgpack_pack_map(packer, value->via.map.size) != 0) {
            return -1;
        }
        for (index = 0; index < value->via.map.size; index++) {
            if (pack_value(packer, &value->via.map.ptr[index].key) != 0 ||
                pack_value(packer, &value->via.map.ptr[index].val) != 0) {
                return -1;
            }
        }
        return 0;
    }
    if (value->type == MSGPACK_OBJECT_ARRAY) {
        if (msgpack_pack_array(packer, value->via.array.size) != 0) {
            return -1;
        }
        for (index = 0; index < value->via.array.size; index++) {
            if (pack_value(packer, &value->via.array.ptr[index]) != 0) {
                return -1;
            }
        }
        return 0;
    }
    if ((value->type == MSGPACK_OBJECT_FLOAT32 || value->type == MSGPACK_OBJECT_FLOAT64) &&
        !isfinite(value->via.f64)) {
        special = isnan(value->via.f64) ? "NaN" :
                  (value->via.f64 < 0 ? "-Infinity" : "Infinity");
        length = strlen(special);
        if (msgpack_pack_str(packer, length) != 0) {
            return -1;
        }
        return msgpack_pack_str_body(packer, special, length);
    }
    if (value->type == MSGPACK_OBJECT_EXT) {
        return pack_extension(packer, value);
    }
    return msgpack_pack_object(packer, *value);
}

flb_sds_t vivo_json(const void *data, size_t size, int escape_unicode)
{
    msgpack_unpacked unpacked;
    msgpack_sbuffer buffer;
    msgpack_packer packer;
    size_t offset = 0;
    flb_sds_t json = NULL;

    msgpack_unpacked_init(&unpacked);
    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);
    if (msgpack_unpack_next(&unpacked, data, size, &offset) == MSGPACK_UNPACK_SUCCESS &&
        offset == size && pack_value(&packer, &unpacked.data) == 0) {
        json = flb_msgpack_raw_to_json_sds(buffer.data, buffer.size, escape_unicode);
    }
    msgpack_sbuffer_destroy(&buffer);
    msgpack_unpacked_destroy(&unpacked);
    return json;
}
