/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <cmetrics/cmt_mpack_utils.h>
#include <mpack/mpack.h>

int cmt_mpack_consume_double_tag(mpack_reader_t *reader, double *output_buffer)
{
    mpack_tag_t tag;

    if (NULL == output_buffer) {
        return CMT_MPACK_INVALID_ARGUMENT_ERROR;
    }

    if (NULL == reader) {
        return CMT_MPACK_INVALID_ARGUMENT_ERROR;
    }

    tag = mpack_read_tag(reader);

    if (mpack_ok != mpack_reader_error(reader)) {
        return CMT_MPACK_ENGINE_ERROR;
    }

    if (mpack_type_double != mpack_tag_type(&tag)) {
        return CMT_MPACK_UNEXPECTED_DATA_TYPE_ERROR;
    }

    *output_buffer = mpack_tag_double_value(&tag);

    return CMT_MPACK_SUCCESS;
}

int cmt_mpack_consume_uint_tag(mpack_reader_t *reader, uint64_t *output_buffer)
{
    mpack_tag_t tag;

    if (NULL == output_buffer) {
        return CMT_MPACK_INVALID_ARGUMENT_ERROR;
    }

    if (NULL == reader) {
        return CMT_MPACK_INVALID_ARGUMENT_ERROR;
    }

    tag = mpack_read_tag(reader);

    if (mpack_ok != mpack_reader_error(reader)) {
        return CMT_MPACK_ENGINE_ERROR;
    }

    if (mpack_type_uint != mpack_tag_type(&tag)) {
        return CMT_MPACK_UNEXPECTED_DATA_TYPE_ERROR;
    }

    *output_buffer = mpack_tag_uint_value(&tag);

    return CMT_MPACK_SUCCESS;
}

int cmt_mpack_consume_string_tag(mpack_reader_t *reader, cfl_sds_t *output_buffer)
{
    uint32_t    string_length;
    mpack_tag_t tag;

    if (NULL == output_buffer) {
        return CMT_MPACK_INVALID_ARGUMENT_ERROR;
    }

    if (NULL == reader) {
        return CMT_MPACK_INVALID_ARGUMENT_ERROR;
    }

    tag = mpack_read_tag(reader);

    if (mpack_ok != mpack_reader_error(reader)) {
        return CMT_MPACK_ENGINE_ERROR;
    }

    if (mpack_type_str != mpack_tag_type(&tag)) {
        return CMT_MPACK_UNEXPECTED_DATA_TYPE_ERROR;
    }

    string_length = mpack_tag_str_length(&tag);

    /* This validation only applies to cmetrics and its use cases, we know
     * for a fact that our label names and values are not supposed to be really
     * long so a huge value here probably means that the data stream got corrupted.
     */

    if (CMT_MPACK_MAX_STRING_LENGTH < string_length) {
        return CMT_MPACK_CORRUPT_INPUT_DATA_ERROR;
    }

    *output_buffer = cfl_sds_create_size(string_length + 1);

    if (NULL == *output_buffer) {
        return CMT_MPACK_ALLOCATION_ERROR;
    }

    cfl_sds_set_len(*output_buffer, string_length);

    mpack_read_cstr(reader, *output_buffer, string_length + 1, string_length);

    if (mpack_ok != mpack_reader_error(reader)) {
        cfl_sds_destroy(*output_buffer);

        *output_buffer = NULL;

        return CMT_MPACK_ENGINE_ERROR;
    }

    mpack_done_str(reader);

    if (mpack_ok != mpack_reader_error(reader)) {
        cfl_sds_destroy(*output_buffer);

        *output_buffer = NULL;

        return CMT_MPACK_ENGINE_ERROR;
    }

    return CMT_MPACK_SUCCESS;
}

int cmt_mpack_unpack_map(mpack_reader_t *reader,
                         struct cmt_mpack_map_entry_callback_t *callback_list,
                         void *context)
{
    struct cmt_mpack_map_entry_callback_t *callback_entry;
    uint32_t                               entry_index;
    uint32_t                               entry_count;
    cfl_sds_t                              key_name;
    int                                    result;
    mpack_tag_t                            tag;

    tag = mpack_read_tag(reader);

    if (mpack_ok != mpack_reader_error(reader)) {
        return CMT_MPACK_ENGINE_ERROR;
    }

    if (mpack_type_map != mpack_tag_type(&tag)) {
        return CMT_MPACK_UNEXPECTED_DATA_TYPE_ERROR;
    }

    entry_count = mpack_tag_map_count(&tag);

    /* This validation only applies to cmetrics and its use cases, we know
     * how our schema looks and how many entries the different fields have and none
     * of those exceed the number we set CMT_MPACK_MAX_MAP_ENTRY_COUNT to which is 10.
     * Making these sanity checks optional or configurable in runtime might be worth
     * the itme and complexity cost but that's something I don't know at the moment.
     */

    if (CMT_MPACK_MAX_MAP_ENTRY_COUNT < entry_count) {
        return CMT_MPACK_CORRUPT_INPUT_DATA_ERROR;
    }

    result = 0;

    for (entry_index = 0 ; 0 == result && entry_index < entry_count ; entry_index++) {
        result = cmt_mpack_consume_string_tag(reader, &key_name);

        if (CMT_MPACK_SUCCESS == result) {
            callback_entry = callback_list;
            result = CMT_MPACK_UNEXPECTED_KEY_ERROR;

            while (CMT_MPACK_UNEXPECTED_KEY_ERROR == result &&
                   NULL != callback_entry->identifier) {

                if (0 == strcmp(callback_entry->identifier, key_name)) {
                    result = callback_entry->handler(reader, entry_index, context);
                }

                callback_entry++;
            }

            cfl_sds_destroy(key_name);
        }
    }

    if (CMT_MPACK_SUCCESS == result) {
        mpack_done_map(reader);

        if (mpack_ok != mpack_reader_error(reader))
        {
            return CMT_MPACK_PENDING_MAP_ENTRIES;
        }
    }

    return result;
}

int cmt_mpack_unpack_array(mpack_reader_t *reader,
                           cmt_mpack_unpacker_entry_callback_fn_t entry_processor_callback,
                           void *context)
{
    uint32_t              entry_index;
    uint32_t              entry_count;
    mpack_tag_t           tag;
    int                   result;

    tag = mpack_read_tag(reader);

    if (mpack_ok != mpack_reader_error(reader))
    {
        return CMT_MPACK_ENGINE_ERROR;
    }

    if (mpack_type_array != mpack_tag_type(&tag)) {
        return CMT_MPACK_UNEXPECTED_DATA_TYPE_ERROR;
    }

    entry_count = mpack_tag_array_count(&tag);

    /* This validation only applies to cmetrics and its use cases, we know
     * that in our schema we have the following arrays :
     *     label text dictionary (strings)
     *     dimension labels (indexes)
     *     metric values
     *         dimension values
     *
     * IMO none of these arrays should be huge so I think using 65535 as a limit
     * gives us more than enough wiggle space (in reality I don't expect any of these
     * arrays to hold more than 128 values but I could be wrong as that probably depends
     * on the flush interval)
     */

    if (CMT_MPACK_MAX_ARRAY_ENTRY_COUNT < entry_count) {
        return CMT_MPACK_CORRUPT_INPUT_DATA_ERROR;
    }

    result = CMT_MPACK_SUCCESS;

    for (entry_index = 0 ;
         CMT_MPACK_SUCCESS == result && entry_index < entry_count ;
         entry_index++) {
        result = entry_processor_callback(reader, entry_index, context);
    }

    if (CMT_MPACK_SUCCESS == result) {
        mpack_done_array(reader);

        if (mpack_ok != mpack_reader_error(reader))
        {
            return CMT_MPACK_PENDING_ARRAY_ENTRIES;
        }
    }

    return result;
}

int cmt_mpack_peek_array_length(mpack_reader_t *reader)
{
    mpack_tag_t tag;

    tag = mpack_peek_tag(reader);

    if (mpack_ok != mpack_reader_error(reader))
    {
        return 0;
    }

    if (mpack_type_array != mpack_tag_type(&tag)) {
        return 0;
    }

    return mpack_tag_array_count(&tag);
}
