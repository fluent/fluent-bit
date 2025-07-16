/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_sds.h>

#include "we.h"
#include "we_util.h"
#include "we_metric.h"
#include "we_perflib.h"

double we_perflib_get_adjusted_counter_value(struct we_perflib_counter *counter)
{
    double result;

    result = (double) counter->primary_value.as_qword;

    switch(counter->definition->type) {
        case PERF_ELAPSED_TIME:
            result -= counter->parent->parent->time;
            result /= counter->parent->parent->frequency;
            break;

        case PERF_100NSEC_TIMER:
        case PERF_PRECISION_100NS_TIMER:
            result /= counter->parent->parent->frequency;
            break;
    }

    return result;
}

char *we_perflib_get_counter_type_as_text(uint32_t counter_Type)
{
    switch (counter_Type) {
        case PERF_100NSEC_TIMER:
            return "PERF_100NSEC_TIMER";
        case PERF_100NSEC_TIMER_INV:
            return "PERF_100NSEC_TIMER_INV";
        case PERF_100NSEC_MULTI_TIMER:
            return "PERF_100NSEC_MULTI_TIMER";
        case PERF_100NSEC_MULTI_TIMER_INV:
            return "PERF_100NSEC_MULTI_TIMER_INV";
        case PERF_AVERAGE_BASE:
            return "PERF_AVERAGE_BASE";
        case PERF_AVERAGE_BULK:
            return "PERF_AVERAGE_BULK";
        case PERF_AVERAGE_TIMER:
            return "PERF_AVERAGE_TIMER";
        case PERF_COUNTER_100NS_QUEUELEN_TYPE:
            return "PERF_COUNTER_100NS_QUEUELEN_TYPE";
        case PERF_COUNTER_BULK_COUNT:
            return "PERF_COUNTER_BULK_COUNT";
        case PERF_COUNTER_COUNTER:
            return "PERF_COUNTER_COUNTER";
        case PERF_COUNTER_DELTA:
            return "PERF_COUNTER_DELTA";
        case PERF_COUNTER_HISTOGRAM_TYPE:
            return "PERF_COUNTER_HISTOGRAM_TYPE";
        case PERF_COUNTER_LARGE_DELTA:
            return "PERF_COUNTER_LARGE_DELTA";
        case PERF_COUNTER_LARGE_QUEUELEN_TYPE:
            return "PERF_COUNTER_LARGE_QUEUELEN_TYPE";
        case PERF_COUNTER_LARGE_RAWCOUNT:
            return "PERF_COUNTER_LARGE_RAWCOUNT";
        case PERF_COUNTER_LARGE_RAWCOUNT_HEX:
            return "PERF_COUNTER_LARGE_RAWCOUNT_HEX";
        case PERF_COUNTER_MULTI_BASE:
            return "PERF_COUNTER_MULTI_BASE";
        case PERF_COUNTER_MULTI_TIMER:
            return "PERF_COUNTER_MULTI_TIMER";
        case PERF_COUNTER_MULTI_TIMER_INV:
            return "PERF_COUNTER_MULTI_TIMER_INV";
        case PERF_COUNTER_NODATA:
            return "PERF_COUNTER_NODATA";
        case PERF_COUNTER_OBJ_TIME_QUEUELEN_TYPE:
            return "PERF_COUNTER_OBJ_TIME_QUEUELEN_TYPE";
        case PERF_COUNTER_QUEUELEN_TYPE:
            return "PERF_COUNTER_QUEUELEN_TYPE";
        case PERF_COUNTER_RAWCOUNT:
            return "PERF_COUNTER_RAWCOUNT";
        case PERF_COUNTER_RAWCOUNT_HEX:
            return "PERF_COUNTER_RAWCOUNT_HEX";
        case PERF_COUNTER_TEXT:
            return "PERF_COUNTER_TEXT";
        case PERF_COUNTER_TIMER:
            return "PERF_COUNTER_TIMER";
        case PERF_COUNTER_TIMER_INV:
            return "PERF_COUNTER_TIMER_INV";
        case PERF_ELAPSED_TIME:
            return "PERF_ELAPSED_TIME";
        case PERF_LARGE_RAW_BASE:
            return "PERF_LARGE_RAW_BASE";
        case PERF_LARGE_RAW_FRACTION:
            return "PERF_LARGE_RAW_FRACTION";
        case PERF_OBJ_TIME_TIMER:
            return "PERF_OBJ_TIME_TIMER";
        case PERF_PRECISION_100NS_TIMER:
            return "PERF_PRECISION_100NS_TIMER";
        case PERF_PRECISION_OBJECT_TIMER:
            return "PERF_PRECISION_OBJECT_TIMER";
        case PERF_PRECISION_SYSTEM_TIMER:
            return "PERF_PRECISION_SYSTEM_TIMER";
        case PERF_RAW_BASE:
            return "PERF_RAW_BASE";
        case PERF_RAW_FRACTION:
            return "PERF_RAW_FRACTION";
        case PERF_SAMPLE_BASE:
            return "PERF_SAMPLE_BASE";
        case PERF_SAMPLE_COUNTER:
            return "PERF_SAMPLE_COUNTER";
        case PERF_SAMPLE_FRACTION:
            return "PERF_SAMPLE_FRACTION";
    };

    return "UNRECOGNIZED_COUNTER_TYPE";
}

void we_perflib_destroy_counter(struct we_perflib_counter *counter)
{
    flb_free(counter);
}

void we_perflib_destroy_instance(struct we_perflib_instance *instance)
{
    struct flb_hash_table_entry *counter_hash_entry;
    struct mk_list            *counter_iterator;
    struct we_perflib_counter *counter;
    struct mk_list            *tmp;

    mk_list_foreach_safe(counter_iterator,
                         tmp,
                         &instance->counters->entries) {
        counter_hash_entry = mk_list_entry(counter_iterator,
                                           struct flb_hash_table_entry,
                                           _head_parent);

        counter = (struct we_perflib_counter *) counter_hash_entry->val;

        we_perflib_destroy_counter(counter);
    }

    if (instance->name != NULL) {
        flb_free(instance->name);
    }

    flb_hash_table_destroy(instance->counters);

    flb_free(instance);
}

void we_perflib_destroy_counter_definition(
        struct we_perflib_counter_definition *definition)
{
    flb_sds_destroy(definition->name_index_str);

    mk_list_del(&definition->_head);

    flb_free(definition);
}

void we_perflib_destroy_object(struct we_perflib_object *object)
{
    struct mk_list                       *definition_iterator;
    struct flb_hash_table_entry          *instance_hash_entry;
    struct mk_list                       *instance_iterator;
    struct we_perflib_counter_definition *definition;
    struct we_perflib_instance           *instance;
    struct mk_list                       *tmp;

    mk_list_foreach_safe(definition_iterator, tmp, &object->counter_definitions) {
        definition = mk_list_entry(definition_iterator,
                                   struct we_perflib_counter_definition,
                                   _head);

        we_perflib_destroy_counter_definition(definition);
    }

    mk_list_foreach_safe(instance_iterator, tmp, &object->instances->entries) {
        instance_hash_entry = mk_list_entry(instance_iterator,
                                            struct flb_hash_table_entry,
                                            _head_parent);

        instance = (struct we_perflib_instance *) instance_hash_entry->val;

        we_perflib_destroy_instance(instance);
    }

    flb_hash_table_destroy(object->instances);

    flb_free(object);
}

static int get_string_list(char *source, flb_sds_t *out_result_buffer)
{
    DWORD     result_buffer_size;
    flb_sds_t result_buffer;
    LSTATUS   result;

    result_buffer = NULL;
    result_buffer_size = 0;

    if (out_result_buffer == NULL) {
        return -1;
    }

    result = RegQueryValueExA(HKEY_PERFORMANCE_TEXT,
                              source,
                              NULL,
                              NULL,
                              NULL,
                              &result_buffer_size);

    if (result != ERROR_SUCCESS) {
        return -2;
    }

    result_buffer = flb_sds_create_size(result_buffer_size);

    if (result_buffer == NULL) {
        return -3;
    }

    result = RegQueryValueExA(HKEY_PERFORMANCE_TEXT,
                              source,
                              NULL,
                              NULL,
                              (LPBYTE) result_buffer,
                              &result_buffer_size);

    if (result != ERROR_SUCCESS)
    {
        flb_sds_destroy(result_buffer);

        return -4;
    }

    *out_result_buffer = result_buffer;

    return 0;
}

static int get_number_of_string_entries(uint32_t *result_count)
{
    DWORD   argument_size;
    DWORD   entry_count;
    HKEY    key_handle;
    LSTATUS result;

    entry_count = 0;
    argument_size = sizeof(DWORD);

    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                           WE_PERFLIB_REGISTRY_PATH,
                           0,
                           KEY_READ,
                           &key_handle);

    if (result != ERROR_SUCCESS) {
        return -1;
    }

    result = RegQueryValueExA(key_handle,
                              WE_PERFLIB_STRING_COUNT_KEY,
                              NULL,
                              0,
                              (LPBYTE) &entry_count,
                              &argument_size);

    RegCloseKey(key_handle);

    if (result != ERROR_SUCCESS) {
        return -2;
    }

    *result_count = (uint32_t) entry_count;

    return 0;
}

static int get_text_mapping_table(struct flb_hash_table **out_mapping_table)
{
    char      *current_counter_string;
    flb_sds_t  counter_strings;
    char      *counter_index;
    char      *counter_name;
    uint32_t   string_count;
    int        result;

    if (out_mapping_table == NULL) {
        return -1;
    }

    result = get_number_of_string_entries(&string_count);

    if (result) {
        return -2;
    }

    result = get_string_list(WE_PERFLIB_COUNTER_KEY_NAME, &counter_strings);

    if (result) {
        return -3;
    }

    *out_mapping_table = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE,
                                               512, string_count * 2);
    if (*out_mapping_table == NULL) {
        flb_sds_destroy(counter_strings);

        return -4;
    }

    current_counter_string = (char *) counter_strings;

    while (1) {
        counter_index = current_counter_string;
        current_counter_string = &current_counter_string[strlen(current_counter_string) + 1];

        if (!current_counter_string[0]) {
            break;
        }

        counter_name = current_counter_string;
        current_counter_string = &current_counter_string[strlen(current_counter_string) + 1];

        if (!current_counter_string[0]) {
            break;
        }

        result = flb_hash_table_add(*out_mapping_table,
                                    counter_name,  strlen(counter_name),
                                    counter_index, strlen(counter_index));

        if (result < 0) {
            flb_sds_destroy(counter_strings);
            flb_hash_table_destroy(*out_mapping_table);

            *out_mapping_table = NULL;

            return -5;
        }

        result = flb_hash_table_add(*out_mapping_table,
                                    counter_index, strlen(counter_index),
                                    counter_name,  strlen(counter_name));

        if (result < 0) {
            flb_sds_destroy(counter_strings);
            flb_hash_table_destroy(*out_mapping_table);

            *out_mapping_table = NULL;

            return -5;
        }
    }

    flb_sds_destroy(counter_strings);

    return 0;
}

int we_perflib_query_raw_data(struct flb_we *ctx, char *source,
                              char **out_buffer, size_t *out_buffer_size)
{
    char   *reallocated_buffer;
    DWORD   buffer_size;
    DWORD   data_size;
    char   *buffer;
    LSTATUS result;

    buffer_size = WE_PERFLIB_QUERY_BUFFER_INITIAL_SIZE;

    result = ERROR_MORE_DATA;

    buffer = (char *) flb_malloc(buffer_size);

    if (buffer == NULL) {
        return -1;
    }

    while (result == ERROR_MORE_DATA) {
        data_size = buffer_size;

        result = RegQueryValueExA(HKEY_PERFORMANCE_DATA,
                                  source,
                                  NULL,
                                  NULL,
                                  buffer,
                                  &data_size);

        RegCloseKey(HKEY_PERFORMANCE_DATA);

        buffer_size += WE_PERFLIB_QUERY_BUFFER_INCREMENT_SIZE;

        reallocated_buffer = (char *) flb_realloc(buffer, buffer_size);

        if (reallocated_buffer == NULL) {
            flb_free(buffer);

            return -2;
        }

        buffer = reallocated_buffer;
    }

    *out_buffer = buffer;
    *out_buffer_size = data_size;

    return 0;
}

static char *we_perflib_lookup_counter_index(struct flb_hash_table *mapping_table,
                                             char *name)
{
    return flb_hash_table_get_ptr(mapping_table,
                                  name,
                                  strlen(name));
}

static char *we_perflib_lookup_counter_name(struct flb_hash_table *mapping_table,
                                            uint32_t index)
{
    char hash_table_index[11];

    sprintf(hash_table_index, "%" PRIu32, index);

    return flb_hash_table_get_ptr(mapping_table,
                                  hash_table_index,
                                  strlen(hash_table_index));
}

static int we_perflib_process_object_type(
                                   struct we_perflib_context *context,
                                   char                      *input_data_block,
                                   struct we_perflib_object **out_perflib_object)
{
    char                     *input_object_block;
    struct we_perflib_object *perflib_object;
    PERF_OBJECT_TYPE         *perf_object;
    PERF_DATA_BLOCK          *perf_data;
    int                       result;

    perf_data = (PERF_DATA_BLOCK *) input_data_block;

    result = wcsncmp(perf_data->Signature, L"PERF", 4);

    if (result) {
        return -1;
    }

    input_object_block = &input_data_block[perf_data->HeaderLength];

    perf_object = (PERF_OBJECT_TYPE *) input_object_block;

    perflib_object = (struct we_perflib_object *) \
                                flb_calloc(1, sizeof(struct we_perflib_object));

    if (perflib_object == NULL) {
        return -2;
    }

    perflib_object->name = we_perflib_lookup_counter_name(
                                            context->counter_indexes,
                                            perf_object->ObjectNameTitleIndex);

    if (perflib_object->name == NULL) {
        flb_free(perflib_object);

        return -3;
    }

    perflib_object->time = perf_data->PerfTime.QuadPart;
    perflib_object->frequency = perf_data->PerfFreq.QuadPart;
    perflib_object->hundred_ns_time = perf_data->PerfTime100nSec.QuadPart;

    perflib_object->counter_count = perf_object->NumCounters;
    perflib_object->instance_count = perf_object->NumInstances;

    perflib_object->total_byte_length = perf_object->TotalByteLength;
    perflib_object->definition_length = perf_object->DefinitionLength;

    perflib_object->instances = flb_hash_table_create(
                                                      FLB_HASH_TABLE_EVICT_NONE,
                                                      64,
                                                      perflib_object->instance_count + 1);

    if (perflib_object->instances == NULL) {
        flb_free(perflib_object);

        return -4;
    }

    mk_list_init(&perflib_object->counter_definitions);

    *out_perflib_object = perflib_object;

    return perf_data->HeaderLength + perf_object->HeaderLength;
}

static int we_perflib_process_counter_definition(
                  struct we_perflib_context             *context,
                  char                                  *input_data_block,
                  struct we_perflib_counter_definition **out_counter_definition)
{
    PERF_COUNTER_DEFINITION              *perf_counter_definition;
    struct we_perflib_counter_definition *counter_definition;
    char                                  name_index_str[12];

    perf_counter_definition = (PERF_COUNTER_DEFINITION *) input_data_block;

    counter_definition = (struct we_perflib_counter_definition *) \
        flb_calloc(1, sizeof(struct we_perflib_counter_definition));

    if (counter_definition == NULL) {
        return -1;
    }

    counter_definition->name_index = perf_counter_definition->CounterNameTitleIndex;

    counter_definition->name = we_perflib_lookup_counter_name(
        context->counter_indexes,
        counter_definition->name_index);

    snprintf(name_index_str,
             sizeof(name_index_str),
             "%" PRIu32,
             counter_definition->name_index);

    counter_definition->name_index_str = flb_sds_create(name_index_str);

    if (counter_definition->name_index_str == NULL) {
        flb_free(counter_definition);

        return -2;
    }

    if (counter_definition->name == NULL) {
        counter_definition->name = "";
    }

    if (counter_definition->name_index_str == NULL) {
        counter_definition->name_index_str = flb_sds_create("");
    }

    counter_definition->help_index = perf_counter_definition->CounterHelpTitleIndex;

    counter_definition->type = perf_counter_definition->CounterType;
    counter_definition->size = perf_counter_definition->CounterSize;
    counter_definition->offset = perf_counter_definition->CounterOffset;
    counter_definition->detail_level = perf_counter_definition->DetailLevel;

    *out_counter_definition = counter_definition;

    return perf_counter_definition->ByteLength;
}

static int we_perflib_process_counter_definitions(
                                    struct we_perflib_context *context,
                                    struct we_perflib_object  *perflib_object,
                                    char                      *input_data_block)
{
    size_t                                counter_definition_index;
    struct we_perflib_counter_definition *counter_definition;
    size_t                                offset;
    int                                   result;

    offset = 0;

    for (counter_definition_index = 0 ;
         counter_definition_index < perflib_object->counter_count ;
         counter_definition_index++) {
        result =  we_perflib_process_counter_definition(context,
                                                        &input_data_block[offset],
                                                        &counter_definition);

        if (result <= 0) {
            return -1;
        }

        offset += result;

        mk_list_add(&counter_definition->_head, &perflib_object->counter_definitions);
    }

    return offset;
}

static struct we_perflib_counter * we_perflib_create_counter(
    struct we_perflib_counter_definition *counter_definition)
{
    struct we_perflib_counter *counter;

    counter = (struct we_perflib_counter *) \
        flb_calloc(1, sizeof(struct we_perflib_counter));

    if (counter == NULL) {
        return NULL;
    }

    counter->definition = counter_definition;

    return counter;
}

static int we_perflib_process_counter(
                    struct we_perflib_context             *context,
                    struct we_perflib_counter_definition  *counter_definition,
                    char                                  *input_data_block,
                    struct we_perflib_counter            **out_counter)
{
    struct we_perflib_counter *perflib_instance_counter;

    perflib_instance_counter = we_perflib_create_counter(counter_definition);

    if (perflib_instance_counter == NULL) {
        return -1;
    }

    memcpy(&perflib_instance_counter->primary_value,
           &input_data_block[counter_definition->offset],
           counter_definition->size);

    if (counter_definition->size > sizeof(union we_perflib_value)) {
        we_perflib_destroy_counter(perflib_instance_counter);

        return -2;
    }

    *out_counter = perflib_instance_counter;

    return 0;
}

static int we_perflib_process_counters(struct we_perflib_context   *context,
                                       struct we_perflib_object    *perflib_object,
                                       struct we_perflib_instance  *instance,
                                       char                        *input_data_block)
{
    struct mk_list                       *counter_definition_iterator;
    struct we_perflib_counter            *perflib_instance_counter;
    PERF_COUNTER_BLOCK                   *perf_counter_block;
    struct we_perflib_counter_definition *counter_definition;
    int                                   result;
    int                                   offset;

    perf_counter_block = (PERF_COUNTER_BLOCK *) input_data_block;

    mk_list_foreach(counter_definition_iterator,
                    &perflib_object->counter_definitions) {
        counter_definition = mk_list_entry(counter_definition_iterator,
                                           struct we_perflib_counter_definition,
                                           _head);

        if (!counter_definition->name_index) {
            continue;
        }

        result = we_perflib_process_counter(context,
                                            counter_definition,
                                            input_data_block,
                                            &perflib_instance_counter);

        if (result < 0) {
            return -1;
        }

        perflib_instance_counter->parent = instance;

        result = -1;

        if (counter_definition->name[0]) {
            result = flb_hash_table_add(instance->counters,
                                        counter_definition->name,
                                        strlen(counter_definition->name),
                                        perflib_instance_counter,
                                        0);
        }
        else
        {
            result = flb_hash_table_add(instance->counters,
                                        counter_definition->name_index_str,
                                        strlen(counter_definition->name_index_str),
                                        perflib_instance_counter,
                                        0);
        }

        if (result < 0) {
            we_perflib_destroy_counter(perflib_instance_counter);

            return -2;
        }
    }

    return perf_counter_block->ByteLength;
}

static struct we_perflib_instance *we_perflib_create_instance(size_t counter_count)
{
    struct we_perflib_instance *instance;

    instance = (struct we_perflib_instance *) \
        flb_calloc(1, sizeof(struct we_perflib_instance));

    if (instance == NULL) {
        return NULL;
    }

    instance->counters = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE,
                                               64,
                                               counter_count + 1);

    if (instance->counters == NULL) {
        flb_free(instance);

        return NULL;
    }

    return instance;
}

static int we_perflib_process_instance(struct we_perflib_context   *context,
                                       struct we_perflib_object    *perflib_object,
                                       char                        *input_data_block,
                                       struct we_perflib_instance **out_instance)
{
    PERF_INSTANCE_DEFINITION   *perf_instance_definition;
    struct we_perflib_instance *perflib_instance;
    int                         offset;
    int                         result;

    perflib_instance = we_perflib_create_instance(perflib_object->counter_count);

    if (perflib_instance == NULL) {
        return -1;
    }

    offset = 0;

    if (perflib_object->instance_count >= 1) {
        perf_instance_definition = (PERF_INSTANCE_DEFINITION *) input_data_block;

        if (perf_instance_definition->NameLength > 0) {
            perflib_instance->name = \
                    we_convert_wstr(&input_data_block[perf_instance_definition->NameOffset], CP_UTF8);
            if (perflib_instance->name == NULL) {
                we_perflib_destroy_instance(perflib_instance);

                return -2;
            }
        }
        else {
            perflib_instance->name = flb_strdup("DEFAULT");
        }

        offset = perf_instance_definition->ByteLength;
    }

    perflib_instance->parent = perflib_object;

    result = we_perflib_process_counters(context,
                                         perflib_object,
                                         perflib_instance,
                                         &input_data_block[offset]);

    if (result < 0) {
        we_perflib_destroy_instance(perflib_instance);

        return -3;
    }

    offset += result;

    *out_instance = perflib_instance;

    return offset;
}

static int we_perflib_process_instances(struct we_perflib_context *context,
                                        struct we_perflib_object  *perflib_object,
                                        char                      *input_data_block)
{
    struct we_perflib_instance *perflib_instance;
    size_t                      instance_index;
    size_t                      total_instance_data_size;
    PERF_COUNTER_BLOCK         *first_counter_block;
    int                         result;
    int                         offset;

    offset = 0;

    /* Calculate the total size of all instance and counter data blocks */
    total_instance_data_size = perflib_object->total_byte_length -
                               perflib_object->definition_length;

    /*
     * If the total size of instance data is exactly equal to the
     * size of the first counter block, we can infer this is a single-instance
     * object that lacks a PERF_INSTANCE_DEFINITION block.
     */
    if (perflib_object->instance_count == PERF_NO_INSTANCES) {
        first_counter_block = (PERF_COUNTER_BLOCK *)input_data_block;

        if (first_counter_block->ByteLength == total_instance_data_size) {
            /* Path for special single-instance objects like "Cache" and "System" */
            perflib_instance = we_perflib_create_instance(perflib_object->counter_count);
            if (perflib_instance == NULL) {
                return -1;
            }

            perflib_instance->name = flb_strdup("_Total");
            perflib_instance->parent = perflib_object;

            result = we_perflib_process_counters(context, perflib_object,
                                                 perflib_instance, input_data_block);

            if (result < 0) {
                we_perflib_destroy_instance(perflib_instance);
                return -1;
            }
            offset += result;

            result = flb_hash_table_add(perflib_object->instances,
                                        perflib_instance->name, strlen(perflib_instance->name),
                                        perflib_instance, 0);

            if (result < 0) {
                we_perflib_destroy_instance(perflib_instance);
                return -2;
            }

            return offset;
        }
    }

    for (instance_index = 0 ;
         instance_index < perflib_object->instance_count ;
         instance_index++) {

        result =  we_perflib_process_instance(context,
                                              perflib_object,
                                              &input_data_block[offset],
                                              &perflib_instance);

        if (result <= 0) {
            return -1;
        }

        offset += result;

        result = flb_hash_table_add(perflib_object->instances,
                                    perflib_instance->name,
                                    strlen(perflib_instance->name),
                                    perflib_instance,
                                    0);

        if (result < 0) {
            we_perflib_destroy_instance(perflib_instance);

            return -2;
        }
    }

    return offset;
}

int we_perflib_query(struct flb_we *ctx,
                     char *counter_name,
                     struct we_perflib_object **out_object)
{
    char                     *counter_name_index;
    char                     *raw_data_buffer;
    size_t                    raw_data_offset;
    struct we_perflib_object *perflib_object;
    size_t                    raw_data_size;
    int                       result;


    counter_name_index = we_perflib_lookup_counter_index(
        ctx->perflib_context.counter_indexes, counter_name);

    if (counter_name_index == NULL) {
        return -1;
    }

    result = we_perflib_query_raw_data(ctx,
                                       counter_name_index,
                                       &raw_data_buffer,
                                       &raw_data_size);

    if (result) {
        return -2;
    }

    raw_data_offset = 0;

    result = we_perflib_process_object_type(&ctx->perflib_context,
                                            &raw_data_buffer[raw_data_offset],
                                            &perflib_object);

    if (result < 0) {
        flb_free(raw_data_buffer);

        return -3;
    }

    raw_data_offset += result;

    result = we_perflib_process_counter_definitions(&ctx->perflib_context,
                                                    perflib_object,
                                                    &raw_data_buffer[raw_data_offset]);

    if (result < 0) {
        we_perflib_destroy_object(perflib_object);
        flb_free(raw_data_buffer);

        return -4;
    }

    raw_data_offset += result;

    result = we_perflib_process_instances(&ctx->perflib_context,
                                          perflib_object,
                                          &raw_data_buffer[raw_data_offset]);

    if (result < 0) {
        we_perflib_destroy_object(perflib_object);
        flb_free(raw_data_buffer);

        return -5;
    }

    flb_free(raw_data_buffer);

    *out_object = perflib_object;

    return 0;
}

int we_perflib_update_counters(struct flb_we                   *ctx,
                               char                            *query,
                               struct we_perflib_metric_source *metric_sources,
                               we_perflib_instance_filter       filter_hook,
                               we_perflib_label_prepend_hook    label_prepend_hook)
{
    char                            *metric_label_list[WE_PERFLIB_METRIC_LABEL_LIST_SIZE];
    struct flb_hash_table_entry     *instance_hash_entry;
    size_t                           metric_label_count;
    struct mk_list                  *instance_iterator;
    struct we_perflib_metric_source *metric_source;
    size_t                           metric_index;
    void                            *metric_entry;
    size_t                           label_index;
    struct we_perflib_object        *measurement;
    uint64_t                         timestamp;
    struct we_perflib_counter       *counter;
    int                              result;


    timestamp = cfl_time_now();

    result = we_perflib_query(ctx, query, &measurement);

    if (result) {
        return -1;
    }

    mk_list_foreach_r (instance_iterator, &measurement->instances->entries) {
        instance_hash_entry = mk_list_entry(instance_iterator,
                                            struct flb_hash_table_entry,
                                            _head_parent);

        if (filter_hook(instance_hash_entry->key, ctx) == 0) {
            for (metric_index = 0 ;
                 metric_sources[metric_index].name != NULL ;
                 metric_index++) {

                metric_source = &metric_sources[metric_index];

                counter = we_perflib_get_counter(measurement,
                                                 instance_hash_entry->key,
                                                 metric_source->name);

                if (counter == NULL) {
                    return -2;
                }

                metric_label_count = 0;

                result = label_prepend_hook(metric_label_list,
                                            WE_PERFLIB_METRIC_LABEL_LIST_SIZE,
                                            &metric_label_count,
                                            metric_source,
                                            instance_hash_entry->key,
                                            counter);

                if (result != 0) {
                    return -3;
                }

                for (label_index = 0 ;
                     label_index < metric_source->label_set_size;
                     label_index++) {
                    metric_label_list[metric_label_count++] = \
                        metric_source->label_set[label_index];
                }

                metric_entry = metric_source->parent->metric_instance;

                if (metric_source->parent->type == CMT_COUNTER) {
                    cmt_counter_set(metric_entry, timestamp,
                                    we_perflib_get_adjusted_counter_value(counter),
                                    metric_label_count, metric_label_list);
                }
                else if (metric_source->parent->type == CMT_GAUGE) {
                    cmt_gauge_set(metric_entry, timestamp,
                                  we_perflib_get_adjusted_counter_value(counter),
                                  metric_label_count, metric_label_list);
                }
            }
        }
    }

    we_perflib_destroy_object(measurement);

    return 0;
}

struct we_perflib_counter *we_perflib_get_counter(struct we_perflib_object *object,
                                                  char *instance_name,
                                                  char *counter_name)
{
    struct we_perflib_instance *instance;
    struct we_perflib_counter  *counter;

    if (instance_name == NULL) {
        instance_name = "DEFAULT";
    }

    instance = flb_hash_table_get_ptr(object->instances,
                                      instance_name,
                                      strlen(instance_name));

    if (instance == NULL) {
        return NULL;
    }

    counter = flb_hash_table_get_ptr(instance->counters,
                                     counter_name,
                                     strlen(counter_name));

    return counter;
}

int we_perflib_init(struct flb_we *ctx)
{
    int result;

    result = get_text_mapping_table(&ctx->perflib_context.counter_indexes);

    if (result) {
        return -1;
    }

    return 0;
}

int we_perflib_exit(struct flb_we *ctx)
{
    if (ctx->perflib_context.counter_indexes != NULL) {
        flb_hash_table_destroy(ctx->perflib_context.counter_indexes);
        ctx->perflib_context.counter_indexes = NULL;
    }

    return 0;
}

/*
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc785636(v=ws.10)
*/

