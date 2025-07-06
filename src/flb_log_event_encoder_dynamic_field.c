/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_encoder_dynamic_field.h>

struct flb_log_event_encoder_dynamic_field_scope *
    flb_log_event_encoder_dynamic_field_scope_current(
    struct flb_log_event_encoder_dynamic_field *field)
{
    if (cfl_list_is_empty(&field->scopes)) {
        return NULL;
    }

    return cfl_list_entry_first(
                &field->scopes,
                struct flb_log_event_encoder_dynamic_field_scope,
                _head);
}

int flb_log_event_encoder_dynamic_field_scope_enter(
    struct flb_log_event_encoder_dynamic_field *field,
    int type)
{
    int                                               result;
    struct flb_log_event_encoder_dynamic_field_scope *scope;

    if (type != MSGPACK_OBJECT_MAP &&
        type != MSGPACK_OBJECT_ARRAY) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    result = flb_log_event_encoder_dynamic_field_append(field);

    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        return result;
    }

    scope = flb_calloc(1,
                       sizeof(struct flb_log_event_encoder_dynamic_field_scope));

    if (scope == NULL) {
        return FLB_EVENT_ENCODER_ERROR_ALLOCATION_ERROR;
    }

    cfl_list_entry_init(&scope->_head);

    scope->type = type;
    scope->offset = field->buffer.size;

    cfl_list_prepend(&scope->_head, &field->scopes);

    if (type == MSGPACK_OBJECT_MAP) {
        flb_mp_map_header_init(&scope->header, &field->packer);
    }
    else if (type == MSGPACK_OBJECT_ARRAY) {
        flb_mp_array_header_init(&scope->header, &field->packer);
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_dynamic_field_scope_leave(
    struct flb_log_event_encoder_dynamic_field *field,
    struct flb_log_event_encoder_dynamic_field_scope *scope,
    int commit)
{
    if (scope == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    if (commit) {
        /* We increment the entry count on each append because
         * we don't discriminate based on the scope type so
         * we need to divide the entry count by two for maps
         * to ensure the entry count matches the kv pair count
         */

        if (scope->type == MSGPACK_OBJECT_MAP) {
            scope->header.entries /= 2;
            flb_mp_map_header_end(&scope->header);
        }
        else {
            flb_mp_array_header_end(&scope->header);
        }
    }
    else {
        field->buffer.size = scope->offset;
    }

    cfl_list_del(&scope->_head);

    flb_free(scope);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_dynamic_field_begin_map(
    struct flb_log_event_encoder_dynamic_field *field)
{
    return flb_log_event_encoder_dynamic_field_scope_enter(field,
                                                           MSGPACK_OBJECT_MAP);
}

int flb_log_event_encoder_dynamic_field_begin_array(
    struct flb_log_event_encoder_dynamic_field *field)
{
    return flb_log_event_encoder_dynamic_field_scope_enter(field,
                                                           MSGPACK_OBJECT_ARRAY);
}

int flb_log_event_encoder_dynamic_field_commit_map(
    struct flb_log_event_encoder_dynamic_field *field)
{
    struct flb_log_event_encoder_dynamic_field_scope *scope;

    scope = flb_log_event_encoder_dynamic_field_scope_current(field);

    return flb_log_event_encoder_dynamic_field_scope_leave(field,
                                                           scope,
                                                           FLB_TRUE);
}

int flb_log_event_encoder_dynamic_field_commit_array(
    struct flb_log_event_encoder_dynamic_field *field)
{
    struct flb_log_event_encoder_dynamic_field_scope *scope;

    scope = flb_log_event_encoder_dynamic_field_scope_current(field);

    return flb_log_event_encoder_dynamic_field_scope_leave(field,
                                                           scope,
                                                           FLB_TRUE);
}

int flb_log_event_encoder_dynamic_field_rollback_map(
    struct flb_log_event_encoder_dynamic_field *field)
{
    struct flb_log_event_encoder_dynamic_field_scope *scope;

    scope = flb_log_event_encoder_dynamic_field_scope_current(field);

    return flb_log_event_encoder_dynamic_field_scope_leave(field,
                                                           scope,
                                                           FLB_FALSE);
}

int flb_log_event_encoder_dynamic_field_rollback_array(
    struct flb_log_event_encoder_dynamic_field *field)
{
    struct flb_log_event_encoder_dynamic_field_scope *scope;

    scope = flb_log_event_encoder_dynamic_field_scope_current(field);

    return flb_log_event_encoder_dynamic_field_scope_leave(field,
                                                           scope,
                                                           FLB_TRUE);
}

int flb_log_event_encoder_dynamic_field_append(
    struct flb_log_event_encoder_dynamic_field *field)
{
    struct flb_log_event_encoder_dynamic_field_scope *scope;

    scope = flb_log_event_encoder_dynamic_field_scope_current(field);

    if (scope == NULL) {
        if (cfl_list_is_empty(&field->scopes)) {
            return FLB_EVENT_ENCODER_SUCCESS;
        }

        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    flb_mp_map_header_append(&scope->header);

    return FLB_EVENT_ENCODER_SUCCESS;
}


static int flb_log_event_encoder_dynamic_field_flush_scopes(
    struct flb_log_event_encoder_dynamic_field *field,
    int commit)
{
    int                                               result;
    struct flb_log_event_encoder_dynamic_field_scope *scope;

    result = FLB_EVENT_ENCODER_SUCCESS;

    do {
        scope = flb_log_event_encoder_dynamic_field_scope_current(field);

        if (scope != NULL) {
            result = flb_log_event_encoder_dynamic_field_scope_leave(field,
                                                                     scope,
                                                                     commit);
        }
    } while (scope != NULL &&
             result == FLB_EVENT_ENCODER_SUCCESS);

    return result;
}

int flb_log_event_encoder_dynamic_field_flush(
    struct flb_log_event_encoder_dynamic_field *field)
{
    int result;

    result = flb_log_event_encoder_dynamic_field_flush_scopes(field, FLB_TRUE);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        field->data = field->buffer.data;
        field->size = field->buffer.size;
    }

    return result;
}

int flb_log_event_encoder_dynamic_field_reset(
    struct flb_log_event_encoder_dynamic_field *field)
{
    msgpack_sbuffer_clear(&field->buffer);

    flb_log_event_encoder_dynamic_field_flush_scopes(field, FLB_FALSE);

    field->data = NULL;
    field->size = 0;

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_dynamic_field_init(
    struct flb_log_event_encoder_dynamic_field *field,
    int type)
{
    msgpack_sbuffer_init(&field->buffer);
    msgpack_packer_init(&field->packer,
                        &field->buffer,
                        msgpack_sbuffer_write);

    field->initialized = FLB_TRUE;
    field->type = type;

    cfl_list_init(&field->scopes);
    flb_log_event_encoder_dynamic_field_reset(field);

    return FLB_EVENT_ENCODER_SUCCESS;
}

void flb_log_event_encoder_dynamic_field_destroy(
    struct flb_log_event_encoder_dynamic_field *field)
{
    /*
     * Ensure any outstanding scopes are cleaned up before releasing the
     * underlying buffer. Otherwise these allocations would leak if the
     * caller did not properly flush or rollback all scopes.
     */
    flb_log_event_encoder_dynamic_field_reset(field);

    msgpack_sbuffer_destroy(&field->buffer);

    field->initialized = FLB_FALSE;
}
