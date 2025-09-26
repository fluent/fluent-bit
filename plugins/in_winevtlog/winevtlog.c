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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sqldb.h>
#include <fluent-bit/flb_input.h>
#include "winevtlog.h"

#define EVENT_PROVIDER_NAME_LENGTH 256

static char* convert_wstr(wchar_t *wstr, UINT codePage);
static wchar_t* convert_str(char *str);

static EVT_HANDLE
create_remote_handle(struct winevtlog_session *session, DWORD *error_code)
{
    EVT_HANDLE remote = NULL;
    EVT_RPC_LOGIN credentials;

    RtlZeroMemory(&credentials, sizeof(EVT_RPC_LOGIN));

    credentials.Server = session->server;
    credentials.Domain = session->domain;
    credentials.User = session->username;
    credentials.Password = session->password;
    credentials.Flags = session->flags;

    remote = EvtOpenSession(EvtRpcLogin, &credentials, 0, 0);
    if (!remote) {
        *error_code = GetLastError();
        return remote;
    }

    SecureZeroMemory(&credentials, sizeof(EVT_RPC_LOGIN));

    return remote;
}

struct winevtlog_channel *winevtlog_subscribe(const char *channel, struct winevtlog_config *ctx,
                                              EVT_HANDLE stored_bookmark, const char *query,
                                              struct winevtlog_session *session)
{
    struct winevtlog_channel *ch;
    EVT_HANDLE bookmark = NULL;
    HANDLE signal_event = NULL;
    DWORD len;
    DWORD flags = 0L;
    PWSTR wide_channel = NULL;
    PWSTR wide_query = NULL;
    EVT_HANDLE remote_handle = NULL;
    void *buf;
    DWORD err = ERROR_SUCCESS;

    ch = flb_calloc(1, sizeof(struct winevtlog_channel));
    if (ch == NULL) {
        flb_errno();
        return NULL;
    }

    ch->name = flb_strdup(channel);
    if (!ch->name) {
        flb_errno();
        flb_free(ch);
        return NULL;
    }
    ch->query = NULL;

    signal_event = CreateEvent(NULL, TRUE, TRUE, NULL);

    // channel : To wide char
    len = MultiByteToWideChar(CP_UTF8, 0, channel, -1, NULL, 0);
    wide_channel = flb_malloc(sizeof(PWSTR) * len);
    MultiByteToWideChar(CP_UTF8, 0, channel, -1, wide_channel, len);
    if (query != NULL) {
    // query : To wide char
        len = MultiByteToWideChar(CP_UTF8, 0, query, -1, NULL, 0);
        wide_query = flb_malloc(sizeof(PWSTR) * len);
        MultiByteToWideChar(CP_UTF8, 0, query, -1, wide_query, len);
        ch->query = flb_strdup(query);
    }

    if (stored_bookmark) {
        flags |= EvtSubscribeStartAfterBookmark;
    } else if (ctx->read_existing_events) {
        flags |= EvtSubscribeStartAtOldestRecord;
    } else {
        flags |= EvtSubscribeToFutureEvents;
    }

    if (session != NULL) {
        remote_handle = create_remote_handle(session, &err);
        if (err != ERROR_SUCCESS) {
            flb_plg_error(ctx->ins, "cannot create remote handle '%s' in %ls (%i)",
                      channel, session->server, err);
            flb_free(ch->name);
            if (ch->query != NULL) {
                flb_free(ch->query);
            }
            flb_free(ch);
            return NULL;
        }

        flb_plg_debug(ctx->ins, "created a remote handle for '%s' in %ls",
                  channel, session->server);
        ch->session = session;
        ch->remote = remote_handle;
    }

    /* The wide_query parameter can handle NULL as `*` for retrieving all events.
     * ref. https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe
     */
    ch->subscription = EvtSubscribe(remote_handle, signal_event, wide_channel, wide_query,
                                    stored_bookmark, NULL, NULL, flags);
    err = GetLastError();
    if (!ch->subscription) {
        flb_plg_error(ctx->ins, "cannot subscribe '%s' (%i)", channel, err);
        flb_free(ch->name);
        if (ch->query != NULL) {
            flb_free(ch->query);
        }
        if (ch->remote) {
            EvtClose(ch->remote);
        }
        flb_free(ch);
        return NULL;
    }
    ch->signal_event = signal_event;
    ch->cancelled_by_us = FALSE;
    ch->reconnect_needed = FALSE;
    ch->last_error = 0;
    ch->retry_attempts = 0;
    ch->next_retry_deadline = 0;
    ch->prng_state = GetTickCount64() ^ (ULONGLONG)(uintptr_t)ch;

    if (stored_bookmark) {
        ch->bookmark = stored_bookmark;
    }
    else {
        bookmark = EvtCreateBookmark(NULL);
        if (bookmark) {
            ch->bookmark = bookmark;
        }
        else {
            if (ch->subscription) {
                EvtClose(ch->subscription);
            }
            if (ch->remote) {
                EvtClose(ch->remote);
            }
            if (signal_event) {
                CloseHandle(signal_event);
            }
            flb_plg_error(ctx->ins, "cannot subscribe '%s' (%i)", channel, GetLastError());
            flb_free(wide_channel);
            flb_free(ch->name);
            if (ch->query != NULL) {
                flb_free(ch->query);
            }
            flb_free(ch);
            return NULL;
        }
    }

    flb_free(wide_channel);
    if (wide_query != NULL) {
        flb_free(wide_query);
    }

    return ch;
}

BOOL cancel_subscription(struct winevtlog_channel *ch)
{
    ch->cancelled_by_us = TRUE;
    return EvtCancel(ch->subscription);
}

void winevtlog_request_cancel(struct winevtlog_channel *ch)
{
    ch->cancelled_by_us = TRUE;
    EvtCancel(ch->subscription);
}

static void close_handles(struct winevtlog_channel *ch)
{
    int i;

    if (ch->subscription) {
        EvtClose(ch->subscription);
        ch->subscription = NULL;
    }
    if (ch->remote) {
        EvtClose(ch->remote);
        ch->remote = NULL;
    }
    if (ch->signal_event) {
        CloseHandle(ch->signal_event);
        ch->signal_event = NULL;
    }
    if (ch->bookmark) {
        EvtClose(ch->bookmark);
        ch->bookmark = NULL;
    }
    for (i = 0; i < ch->count; i++) {
        if (ch->events[i]) {
            EvtClose(ch->events[i]);
            ch->events[i] = NULL;
        }
    }
    ch->count = 0;
}


void winevtlog_close(struct winevtlog_channel *ch)
{
    flb_free(ch->name);
    if (ch->query != NULL) {
        flb_free(ch->query);
    }
    close_handles(ch);

    flb_free(ch);
}

// Render the event as an XML string and print it.
PWSTR render_event(EVT_HANDLE hEvent, DWORD flags, unsigned int *event_size)
{
    DWORD status = ERROR_SUCCESS;
    DWORD buffer_size = 0;
    DWORD buffer_used = 0;
    DWORD count = 0;
    LPWSTR event_xml = NULL;

    if (flags != EvtRenderEventXml && flags != EvtRenderBookmark) {
        flb_error("Invalid flags is specified: %d", flags);
        return NULL;
    }

    if (!EvtRender(NULL, hEvent, flags, buffer_size, event_xml, &buffer_used, &count)) {
        status = GetLastError();
        if (status == ERROR_INSUFFICIENT_BUFFER) {
            buffer_size = buffer_used;
            /* return buffer size */
            *event_size = buffer_size;
            event_xml = (LPWSTR)flb_malloc(buffer_size);
            if (event_xml) {
                EvtRender(NULL, hEvent, flags, buffer_size, event_xml, &buffer_used, &count);
            }
            else {
                flb_error("malloc failed");
                goto cleanup;
            }
        }

        status = GetLastError();
        if (status != ERROR_SUCCESS) {
            flb_error("EvtRender failed with %d", GetLastError());
            goto cleanup;
        }
    }

    return event_xml;

cleanup:

    if (event_xml) {
        flb_free(event_xml);
    }

    return NULL;
}

DWORD render_system_event(EVT_HANDLE event, PEVT_VARIANT *system, unsigned int *system_size)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE context = NULL;
    DWORD buffer_size = 0;
    DWORD buffer_used = 0;
    DWORD count = 0;
    PEVT_VARIANT rendered_system = NULL;

    context = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    if (NULL == context) {
        status = GetLastError();
        flb_error("failed to create RenderContext with %d", status);

        goto cleanup;
    }
    if (!EvtRender(context,
                   event,
                   EvtRenderEventValues,
                   buffer_size,
                   rendered_system,
                   &buffer_used,
                   &count)) {
        status = GetLastError();

        if (status == ERROR_INSUFFICIENT_BUFFER) {
            buffer_size = buffer_used;
            rendered_system = (PEVT_VARIANT)flb_malloc(buffer_size);
            if (rendered_system) {
                EvtRender(context,
                          event,
                          EvtRenderEventValues,
                          buffer_size,
                          rendered_system,
                          &buffer_used,
                          &count);
                status = GetLastError();
                *system_size = buffer_used;
            } else {
                if (rendered_system)
                    flb_free(rendered_system);

                flb_error("failed to malloc memory with %d", status);

                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != status) {
            EvtClose(context);
            flb_free(rendered_system);

            return status;
        }
    }

    *system = rendered_system;

cleanup:

    if (context) {
        EvtClose(context);
    }

    return status;
}


PWSTR get_message(EVT_HANDLE metadata, EVT_HANDLE handle, unsigned int *message_size)
{
    WCHAR* buffer = NULL;
    WCHAR* previous_buffer = NULL;
    DWORD status = ERROR_SUCCESS;
    DWORD buffer_size = 512;
    DWORD buffer_used = 0;
    LPVOID format_message_buffer;
    WCHAR* message = NULL;
    char *error_message = NULL;

    buffer = flb_malloc(sizeof(WCHAR) * buffer_size);
    if (!buffer) {
        flb_error("failed to premalloc message buffer");

        goto buffer_error;
    }

    // Get the size of the buffer
    if (!EvtFormatMessage(metadata, handle, 0, 0, NULL,
                          EvtFormatMessageEvent, buffer_size, buffer, &buffer_used)) {
        status = GetLastError();
        if (ERROR_INSUFFICIENT_BUFFER == status) {
            buffer_size = buffer_used;
            previous_buffer = buffer;
            buffer = flb_realloc(previous_buffer, sizeof(WCHAR) * buffer_size);
            if (!buffer) {
                flb_error("failed to malloc message buffer");
                flb_free(previous_buffer);

                goto buffer_error;
            }

            if (!EvtFormatMessage(metadata,
                                  handle,
                                  0xffffffff,
                                  0,
                                  NULL,
                                  EvtFormatMessageEvent,
                                  buffer_size,
                                  buffer,
                                  &buffer_used)) {
                status = GetLastError();
                *message_size = buffer_used;

                if (status != ERROR_EVT_UNRESOLVED_VALUE_INSERT) {
                    switch (status) {
                        case ERROR_EVT_MESSAGE_NOT_FOUND:
                        case ERROR_EVT_MESSAGE_ID_NOT_FOUND:
                        case ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND:
                        case ERROR_RESOURCE_DATA_NOT_FOUND:
                        case ERROR_RESOURCE_TYPE_NOT_FOUND:
                        case ERROR_RESOURCE_NAME_NOT_FOUND:
                        case ERROR_RESOURCE_LANG_NOT_FOUND:
                        case ERROR_MUI_FILE_NOT_FOUND:
                        case ERROR_EVT_UNRESOLVED_PARAMETER_INSERT:
                        {
                            if (FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                               FORMAT_MESSAGE_IGNORE_INSERTS,
                                               NULL,
                                               status,
                                               MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                               (WCHAR*)(&format_message_buffer),
                                               0,
                                               NULL) == 0)
                                FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                               FORMAT_MESSAGE_IGNORE_INSERTS,
                                               NULL,
                                               status,
                                               MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                                               (WCHAR*)(&format_message_buffer),
                                               0,
                                               NULL);
                            error_message = convert_wstr((WCHAR*)format_message_buffer, CP_ACP);
                            flb_error("Failed to get message with %d, err = %s", status, error_message);
                            flb_free(error_message);

                            message = _wcsdup((WCHAR*)format_message_buffer);
                            LocalFree(format_message_buffer);

                            goto cleanup;
                        }
                    }

                    if (status != ERROR_INSUFFICIENT_BUFFER) {
                        flb_error("failed with %d", status);
                        goto cleanup;
                    }
                }
            }
        }
    }

    message = _wcsdup(buffer);

cleanup:
    if (buffer) {
        flb_free(buffer);
    }

buffer_error:

    return message;
}

PWSTR get_description(EVT_HANDLE handle, LANGID langID, unsigned int *message_size)
{
    PEVT_VARIANT values = NULL;
    DWORD buffer_size = 0;
    DWORD buffer_size_used = 0;
    DWORD status = ERROR_SUCCESS;
    DWORD count = 0;
    WCHAR *message = NULL;
    EVT_HANDLE metadata = NULL;

    PCWSTR properties[] = { L"Event/System/Provider/@Name", L"Event/RenderingInfo/Message" };
    EVT_HANDLE context =
            EvtCreateRenderContext(_countof(properties), properties,
                                   EvtRenderContextValues);
    if (context == NULL) {
        flb_error("Failed to create renderContext");
        goto cleanup;
    }

    // Get the size of the buffer
    EvtRender(context, handle, EvtRenderEventValues, 0, NULL, &buffer_size, &count);
    values = (PEVT_VARIANT)flb_malloc(buffer_size);

    if (EvtRender(context,
                  handle,
                  EvtRenderEventValues,
                  buffer_size,
                  values,
                  &buffer_size_used,
                  &count) != FALSE){
        status = ERROR_SUCCESS;
    }
    else {
        status = GetLastError();
    }

    if (status != ERROR_SUCCESS) {
        flb_error("failed to query RenderContextValues");
        goto cleanup;
    }

    /* For non forwarded events, we need to determine the
     * corresponding metadata. */
    if ((values[1].Type & EVT_VARIANT_TYPE_MASK) == EvtVarTypeNull) {
        /* Metadata can be NULL because some of the events do not have an
         * associated publisher metadata. */
        metadata = EvtOpenPublisherMetadata(
                NULL, // TODO: Remote handle
                values[0].StringVal,
                NULL,
                MAKELCID(langID, SORT_DEFAULT),
                0);

        message = get_message(metadata, handle, message_size);
    }
    else if ((values[1].Type & EVT_VARIANT_TYPE_MASK) == EvtVarTypeString) {
        /* Forwarded events contain RenderingInfo element */
        message = _wcsdup(values[1].StringVal);
    }

cleanup:
    if (context) {
        EvtClose(context);
    }

    if (metadata) {
        EvtClose(metadata);
    }

    if (values) {
        flb_free(values);
    }

    return message;
}

int get_string_inserts(EVT_HANDLE handle, PEVT_VARIANT *string_inserts_values,
                       UINT *prop_count, unsigned int *string_inserts_size)
{
    PEVT_VARIANT values;
    DWORD buffer_size = 0;
    DWORD buffer_size_used = 0;
    DWORD count = 0;
    BOOL succeeded = FLB_TRUE;

    EVT_HANDLE context = EvtCreateRenderContext(0, NULL, EvtRenderContextUser);
    if (context == NULL) {
        flb_error("Failed to create renderContext");
        succeeded = FLB_FALSE;
        goto cleanup;
    }

    // Get the size of the buffer
    EvtRender(context, handle, EvtRenderEventValues, 0, NULL, &buffer_size, &count);
    values = (PEVT_VARIANT)flb_malloc(buffer_size);

    succeeded = EvtRender(context,
                          handle,
                          EvtRenderEventValues,
                          buffer_size,
                          values,
                          &buffer_size_used,
                          &count);

    if (!succeeded) {
        flb_error("Failed to get string inserts with %d\n", GetLastError());
        goto cleanup;
    }

    *prop_count = count;
    *string_inserts_values = values;
    *string_inserts_size = buffer_size;

cleanup:

    if (context != NULL) {
        EvtClose(context);
    }

    return succeeded;
}

static int winevtlog_next(struct winevtlog_channel *ch, int hit_threshold)
{
    EVT_HANDLE events[SUBSCRIBE_ARRAY_SIZE];
    DWORD count = 0;
    DWORD status = ERROR_SUCCESS;
    BOOL has_next = FALSE;
    int i;
    DWORD wait = 0;

    /* If subscription handle is NULL, it should return false. */
    if (!ch->subscription) {
        flb_error("Invalid subscription is passed");
        return FLB_FALSE;
    }

    if (hit_threshold) {
        return FLB_FALSE;
    }

    wait = WaitForSingleObject(ch->signal_event, 0);
    if (wait == WAIT_FAILED) {
        flb_error("subscription is invalid. err code = %d", GetLastError());
        return FLB_FALSE;
    }
    else if (wait != WAIT_OBJECT_0) {
        return FLB_FALSE;
    }

    has_next = EvtNext(ch->subscription, SUBSCRIBE_ARRAY_SIZE,
                       events, INFINITE, 0, &count);

    if (!has_next) {
        status = GetLastError();
        if (status == ERROR_CANCELLED) {
            if (ch->cancelled_by_us) {
                /* Conmsume this flag and return early */
                ch->cancelled_by_us = FALSE;
                return FLB_FALSE;
            }
            ch->reconnect_needed = TRUE;
            ch->last_error = status;
            flb_debug("[in_winevtlog] subscription cancelled unexpectedly (err=%lu), will reconnect", status);
            return FLB_FALSE;
        }
        if (status != ERROR_NO_MORE_ITEMS) {
            ch->reconnect_needed = TRUE;
            ch->last_error = status;
            flb_warn("[in_winevtlog] EvtNext failed (err=%lu), will reconnect", status);
            return FLB_FALSE;
        }

        ResetEvent(ch->signal_event);
    }

    if (status == ERROR_SUCCESS) {
        ch->count = count;
        for (i = 0; i < count; i++) {
            ch->events[i] = events[i];
            EvtUpdateBookmark(ch->bookmark, ch->events[i]);
        }

        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static inline void backoff_defaults(struct winevtlog_backoff *dst, const struct winevtlog_backoff *src)
{
    dst->base_ms          = (src && src->base_ms)          ? src->base_ms          : 500;
    dst->max_ms           = (src && src->max_ms)           ? src->max_ms           : 30000;
    dst->multiplier_x1000 = (src && src->multiplier_x1000) ? src->multiplier_x1000 : 2000; /* x2.0 */
    dst->jitter_pct       = (src && src->jitter_pct)       ? src->jitter_pct       : 20;
    dst->max_retries      = (src && src->max_retries)      ? src->max_retries      : 8;
}

static inline DWORD prng16(ULONGLONG *state)
{
    *state = (*state * 6364136223846793005ULL + 1ULL);
    return (DWORD)((*state >> 33) & 0xFFFF);
}

static DWORD calc_backoff_ms(struct winevtlog_channel *ch, const struct winevtlog_backoff *cfg, DWORD attempt)
{
    DWORD i = 0;
    DWORD ms = 0;
    LONG span = 0;
    LONG delta = 0;
    LONG with_jitter = 0;
    double mult = (double)cfg->multiplier_x1000 / 1000.0;
    double t = (double)cfg->base_ms;

    for (i = 0; i < attempt; i++) {
        t *= mult;
        if (t >= (double)cfg->max_ms) { t = (double)cfg->max_ms; break; }
    }
    ms = (DWORD)((t > (double)cfg->max_ms) ? cfg->max_ms : t);
    /* ±jitter% */
    span = (LONG)((ms * cfg->jitter_pct) / 100);
    delta = (LONG)(prng16(&ch->prng_state) % (2 * span + 1)) - span;
    with_jitter = (LONG)ms + delta;
    if (with_jitter < 0) {
        with_jitter = 0;
    }
    return (DWORD)with_jitter;
}

void winevtlog_schedule_retry(struct winevtlog_channel *ch, struct winevtlog_config *ctx)
{
    struct winevtlog_backoff cfg;
    DWORD delay = 0;
    backoff_defaults(&cfg, ctx ? &ctx->backoff : NULL);
    delay = calc_backoff_ms(ch, &cfg, ch->retry_attempts);
    ch->next_retry_deadline = GetTickCount64() + (ULONGLONG)delay;
}

int winevtlog_try_reconnect(struct winevtlog_channel *ch, struct winevtlog_config *ctx)
{
    HANDLE   new_signal = NULL;
    EVT_HANDLE new_remote = NULL;
    EVT_HANDLE new_sub = NULL;
    DWORD flags = 0;
    DWORD err = 0;
    PWSTR wide_channel = NULL;
    PWSTR wide_query   = NULL;
    DWORD len;

    len = MultiByteToWideChar(CP_UTF8, 0, ch->name, -1, NULL, 0);
    if (len == 0) {
        return -1;
    }
    wide_channel = flb_malloc(sizeof(WCHAR) * len);
    if (!wide_channel) {
        return -1;
    }
    MultiByteToWideChar(CP_UTF8, 0, ch->name, -1, wide_channel, len);

    if (ch->query) {
        len = MultiByteToWideChar(CP_UTF8, 0, ch->query, -1, NULL, 0);
        if (len == 0) {
            flb_free(wide_channel);
            return -1;
        }
        wide_query = flb_malloc(sizeof(WCHAR) * len);
        if (!wide_query) {
            flb_free(wide_channel);
            return -1;
        }
        MultiByteToWideChar(CP_UTF8, 0, ch->query, -1, wide_query, len);
    }

    new_signal = CreateEvent(NULL, TRUE, TRUE, NULL);
    if (!new_signal) {
        flb_free(wide_channel);
        if (wide_query) {
            flb_free(wide_query);
        }
        return -1;
    }

    if (ch->session) {
        new_remote = create_remote_handle(ch->session, &err);
        if (err != ERROR_SUCCESS || !new_remote) {
            flb_plg_error(ctx->ins, "reconnect: cannot create remote handle '%s' in %ls (err=%lu)",
                          ch->name, ch->session->server, err);
            CloseHandle(new_signal);
            flb_free(wide_channel);
            if (wide_query) {
                flb_free(wide_query);
            }
            return -1;
        }
    }

    if (ch->bookmark) {
        flags = EvtSubscribeStartAfterBookmark;
    }
    else if (ctx->read_existing_events) {
        flags = EvtSubscribeStartAtOldestRecord;
    }
    else {
        flags = EvtSubscribeToFutureEvents;
    }

    new_sub = EvtSubscribe(new_remote, new_signal, wide_channel, wide_query,
                           ch->bookmark, NULL, NULL, flags);
    if (!new_sub) {
        DWORD sub_err = GetLastError();
        if (sub_err == ERROR_EVT_QUERY_RESULT_STALE) {
            flb_plg_warn(ctx->ins, "reconnect: bookmark stale on '%s' (err=%lu), falling back to latest",
                         ch->name, sub_err);
            flags = ctx->read_existing_events ? EvtSubscribeStartAtOldestRecord
                                              : EvtSubscribeToFutureEvents;
            new_sub = EvtSubscribe(new_remote, new_signal, wide_channel, wide_query,
                                   NULL, NULL, NULL, flags);
        }
    }

    if (!new_sub) {
        DWORD sub_err = GetLastError();
        flb_plg_error(ctx->ins, "reconnect: EvtSubscribe failed on '%s' (err=%lu)", ch->name, sub_err);
        if (new_remote) EvtClose(new_remote);
        CloseHandle(new_signal);
        flb_free(wide_channel);
        if (wide_query) {
            flb_free(wide_query);
        }
        return -1;
    }

    if (ch->subscription) {
        EvtClose(ch->subscription);
    }
    if (ch->remote) {
        EvtClose(ch->remote);
    }
    if (ch->signal_event) {
        CloseHandle(ch->signal_event);
    }

    ch->subscription    = new_sub;
    ch->remote          = new_remote;
    ch->signal_event    = new_signal;
    ch->reconnect_needed  = FALSE;
    ch->retry_attempts    = 0;
    ch->next_retry_deadline = 0;
    ch->last_error        = 0;
    ch->count             = 0;

    flb_plg_debug(ctx->ins, "reconnected subscription for '%s'", ch->name);
    flb_free(wide_channel);
    if (wide_query) {
        flb_free(wide_query);
    }
    return 0;
}

/*
 * Read from an open Windows Event Log channel.
 */
int winevtlog_read(struct winevtlog_channel *ch, struct winevtlog_config *ctx,
                   unsigned int *read)
{
    DWORD status = ERROR_SUCCESS;
    PWSTR system_xml = NULL;
    unsigned int system_size = 0;
    unsigned int message_size = 0;
    unsigned int string_inserts_size = 0;
    int hit_threshold = FLB_FALSE;
    unsigned int read_size = 0;
    PWSTR message = NULL;
    PEVT_VARIANT rendered_system = NULL;
    PEVT_VARIANT string_inserts = NULL;
    UINT count_inserts = 0;
    DWORD i = 0;
    int rc = 0;

    while (winevtlog_next(ch, hit_threshold)) {
        for (i = 0; i < ch->count; i++) {
            if (ctx->render_event_as_xml) {
                system_xml = render_event(ch->events[i], EvtRenderEventXml, &system_size);
                message = get_description(ch->events[i], LANG_NEUTRAL, &message_size);
                get_string_inserts(ch->events[i], &string_inserts, &count_inserts, &string_inserts_size);
                if (system_xml) {
                    /* Caluculate total allocated size: system + message + string_inserts */
                    read_size += (system_size + message_size + string_inserts_size);
                    winevtlog_pack_xml_event(system_xml, message, string_inserts,
                                             count_inserts, ch, ctx);

                    flb_free(string_inserts);
                    flb_free(system_xml);
                    if (message)
                        flb_free(message);
                }
            }
            else {
                render_system_event(ch->events[i], &rendered_system, &system_size);
                message = get_description(ch->events[i], LANG_NEUTRAL, &message_size);
                get_string_inserts(ch->events[i], &string_inserts, &count_inserts, &string_inserts_size);
                if (rendered_system) {
                    /* Caluculate total allocated size: system + message + string_inserts */
                    read_size += (system_size + message_size + string_inserts_size);
                    winevtlog_pack_event(rendered_system, message, string_inserts,
                                         count_inserts, ch, ctx);

                    flb_free(string_inserts);
                    flb_free(rendered_system);
                    if (message)
                        flb_free(message);
                }
            }
        }

        /* Closes any events in case an error occurred above. */
        for (i = 0; i < ch->count; i++) {
            if (NULL != ch->events[i]) {
                EvtClose(ch->events[i]);
                ch->events[i] = NULL;
            }
        }

        if (read_size > ctx->total_size_threshold) {
            hit_threshold = FLB_TRUE;
            /* hit reading threshold on read, then break. */
            break;
        }
    }

    *read = read_size;

    if (ch->reconnect_needed) {
        ULONGLONG now = GetTickCount64();
        if (ch->next_retry_deadline == 0 || now >= ch->next_retry_deadline) {
            int rc = winevtlog_try_reconnect(ch, ctx);
            if (rc != 0) {
                struct winevtlog_backoff eff;
                backoff_defaults(&eff, ctx ? &ctx->backoff : NULL);
                if (ch->retry_attempts < eff.max_retries) {
                    ch->retry_attempts++;
                    winevtlog_schedule_retry(ch, ctx);
                    flb_plg_warn(ctx->ins, "reconnect attempt %lu failed for '%s' (err=%lu), next at +%lums",
                                 (unsigned long)ch->retry_attempts, ch->name, ch->last_error,
                                 (unsigned long)(ch->next_retry_deadline - now));
                }
                else {
                    flb_plg_error(ctx->ins, "reconnect exhausted for '%s' (last err=%lu)", ch->name, ch->last_error);
                    ch->reconnect_needed = FALSE;
                }
            }
        }
    }
    return 0;
}

/*
 * Open multiple channels at once. The return value is a linked
 * list of winevtlog_channel objects.
 *
 * "channels" are comma-separated names like "Setup,Security".
 */
struct mk_list *winevtlog_open_all(const char *channels, struct winevtlog_config *ctx)
{
    char *tmp;
    char *channel;
    char *state;
    struct winevtlog_channel *ch;
    struct mk_list *list;

    tmp = flb_strdup(channels);
    if (!tmp) {
        flb_errno();
        return NULL;
    }

    list = flb_malloc(sizeof(struct mk_list));
    if (!list) {
        flb_errno();
        flb_free(tmp);
        return NULL;
    }
    mk_list_init(list);

    channel = strtok_s(tmp , ",", &state);
    while (channel) {
        ch = winevtlog_subscribe(channel, ctx, NULL, ctx->event_query,
                                 ctx->session);
        if (ch) {
            mk_list_add(&ch->_head, list);
        }
        else {
            if (ctx->ignore_missing_channels) {
                flb_debug("[in_winevtlog] channel '%s' does not exist", channel);
            }
            else {
                flb_free(tmp);
                winevtlog_close_all(list);
                return NULL;
            }
        }
        channel = strtok_s(NULL, ",", &state);
    }

    if (mk_list_size(list) == 0) {
        flb_free(tmp);
        winevtlog_close_all(list);
        return NULL;
    }

    flb_free(tmp);
    return list;
}

void winevtlog_close_all(struct mk_list *list)
{
    struct winevtlog_channel *ch;
    struct mk_list *head;
    struct mk_list *tmp;

    mk_list_foreach_safe(head, tmp, list) {
        ch = mk_list_entry(head, struct winevtlog_channel, _head);
        mk_list_del(&ch->_head);
        winevtlog_close(ch);
    }
    flb_free(list);
}

/*
 * Callback function for flb_sqldb_query().
 */
static int winevtlog_sqlite_callback(void *data, int argc, char **argv, char **cols)
{
    struct winevtlog_sqlite_record *p = data;

    p->name = argv[0];
    p->bookmark_xml = strdup(argv[1]);
    p->time_updated = (unsigned int) strtoul(argv[2], NULL, 10);
    p->created = (unsigned int) strtoul(argv[3], NULL, 10);
    return 0;
}

static wchar_t* convert_str(char *str)
{
    int size = 0;
    wchar_t *buf = NULL;

    size = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (size == 0) {
        return NULL;
    }

    buf = flb_malloc(sizeof(PWSTR) * size);
    if (buf == NULL) {
        flb_errno();
        return NULL;
    }
    size = MultiByteToWideChar(CP_UTF8, 0, str, -1, buf, size);
    if (size == 0) {
        flb_free(buf);
        return NULL;
    }

    return buf;
}

static char* convert_wstr(wchar_t *wstr, UINT codePage)
{
    int size = 0;
    char *buf = NULL;

    size = WideCharToMultiByte(codePage, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (size == 0) {
        return NULL;
    }

    buf = flb_malloc(size);
    if (buf == NULL) {
        flb_errno();
        return NULL;
    }
    size = WideCharToMultiByte(codePage, 0, wstr, -1, buf, size, NULL, NULL);
    if (size == 0) {
        flb_free(buf);
        return NULL;
    }

    return buf;
}

/*
 * Load the bookmark from SQLite DB.
 */
int winevtlog_sqlite_load(struct winevtlog_channel *ch, struct winevtlog_config *ctx, struct flb_sqldb *db)
{
    int ret;
    char query[1024];
    struct winevtlog_sqlite_record record = {0};
    EVT_HANDLE bookmark = NULL;
    PWSTR bookmark_xml = NULL;
    struct winevtlog_channel *re_ch = NULL;

    snprintf(query, sizeof(query) - 1, SQL_GET_CHANNEL, ch->name);

    ret = flb_sqldb_query(db, query, winevtlog_sqlite_callback, &record);
    if (ret == FLB_ERROR) {
        return -1;
    }

    if (record.created) {
        ch->time_created = record.created;
    }
    if (record.time_updated) {
        ch->time_updated = record.time_updated;
    }

    if (record.name) {
        bookmark_xml = convert_str(record.bookmark_xml);
        if (bookmark_xml) {
            bookmark = EvtCreateBookmark(bookmark_xml);
            if (bookmark) {
                /* re-create subscription handles */
                if (ctx) {
                    ctx->read_existing_events = FLB_FALSE;
                }
                re_ch = winevtlog_subscribe(ch->name, ctx, bookmark, ch->query, ch->session);
                if (re_ch != NULL) {
                    close_handles(ch);

                    ch->bookmark = re_ch->bookmark;
                    ch->subscription = re_ch->subscription;
                    ch->signal_event = re_ch->signal_event;
                    ch->session = re_ch->session;
                }
                else {
                    flb_plg_error(ctx->ins, "Failed to subscribe with bookmark XML: %s\n", record.bookmark_xml);
                    ch->bookmark = EvtCreateBookmark(NULL);
                }
            }
            else {
                flb_plg_error(ctx->ins, "Failed to load bookmark XML with %d\n", GetLastError());
                ch->bookmark = EvtCreateBookmark(NULL);
            }
        }
        if (bookmark_xml) {
            flb_free(bookmark_xml);
        }
    }
    return 0;
}

/*
 * Save the bookmark into SQLite DB.
 */
int winevtlog_sqlite_save(struct winevtlog_channel *ch, struct winevtlog_config *ctx, struct flb_sqldb *db)
{
    int ret;
    char query[1024];
    PWSTR wide_bookmark_xml = NULL;
    char *bookmark_xml;
    int used_size = 0;

    wide_bookmark_xml = render_event(ch->bookmark, EvtRenderBookmark, &used_size);
    if (wide_bookmark_xml == NULL) {
        flb_plg_error(ctx->ins, "failed to render bookmark with %d", GetLastError());
        flb_free(wide_bookmark_xml);

        return -1;
    }
    bookmark_xml = convert_wstr(wide_bookmark_xml, CP_UTF8);
    if (bookmark_xml == NULL) {
        flb_plg_error(ctx->ins, "failed to convert Wider string with %d", GetLastError());
        flb_free(wide_bookmark_xml);
        flb_free(bookmark_xml);

        return -1;
    }

    snprintf(query, sizeof(query) - 1, SQL_UPDATE_CHANNEL,
             ch->name, bookmark_xml, ch->time_updated, time(NULL));

    ret = flb_sqldb_query(db, query, NULL, NULL);
    if (ret == FLB_ERROR) {
        flb_plg_error(ctx->ins, "failed to save db with %d", GetLastError());
        flb_free(wide_bookmark_xml);
        flb_free(bookmark_xml);

        return -1;
    }

    flb_free(wide_bookmark_xml);
    flb_free(bookmark_xml);

    return 0;
}
