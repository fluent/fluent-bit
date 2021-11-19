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

struct winevtlog_channel *winevtlog_subscribe(const char *channel, int read_existing_events,
                                              EVT_HANDLE bookmark)
{
    struct winevtlog_channel *ch;
    EVT_HANDLE hBookmark = NULL;
    HANDLE hSignalEvent = NULL;
    DWORD len, flags = 0L;
    PWSTR wChannel = L"Application", wQuery = L"*";
    void *buf;

    ch = flb_calloc(1, sizeof(struct winevtlog_channel));
    if (!ch) {
        flb_errno();
        return NULL;
    }

    ch->name = flb_strdup(channel);
    if (!ch->name) {
        flb_errno();
        flb_free(ch);
        return NULL;
    }

    hSignalEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    // channel : To wide char
    len = MultiByteToWideChar(CP_UTF8, 0, channel, -1, NULL, 0);
    wChannel = flb_malloc(sizeof(PWSTR) * len);
    MultiByteToWideChar(CP_UTF8, 0, channel, -1, wChannel, len);

    if (bookmark) {
        flags |= EvtSubscribeStartAfterBookmark;
    } else if (read_existing_events) {
        flags |= EvtSubscribeStartAtOldestRecord;
    } else {
        flags |= EvtSubscribeToFutureEvents;
    }

    ch->subscription = EvtSubscribe(NULL, hSignalEvent, wChannel, wQuery, bookmark, NULL, NULL, flags);
    if (!ch->subscription) {
        flb_error("[in_winevtlog] cannot subscribe '%s' (%i)", channel, GetLastError());
        flb_free(ch->name);
        flb_free(ch);
        return NULL;
    }
    ch->signal_event = hSignalEvent;

    if (bookmark) {
        ch->bookmark = bookmark;
    }
    else {
        hBookmark = EvtCreateBookmark(NULL);
        if (hBookmark) {
            ch->bookmark = hBookmark;
        }
        else {
            if (ch->subscription) {
                EvtClose(ch->subscription);
            }
            if (hSignalEvent) {
                CloseHandle(hSignalEvent);
            }
            flb_error("[in_winevtlog] cannot subscribe '%s' (%i)", channel, GetLastError());
            flb_free(wChannel);
            flb_free(ch->name);
            flb_free(ch);
            return NULL;
        }
    }

    flb_free(wChannel);

    return ch;
}

BOOL cancel_subscription(struct winevtlog_channel *ch)
{
    return EvtCancel(ch->subscription);
}

static void close_handles(struct winevtlog_channel *ch)
{
    if (ch->subscription) {
        EvtClose(ch->subscription);
        ch->subscription = NULL;
    }
    if (ch->signal_event) {
        CloseHandle(ch->signal_event);
        ch->signal_event = NULL;
    }
    if (ch->bookmark) {
        EvtClose(ch->bookmark);
        ch->bookmark = NULL;
    }
    for (int i = 0; i < ch->count; i++) {
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
    close_handles(ch);

    flb_free(ch);
}

// Render the event as an XML string and print it.
PWSTR render_event(EVT_HANDLE hEvent, DWORD flags, unsigned int *event_size)
{
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD count = 0;
    LPWSTR wEventXML = NULL;

    if (flags != EvtRenderEventXml && flags != EvtRenderBookmark) {
        flb_error("Invalid flags is specified: %d", flags);
        return NULL;
    }

    if (!EvtRender(NULL, hEvent, flags, dwBufferSize, wEventXML, &dwBufferUsed, &count))
    {
        status = GetLastError();
        if (status == ERROR_INSUFFICIENT_BUFFER)
        {
            dwBufferSize = dwBufferUsed;
            /* return buffer size */
            *event_size = dwBufferSize;
            wEventXML = (LPWSTR)flb_malloc(dwBufferSize);
            if (wEventXML)
            {
                EvtRender(NULL, hEvent, flags, dwBufferSize, wEventXML, &dwBufferUsed, &count);
            }
            else
            {
                flb_error("malloc failed");
                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != (status = GetLastError()))
        {
            flb_error("EvtRender failed with %d", GetLastError());
            goto cleanup;
        }
    }

    return wEventXML;

cleanup:

    if (wEventXML) {
        flb_free(wEventXML);
    }

    return NULL;
}

DWORD render_system_event(EVT_HANDLE hEvent, PEVT_VARIANT *pSystem, unsigned int *system_size)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hContext = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    PEVT_VARIANT pValues = NULL;

    hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    if (NULL == hContext) {
        status = GetLastError();
        flb_error("failed to create RenderContext with %d", status);

        goto cleanup;
    }
    if (!EvtRender(hContext,
                   hEvent,
                   EvtRenderEventValues,
                   dwBufferSize,
                   pValues,
                   &dwBufferUsed,
                   &dwPropertyCount)) {
        status = GetLastError();

        if (status == ERROR_INSUFFICIENT_BUFFER) {
            dwBufferSize = dwBufferUsed;
            pValues = (PEVT_VARIANT)flb_malloc(dwBufferSize);
            if (pValues) {
                EvtRender(hContext,
                          hEvent,
                          EvtRenderEventValues,
                          dwBufferSize,
                          pValues,
                          &dwBufferUsed,
                          &dwPropertyCount);
                status = GetLastError();
                *system_size = dwBufferUsed;
            } else {
                if (pValues)
                    flb_free(pValues);

                flb_error("failed to malloc memory with %d", status);

                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != status) {
            EvtClose(hContext);
            flb_free(pValues);

            return status;
        }
    }

    *pSystem = pValues;

cleanup:

    if (hContext)
        EvtClose(hContext);

    return status;
}


PWSTR get_message(EVT_HANDLE hMetadata, EVT_HANDLE handle, unsigned int *message_size)
{
    WCHAR* pBuffer = NULL;
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    LPVOID lpMsgBuf;
    WCHAR* wMessage = NULL;
    char *error_message = NULL;

    // Get the size of the buffer
    if (!EvtFormatMessage(hMetadata, handle, 0, 0, NULL,
                          EvtFormatMessageEvent, dwBufferSize, pBuffer, &dwBufferUsed)) {
        status = GetLastError();
        if (ERROR_INSUFFICIENT_BUFFER == status) {
            dwBufferSize = dwBufferUsed;
            pBuffer = flb_malloc(sizeof(WCHAR) * dwBufferSize);
            if (!pBuffer) {
                flb_error("failed to malloc message buffer");

                goto cleanup;
            }
            if (!EvtFormatMessage(hMetadata,
                                  handle,
                                  0xffffffff,
                                  0,
                                  NULL,
                                  EvtFormatMessageEvent,
                                  dwBufferSize,
                                  pBuffer,
                                  &dwBufferUsed)) {
                status = GetLastError();
                *message_size = dwBufferUsed;

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
                                               (WCHAR*)(&lpMsgBuf),
                                               0,
                                               NULL) == 0)
                                FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                               FORMAT_MESSAGE_IGNORE_INSERTS,
                                               NULL,
                                               status,
                                               MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                                               (WCHAR*)(&lpMsgBuf),
                                               0,
                                               NULL);
                            error_message = convert_wstr((WCHAR*)lpMsgBuf, CP_ACP);
                            flb_error("Failed to get message with %d, err = %s", status, error_message);
                            flb_free(error_message);

                            wMessage = _wcsdup((WCHAR*)lpMsgBuf);
                            LocalFree(lpMsgBuf);

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

    wMessage = _wcsdup(pBuffer);

cleanup:
    if (pBuffer)
        flb_free(pBuffer);

    return wMessage;
}

PWSTR get_description(EVT_HANDLE handle, LANGID langID, unsigned int *message_size)
{
    WCHAR *wBuffer[EVENT_PROVIDER_NAME_LENGTH];
    PEVT_VARIANT pValues = NULL;
    DWORD dwBufferUsed = 0;
    DWORD status = ERROR_SUCCESS, count = 0;
    WCHAR *wMessage = NULL;
    EVT_HANDLE hMetadata = NULL;

    PCWSTR eventProperties[] = { L"Event/System/Provider/@Name" };
    EVT_HANDLE hContext =
            EvtCreateRenderContext(1, eventProperties, EvtRenderContextValues);
    if (hContext == NULL) {
        flb_error("Failed to create renderContext");
        goto cleanup;
    }

    if (EvtRender(hContext,
                  handle,
                  EvtRenderEventValues,
                  EVENT_PROVIDER_NAME_LENGTH,
                  wBuffer,
                  &dwBufferUsed,
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
    pValues = (PEVT_VARIANT)wBuffer;

    hMetadata = EvtOpenPublisherMetadata(
            NULL, // TODO: Remote handle
            pValues[0].StringVal,
            NULL,
            MAKELCID(langID, SORT_DEFAULT),
            0);
    if (hMetadata == NULL) {
        goto cleanup;
    }

    wMessage = get_message(hMetadata, handle, message_size);

cleanup:
    if (hContext) {
        EvtClose(hContext);
    }

    if (hMetadata) {
        EvtClose(hMetadata);
    }

    return wMessage;
}

int get_string_inserts(EVT_HANDLE handle, PEVT_VARIANT *values, UINT *prop_count, unsigned int *string_inserts_size)
{
    PEVT_VARIANT pValues;
    DWORD dwBufferSize = 0;
    DWORD dwBufferSizeUsed = 0;
    DWORD dwPropCount = 0;
    BOOL succeeded = FLB_TRUE;

    EVT_HANDLE hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextUser);
    if (hContext == NULL) {
        flb_error("Failed to create renderContext");
        succeeded = FLB_FALSE;
        goto cleanup;
    }

    // Get the size of the buffer
    EvtRender(hContext, handle, EvtRenderEventValues, 0, NULL, &dwBufferSize, &dwPropCount);
    pValues = (PEVT_VARIANT)flb_malloc(dwBufferSize);

    succeeded = EvtRender(hContext,
                          handle,
                          EvtRenderContextValues,
                          dwBufferSize,
                          pValues,
                          &dwBufferSizeUsed,
                          &dwPropCount);

    if (!succeeded) {
        flb_error("Failed to get string inserts with %d\n", GetLastError());
        goto cleanup;
    }

    *prop_count = dwPropCount;
    *values = pValues;
    *string_inserts_size = dwBufferSize;

cleanup:

    if (hContext != NULL)
        EvtClose(hContext);

    return succeeded;
}

static int winevtlog_next(struct winevtlog_channel *ch, int hit_threshold)
{
    EVT_HANDLE hEvents[SUBSCRIBE_ARRAY_SIZE];
    DWORD count = 0;
    DWORD status = ERROR_SUCCESS;
    BOOL has_next = FALSE;

    /* If subscription handle is NULL, it should return false. */
    if (!ch->subscription) {
        flb_error("Invalid subscription is passed");
        return FLB_FALSE;
    }

    if (hit_threshold) {
        return FLB_FALSE;
    }

    has_next = EvtNext(ch->subscription, SUBSCRIBE_ARRAY_SIZE,
                       hEvents, INFINITE, 0, &count);

    if (!has_next) {
        status = GetLastError();
        if (ERROR_CANCELLED == status) {
            return FLB_FALSE;
        }
        if (ERROR_NO_MORE_ITEMS != status) {
            return FLB_FALSE;
        }
    }

    if (status == ERROR_SUCCESS) {
        ch->count = count;
        for (int i = 0; i < count; i++) {
            ch->events[i] = hEvents[i];
            EvtUpdateBookmark(ch->bookmark, ch->events[i]);
        }

        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/*
 * Read from an open Windows Event Log channel.
 */
int winevtlog_read(struct winevtlog_channel *ch, msgpack_packer *mp_pck, struct winevtlog_config *ctx,
                   unsigned int *read)
{
    DWORD status = ERROR_SUCCESS;
    PWSTR wSystem = NULL;
    unsigned int system_size = 0;
    unsigned int message_size = 0;
    unsigned int string_inserts_size = 0;
    int hit_threshold = FLB_FALSE;
    unsigned int read_size = 0;
    PWSTR wMessage = NULL;
    PEVT_VARIANT pSystem = NULL;
    PEVT_VARIANT pStringInserts = NULL;
    UINT countInserts = 0;
    DWORD i = 0;

    while (winevtlog_next(ch, hit_threshold)) {
        for (DWORD i = 0; i < ch->count; i++) {
            if (ctx->render_event_as_xml) {
                wSystem = render_event(ch->events[i], EvtRenderEventXml, &system_size);
                wMessage = get_description(ch->events[i], LANG_NEUTRAL, &message_size);
                get_string_inserts(ch->events[i], &pStringInserts, &countInserts, &string_inserts_size);
                if (wSystem) {
                    /* Caluculate total allocated size: system + message + string_inserts */
                    read_size += (system_size + message_size + string_inserts_size);
                    winevtlog_pack_xml_event(mp_pck, wSystem, wMessage, pStringInserts, countInserts, ch, ctx);

                    flb_free(pStringInserts);
                    flb_free(wSystem);
                    if (wMessage)
                        flb_free(wMessage);
                }
            }
            else {
                render_system_event(ch->events[i], &pSystem, &system_size);
                wMessage = get_description(ch->events[i], LANG_NEUTRAL, &message_size);
                get_string_inserts(ch->events[i], &pStringInserts, &countInserts, &string_inserts_size);
                if (pSystem) {
                    /* Caluculate total allocated size: system + message + string_inserts */
                    read_size += (system_size + message_size + string_inserts_size);
                    winevtlog_pack_event(mp_pck, pSystem, wMessage, pStringInserts, countInserts, ch, ctx);

                    flb_free(pStringInserts);
                    flb_free(pSystem);
                    if (wMessage)
                        flb_free(wMessage);
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

    return 0;
}

/*
 * Open multiple channels at once. The return value is a linked
 * list of winevtlog_channel objects.
 *
 * "channels" are comma-separated names like "Setup,Security".
 */
struct mk_list *winevtlog_open_all(const char *channels, int read_existing_events)
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
        ch = winevtlog_subscribe(channel, read_existing_events, NULL);
        if (!ch) {
            flb_free(tmp);
            winevtlog_close_all(list);
            return NULL;
        }
        mk_list_add(&ch->_head, list);
        channel = strtok_s(NULL, ",", &state);
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
    if (size == 0)
        return NULL;

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
    if (size == 0)
        return NULL;

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
int winevtlog_sqlite_load(struct winevtlog_channel *ch, struct flb_sqldb *db)
{
    int ret;
    char query[1024];
    struct winevtlog_sqlite_record record = {0};
    EVT_HANDLE hBookmark = NULL;
    PWSTR wBookmarkXML = NULL;
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
        wBookmarkXML = convert_str(record.bookmark_xml);
        if (wBookmarkXML) {
            hBookmark = EvtCreateBookmark(wBookmarkXML);
            if (hBookmark) {
                /* re-create subscription handles */
                re_ch = winevtlog_subscribe(ch->name, FLB_FALSE, hBookmark);
                if (re_ch != NULL) {
                    close_handles(ch);

                    ch->bookmark = re_ch->bookmark;
                    ch->subscription = re_ch->subscription;
                    ch->signal_event = re_ch->signal_event;
                }
                else {
                    flb_error("Failed to subscribe with bookmarkXML: %s\n", record.bookmark_xml);
                    ch->bookmark = EvtCreateBookmark(NULL);
                }
            }
            else {
                flb_error("Failed to load bookmarkXML with %d\n", GetLastError());
                ch->bookmark = EvtCreateBookmark(NULL);
            }
        }
        if (wBookmarkXML) {
            flb_free(wBookmarkXML);
        }
    }
    return 0;
}

/*
 * Save the bookmark into SQLite DB.
 */
int winevtlog_sqlite_save(struct winevtlog_channel *ch, struct flb_sqldb *db)
{
    int ret;
    char query[1024];
    PWSTR wBookmarkXML = NULL;
    char *bookmarkXML;
    int used_size = 0;

    wBookmarkXML = render_event(ch->bookmark, EvtRenderBookmark, &used_size);
    if (wBookmarkXML == NULL) {
        flb_error("failed to render bookmark with %d", GetLastError());
        flb_free(wBookmarkXML);

        return -1;
    }
    bookmarkXML = convert_wstr(wBookmarkXML, CP_UTF8);
    if (bookmarkXML == NULL) {
        flb_error("failed to convert Wider string with %d", GetLastError());
        flb_free(wBookmarkXML);
        flb_free(bookmarkXML);

        return -1;
    }

    snprintf(query, sizeof(query) - 1, SQL_UPDATE_CHANNEL,
             ch->name, bookmarkXML, ch->time_updated, time(NULL));

    ret = flb_sqldb_query(db, query, NULL, NULL);
    if (ret == FLB_ERROR) {
        flb_error("failed to save db with %d", GetLastError());
        flb_free(wBookmarkXML);
        flb_free(bookmarkXML);

        return -1;
    }

    flb_free(wBookmarkXML);
    flb_free(bookmarkXML);

    return 0;
}
