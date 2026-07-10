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
#include <wchar.h>
#include "winevtlog.h"

#define EVENT_PROVIDER_NAME_LENGTH 256

static char* convert_wstr(wchar_t *wstr, UINT codePage);
static wchar_t* convert_str(char *str);

static const char *skip_spaces(const char *cursor)
{
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        cursor++;
    }

    return cursor;
}

static char *trim_spaces(char *value)
{
    char *end;

    value = (char *) skip_spaces(value);
    end = value + strlen(value);

    while (end > value &&
           (*(end - 1) == ' ' || *(end - 1) == '\t' ||
            *(end - 1) == '\r' || *(end - 1) == '\n')) {
        end--;
    }
    *end = '\0';

    return value;
}

static int query_is_structured_xml(const char *query)
{
    const unsigned char *cursor;

    if (query == NULL) {
        return FLB_FALSE;
    }

    cursor = (const unsigned char *) query;

    if (strlen((const char *) cursor) >= 3 &&
        cursor[0] == 0xef && cursor[1] == 0xbb && cursor[2] == 0xbf) {
        cursor += 3;
    }

    cursor = (const unsigned char *) skip_spaces((const char *) cursor);

    return *cursor == '<';
}

static const char *xml_tag_end(const char *tag)
{
    char quote = '\0';

    while (*tag != '\0') {
        if (quote != '\0') {
            if (*tag == quote) {
                quote = '\0';
            }
        }
        else if (*tag == '\'' || *tag == '"') {
            quote = *tag;
        }
        else if (*tag == '>') {
            return tag + 1;
        }
        tag++;
    }

    return NULL;
}

static int xml_tag_is(const char *tag, const char *name, int closing)
{
    size_t name_length;

    if (*tag != '<') {
        return FLB_FALSE;
    }
    tag++;

    if (closing) {
        if (*tag != '/') {
            return FLB_FALSE;
        }
        tag++;
    }
    else if (*tag == '/') {
        return FLB_FALSE;
    }

    tag = skip_spaces(tag);
    name_length = strlen(name);

    if (strncasecmp(tag, name, name_length) != 0) {
        return FLB_FALSE;
    }

    tag += name_length;
    return *tag == '>' || *tag == '/' || *tag == ' ' || *tag == '\t' ||
           *tag == '\r' || *tag == '\n';
}

static int xml_attribute(const char *tag, const char *tag_end, const char *name,
                         const char **value, size_t *value_length)
{
    char quote;
    size_t attribute_length;
    size_t name_length;
    const char *cursor;
    const char *attribute;
    const char *value_end;

    name_length = strlen(name);
    cursor = tag + 1;

    if (*cursor == '/') {
        cursor++;
    }
    cursor = skip_spaces(cursor);
    while (cursor < tag_end &&
           *cursor != ' ' && *cursor != '\t' && *cursor != '\r' &&
           *cursor != '\n' && *cursor != '>' && *cursor != '/') {
        cursor++;
    }

    while (cursor < tag_end && *cursor != '>' && *cursor != '/') {
        cursor = skip_spaces(cursor);

        if (cursor >= tag_end || *cursor == '>' || *cursor == '/') {
            break;
        }

        attribute = cursor;
        while (cursor < tag_end &&
               *cursor != '=' && *cursor != ' ' && *cursor != '\t' &&
               *cursor != '\r' && *cursor != '\n' &&
               *cursor != '>' && *cursor != '/') {
            cursor++;
        }
        attribute_length = cursor - attribute;
        cursor = skip_spaces(cursor);

        if (cursor >= tag_end || *cursor != '=') {
            return FLB_FALSE;
        }
        cursor = skip_spaces(cursor + 1);
        if (cursor >= tag_end || (*cursor != '\'' && *cursor != '"')) {
            return FLB_FALSE;
        }

        quote = *cursor;
        cursor++;
        value_end = cursor;
        while (value_end < tag_end && *value_end != quote) {
            value_end++;
        }
        if (value_end >= tag_end) {
            return FLB_FALSE;
        }

        if (attribute_length == name_length &&
            strncasecmp(attribute, name, name_length) == 0) {
            *value = cursor;
            *value_length = value_end - *value;
            return FLB_TRUE;
        }
        cursor = value_end + 1;
    }

    return FLB_FALSE;
}

static const wchar_t *wxml_tag_end(const wchar_t *tag)
{
    wchar_t quote = L'\0';

    while (*tag != L'\0') {
        if (quote != L'\0') {
            if (*tag == quote) {
                quote = L'\0';
            }
        }
        else if (*tag == L'\'' || *tag == L'"') {
            quote = *tag;
        }
        else if (*tag == L'>') {
            return tag + 1;
        }
        tag++;
    }

    return NULL;
}

static int wxml_tag_is(const wchar_t *tag, const wchar_t *name, int closing)
{
    size_t name_length;

    if (*tag != L'<') {
        return FLB_FALSE;
    }
    tag++;

    if (closing) {
        if (*tag != L'/') {
            return FLB_FALSE;
        }
        tag++;
    }
    else if (*tag == L'/') {
        return FLB_FALSE;
    }

    while (*tag == L' ' || *tag == L'\t' || *tag == L'\r' || *tag == L'\n') {
        tag++;
    }

    name_length = wcslen(name);
    if (wcsncmp(tag, name, name_length) != 0) {
        return FLB_FALSE;
    }

    tag += name_length;
    return *tag == L'>' || *tag == L'/' || *tag == L' ' || *tag == L'\t' ||
           *tag == L'\r' || *tag == L'\n';
}

static int wxml_attribute(const wchar_t *tag, const wchar_t *tag_end,
                          const wchar_t *name, const wchar_t **value,
                          size_t *value_length)
{
    wchar_t quote;
    size_t attribute_length;
    size_t name_length;
    const wchar_t *cursor;
    const wchar_t *attribute;
    const wchar_t *value_end;

    name_length = wcslen(name);
    cursor = tag + 1;

    if (*cursor == L'/') {
        cursor++;
    }
    while (*cursor == L' ' || *cursor == L'\t' || *cursor == L'\r' || *cursor == L'\n') {
        cursor++;
    }
    while (cursor < tag_end && *cursor != L' ' && *cursor != L'\t' &&
           *cursor != L'\r' && *cursor != L'\n' && *cursor != L'>' &&
           *cursor != L'/') {
        cursor++;
    }

    while (cursor < tag_end && *cursor != L'>' && *cursor != L'/') {
        while (*cursor == L' ' || *cursor == L'\t' ||
               *cursor == L'\r' || *cursor == L'\n') {
            cursor++;
        }

        if (cursor >= tag_end || *cursor == L'>' || *cursor == L'/') {
            break;
        }

        attribute = cursor;
        while (cursor < tag_end && *cursor != L'=' && *cursor != L' ' &&
               *cursor != L'\t' && *cursor != L'\r' && *cursor != L'\n' &&
               *cursor != L'>' && *cursor != L'/') {
            cursor++;
        }
        attribute_length = cursor - attribute;

        while (*cursor == L' ' || *cursor == L'\t' ||
               *cursor == L'\r' || *cursor == L'\n') {
            cursor++;
        }
        if (cursor >= tag_end || *cursor != L'=') {
            return FLB_FALSE;
        }

        cursor++;
        while (*cursor == L' ' || *cursor == L'\t' ||
               *cursor == L'\r' || *cursor == L'\n') {
            cursor++;
        }
        if (cursor >= tag_end || (*cursor != L'\'' && *cursor != L'"')) {
            return FLB_FALSE;
        }

        quote = *cursor++;
        value_end = cursor;
        while (value_end < tag_end && *value_end != quote) {
            value_end++;
        }
        if (value_end >= tag_end) {
            return FLB_FALSE;
        }

        if (attribute_length == name_length &&
            wcsncmp(attribute, name, name_length) == 0) {
            *value = cursor;
            *value_length = value_end - cursor;
            return FLB_TRUE;
        }
        cursor = value_end + 1;
    }

    return FLB_FALSE;
}

static PWSTR wxml_decode_attribute(const wchar_t *value, size_t value_length)
{
    size_t input_index;
    size_t output_index = 0;
    PWSTR output;

    output = flb_malloc(sizeof(wchar_t) * (value_length + 1));
    if (output == NULL) {
        flb_errno();
        return NULL;
    }

    for (input_index = 0; input_index < value_length; input_index++) {
        if (value[input_index] != L'&') {
            output[output_index++] = value[input_index];
            continue;
        }

        if (input_index + 5 <= value_length &&
            wcsncmp(&value[input_index], L"&amp;", 5) == 0) {
            output[output_index++] = L'&';
            input_index += 4;
        }
        else if (input_index + 4 <= value_length &&
                 wcsncmp(&value[input_index], L"&lt;", 4) == 0) {
            output[output_index++] = L'<';
            input_index += 3;
        }
        else if (input_index + 4 <= value_length &&
                 wcsncmp(&value[input_index], L"&gt;", 4) == 0) {
            output[output_index++] = L'>';
            input_index += 3;
        }
        else if (input_index + 6 <= value_length &&
                 wcsncmp(&value[input_index], L"&quot;", 6) == 0) {
            output[output_index++] = L'"';
            input_index += 5;
        }
        else if (input_index + 6 <= value_length &&
                 wcsncmp(&value[input_index], L"&apos;", 6) == 0) {
            output[output_index++] = L'\'';
            input_index += 5;
        }
        else {
            flb_free(output);
            return NULL;
        }
    }

    output[output_index] = L'\0';
    return output;
}

static void winevtlog_event_template_destroy(struct winevtlog_event_template *event_template)
{
    UINT index;

    if (event_template == NULL) {
        return;
    }

    for (index = 0; index < event_template->data_count; index++) {
        flb_free(event_template->data_names[index]);
    }
    flb_free(event_template->data_names);
    flb_free(event_template->cache_key);
    flb_free(event_template->provider_name);
    flb_free(event_template);
}

void winevtlog_event_template_cache_destroy(struct winevtlog_config *ctx)
{
    struct winevtlog_event_template *event_template;
    struct mk_list *head;
    struct mk_list *tmp;

    if (ctx == NULL) {
        return;
    }

    if (ctx->event_template_cache != NULL) {
        flb_hash_table_destroy(ctx->event_template_cache);
        ctx->event_template_cache = NULL;
    }

    mk_list_foreach_safe(head, tmp, &ctx->event_templates) {
        event_template = mk_list_entry(head,
                                       struct winevtlog_event_template,
                                       _head);
        mk_list_del(&event_template->_head);
        winevtlog_event_template_destroy(event_template);
    }
}

static char *event_template_cache_key(PCWSTR provider_name, DWORD event_id,
                                      DWORD version, size_t *key_length)
{
    int provider_length;
    int suffix_length;
    size_t provider_utf8_length;
    char suffix[32];
    char *key;

    provider_length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                          provider_name, -1, NULL, 0, NULL,
                                          NULL);
    if (provider_length == 0) {
        return NULL;
    }

    suffix_length = _snprintf_s(suffix, sizeof(suffix), _TRUNCATE,
                                "|%lu|%lu", event_id, version);
    if (suffix_length <= 0) {
        return NULL;
    }

    provider_utf8_length = (size_t) provider_length - 1;
    key = flb_malloc(provider_utf8_length + (size_t) suffix_length + 1);
    if (key == NULL) {
        flb_errno();
        return NULL;
    }

    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, provider_name, -1,
                            key, provider_length, NULL, NULL) == 0) {
        flb_free(key);
        return NULL;
    }

    memcpy(&key[provider_utf8_length], suffix, (size_t) suffix_length + 1);
    *key_length = provider_utf8_length + (size_t) suffix_length;
    return key;
}

static struct winevtlog_event_template *event_template_cache_find(
        struct winevtlog_config *ctx, PCWSTR provider_name,
        DWORD event_id, DWORD version)
{
    char *cache_key;
    size_t cache_key_length;
    size_t cache_value_size;
    void *cache_value;
    struct winevtlog_event_template *event_template;

    if (ctx->event_template_cache == NULL) {
        return NULL;
    }

    cache_key = event_template_cache_key(provider_name, event_id, version,
                                         &cache_key_length);
    if (cache_key == NULL) {
        return NULL;
    }

    if (flb_hash_table_get(ctx->event_template_cache, cache_key,
                           (int) cache_key_length, &cache_value,
                           &cache_value_size) < 0) {
        flb_free(cache_key);
        return NULL;
    }

    flb_free(cache_key);
    event_template = cache_value;
    mk_list_del(&event_template->_head);
    mk_list_add(&event_template->_head, &ctx->event_templates);
    return event_template;
}

static int event_template_cache_evict(struct winevtlog_config *ctx)
{
    struct winevtlog_event_template *event_template;

    while (mk_list_size(&ctx->event_templates) >=
           ctx->event_template_cache_size) {
        event_template = mk_list_entry_first(&ctx->event_templates,
                                              struct winevtlog_event_template,
                                              _head);
        if (flb_hash_table_del_ptr(ctx->event_template_cache,
                                   event_template->cache_key,
                                   (int) event_template->cache_key_length,
                                   event_template) != 0) {
            return -1;
        }
        mk_list_del(&event_template->_head);
        winevtlog_event_template_destroy(event_template);
    }

    return 0;
}

static struct winevtlog_event_template *event_template_cache_create(
        struct winevtlog_config *ctx, PCWSTR provider_name,
        DWORD event_id, DWORD version)
{
    size_t provider_name_length;
    struct winevtlog_event_template *event_template;

    event_template = flb_calloc(1, sizeof(struct winevtlog_event_template));
    if (event_template == NULL) {
        flb_errno();
        return NULL;
    }

    provider_name_length = wcslen(provider_name);
    event_template->provider_name = flb_malloc(sizeof(wchar_t) *
                                                (provider_name_length + 1));
    if (event_template->provider_name == NULL) {
        flb_errno();
        winevtlog_event_template_destroy(event_template);
        return NULL;
    }

    memcpy(event_template->provider_name, provider_name,
           sizeof(wchar_t) * (provider_name_length + 1));
    event_template->event_id = event_id;
    event_template->version = version;

    event_template->cache_key = event_template_cache_key(provider_name,
                                                          event_id, version,
                                                          &event_template->cache_key_length);
    if (event_template->cache_key == NULL ||
        event_template_cache_evict(ctx) != 0 ||
        flb_hash_table_add(ctx->event_template_cache,
                           event_template->cache_key,
                           (int) event_template->cache_key_length,
                           event_template, 0) < 0) {
        winevtlog_event_template_destroy(event_template);
        return NULL;
    }

    mk_list_add(&event_template->_head, &ctx->event_templates);

    return event_template;
}

static int event_template_append_name(struct winevtlog_event_template *event_template,
                                      PWSTR name)
{
    PWSTR *new_names;
    UINT index;

    if (name == NULL || name[0] == L'\0') {
        return -1;
    }

    for (index = 0; index < event_template->data_count; index++) {
        if (wcscmp(event_template->data_names[index], name) == 0) {
            return -1;
        }
    }

    new_names = flb_realloc(event_template->data_names,
                            sizeof(PWSTR) * (event_template->data_count + 1));
    if (new_names == NULL) {
        flb_errno();
        return -1;
    }

    event_template->data_names = new_names;
    event_template->data_names[event_template->data_count++] = name;
    return 0;
}

static int event_template_parse_data_names(
        struct winevtlog_event_template *event_template,
        PCWSTR template_xml)
{
    const wchar_t *cursor;
    const wchar_t *tag_end;
    const wchar_t *name;
    size_t name_length;
    PWSTR decoded_name;

    if (template_xml == NULL) {
        return -1;
    }

    cursor = template_xml;
    while ((cursor = wcschr(cursor, L'<')) != NULL) {
        tag_end = wxml_tag_end(cursor);
        if (tag_end == NULL) {
            return -1;
        }

        if (wxml_tag_is(cursor, L"data", FLB_FALSE)) {
            if (!wxml_attribute(cursor, tag_end, L"name", &name, &name_length)) {
                return -1;
            }

            decoded_name = wxml_decode_attribute(name, name_length);
            if (decoded_name == NULL ||
                event_template_append_name(event_template, decoded_name) != 0) {
                flb_free(decoded_name);
                return -1;
            }
        }
        cursor = tag_end;
    }

    return 0;
}

static int event_metadata_get_uint32(EVT_HANDLE event_metadata,
                                     EVT_EVENT_METADATA_PROPERTY_ID property_id,
                                     DWORD *value)
{
    DWORD buffer_size = 0;
    DWORD buffer_used = 0;
    PEVT_VARIANT property = NULL;
    DWORD status;
    int result = -1;

    if (EvtGetEventMetadataProperty(event_metadata, property_id, 0, 0, NULL,
                                    &buffer_size)) {
        return -1;
    }

    status = GetLastError();
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        return -1;
    }

    property = flb_malloc(buffer_size);
    if (property == NULL) {
        flb_errno();
        return -1;
    }

    if (!EvtGetEventMetadataProperty(event_metadata, property_id, 0,
                                     buffer_size, property, &buffer_used) ||
        (property->Type & EVT_VARIANT_TYPE_MASK) != EvtVarTypeUInt32) {
        goto cleanup;
    }

    *value = property->UInt32Val;
    result = 0;

cleanup:
    flb_free(property);
    return result;
}

static PWSTR event_metadata_get_template(EVT_HANDLE event_metadata)
{
    DWORD buffer_size = 0;
    DWORD buffer_used = 0;
    PEVT_VARIANT property = NULL;
    PWSTR template_xml = NULL;
    size_t template_length;
    DWORD status;

    if (EvtGetEventMetadataProperty(event_metadata,
                                    EventMetadataEventTemplate,
                                    0, 0, NULL, &buffer_size)) {
        return NULL;
    }

    status = GetLastError();
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        return NULL;
    }

    property = flb_malloc(buffer_size);
    if (property == NULL) {
        flb_errno();
        return NULL;
    }

    if (!EvtGetEventMetadataProperty(event_metadata,
                                     EventMetadataEventTemplate,
                                     0, buffer_size, property, &buffer_used) ||
        (property->Type & EVT_VARIANT_TYPE_MASK) != EvtVarTypeString ||
        property->StringVal == NULL) {
        goto cleanup;
    }

    template_length = wcslen(property->StringVal);
    template_xml = flb_malloc(sizeof(wchar_t) * (template_length + 1));
    if (template_xml == NULL) {
        flb_errno();
        goto cleanup;
    }

    memcpy(template_xml, property->StringVal,
           sizeof(wchar_t) * (template_length + 1));

cleanup:
    flb_free(property);
    return template_xml;
}

static void event_template_load(struct winevtlog_event_template *event_template,
                                EVT_HANDLE remote,
                                struct winevtlog_config *ctx)
{
    DWORD event_id;
    DWORD version;
    DWORD status;
    EVT_HANDLE event_metadata = NULL;
    EVT_HANDLE event_metadata_enum = NULL;
    EVT_HANDLE publisher_metadata = NULL;
    PWSTR template_xml = NULL;

    publisher_metadata = EvtOpenPublisherMetadata(
            remote, event_template->provider_name, NULL,
            MAKELCID(LANG_NEUTRAL, SORT_DEFAULT), 0);
    if (publisher_metadata == NULL) {
        flb_plg_debug(ctx->ins,
                      "could not open publisher metadata for event data map: %lu",
                      GetLastError());
        goto cleanup;
    }

    event_metadata_enum = EvtOpenEventMetadataEnum(publisher_metadata, 0);
    if (event_metadata_enum == NULL) {
        flb_plg_debug(ctx->ins,
                      "could not enumerate publisher event metadata: %lu",
                      GetLastError());
        goto cleanup;
    }

    while (FLB_TRUE) {
        event_metadata = EvtNextEventMetadata(event_metadata_enum, 0);
        if (event_metadata == NULL) {
            status = GetLastError();
            if (status != ERROR_NO_MORE_ITEMS) {
                flb_plg_debug(ctx->ins,
                              "could not read publisher event metadata: %lu",
                              status);
            }
            break;
        }

        if (event_metadata_get_uint32(event_metadata, EventMetadataEventID,
                                      &event_id) == 0 &&
            event_metadata_get_uint32(event_metadata, EventMetadataEventVersion,
                                      &version) == 0 &&
            event_id == event_template->event_id &&
            version == event_template->version) {
            template_xml = event_metadata_get_template(event_metadata);
            if (template_xml == NULL) {
                flb_plg_debug(ctx->ins,
                              "could not read event metadata template for event %lu",
                              event_template->event_id);
                break;
            }

            if (event_template_parse_data_names(event_template,
                                                template_xml) == 0 &&
                event_template->data_count > 0) {
                event_template->valid = FLB_TRUE;
                flb_plg_debug(ctx->ins,
                              "loaded EventData template for %ls, event %lu version %lu: %u fields",
                              event_template->provider_name,
                              event_template->event_id,
                              event_template->version,
                              event_template->data_count);
            }
            else {
                flb_plg_debug(ctx->ins,
                              "EventData template has no usable names for %ls, event %lu version %lu",
                              event_template->provider_name,
                              event_template->event_id,
                              event_template->version);
            }
            break;
        }

        EvtClose(event_metadata);
        event_metadata = NULL;
    }

cleanup:
    if (template_xml != NULL) {
        flb_free(template_xml);
    }
    if (event_metadata != NULL) {
        EvtClose(event_metadata);
    }
    if (event_metadata_enum != NULL) {
        EvtClose(event_metadata_enum);
    }
    if (publisher_metadata != NULL) {
        EvtClose(publisher_metadata);
    }
}

struct winevtlog_event_template *winevtlog_event_template_get(
        PEVT_VARIANT system, EVT_HANDLE remote,
        struct winevtlog_config *ctx)
{
    DWORD event_id;
    DWORD version;
    PCWSTR provider_name;
    struct winevtlog_event_template *event_template;

    if (ctx == NULL || system == NULL ||
        (system[EvtSystemProviderName].Type & EVT_VARIANT_TYPE_MASK) !=
                EvtVarTypeString ||
        system[EvtSystemProviderName].StringVal == NULL ||
        (system[EvtSystemEventID].Type & EVT_VARIANT_TYPE_MASK) !=
                EvtVarTypeUInt16) {
        return NULL;
    }

    provider_name = system[EvtSystemProviderName].StringVal;
    event_id = system[EvtSystemEventID].UInt16Val;
    version = 0;

    if ((system[EvtSystemVersion].Type & EVT_VARIANT_TYPE_MASK) ==
            EvtVarTypeByte) {
        version = system[EvtSystemVersion].ByteVal;
    }

    event_template = event_template_cache_find(ctx, provider_name,
                                               event_id, version);
    if (event_template != NULL) {
        return event_template;
    }

    event_template = event_template_cache_create(ctx, provider_name,
                                                 event_id, version);
    if (event_template == NULL) {
        return NULL;
    }

    event_template_load(event_template, remote, ctx);
    return event_template;
}

static int path_matches_channel(const char *path, size_t path_length,
                                const char *channel)
{
    size_t channel_length;

    if (path == NULL) {
        return FLB_FALSE;
    }

    channel_length = strlen(channel);
    if (channel_length != path_length) {
        return FLB_FALSE;
    }

    return strncasecmp(path, channel, path_length) == 0;
}

static const char *xml_element_end(const char *element, const char *limit,
                                   const char *name)
{
    const char *cursor;
    const char *tag_end;

    tag_end = xml_tag_end(element);
    if (tag_end == NULL || tag_end > limit) {
        return NULL;
    }

    if (tag_end >= element + 2 && *(tag_end - 2) == '/') {
        return tag_end;
    }

    cursor = tag_end;
    while (cursor < limit) {
        cursor = strchr(cursor, '<');
        if (cursor == NULL || cursor >= limit) {
            return NULL;
        }
        if (xml_tag_is(cursor, name, FLB_TRUE)) {
            tag_end = xml_tag_end(cursor);
            if (tag_end == NULL || tag_end > limit) {
                return NULL;
            }
            return tag_end;
        }
        cursor++;
    }

    return NULL;
}

static int query_for_channel(const char *query, const char *channel,
                             flb_sds_t *channel_query)
{
    int matches = 0;
    int query_selects;
    flb_sds_t output;
    flb_sds_t query_body;
    const char *cursor;
    const char *query_start;
    const char *query_open_end;
    const char *query_close;
    const char *query_end;
    const char *element_start;
    const char *element_open_end;
    const char *element_end;
    const char *query_path;
    const char *element_path;
    const char *effective_path;
    const char *element_name;
    size_t query_path_length;
    size_t element_path_length;
    size_t effective_path_length;

    *channel_query = NULL;

    if (!query_is_structured_xml(query)) {
        if (query != NULL) {
            *channel_query = flb_sds_create(query);
            if (*channel_query == NULL) {
                return -1;
            }
        }
        return 0;
    }

    output = flb_sds_create("<QueryList>");
    if (output == NULL) {
        return -1;
    }

    cursor = query;
    while ((query_start = strchr(cursor, '<')) != NULL) {
        if (!xml_tag_is(query_start, "Query", FLB_FALSE)) {
            cursor = query_start + 1;
            continue;
        }

        query_open_end = xml_tag_end(query_start);
        if (query_open_end == NULL) {
            flb_sds_destroy(output);
            return -1;
        }

        query_close = query_open_end;
        while ((query_close = strchr(query_close, '<')) != NULL) {
            if (xml_tag_is(query_close, "Query", FLB_TRUE)) {
                break;
            }
            query_close++;
        }
        if (query_close == NULL) {
            flb_sds_destroy(output);
            return -1;
        }

        query_end = xml_tag_end(query_close);
        if (query_end == NULL) {
            flb_sds_destroy(output);
            return -1;
        }

        query_path = NULL;
        query_path_length = 0;
        xml_attribute(query_start, query_open_end, "Path",
                      &query_path, &query_path_length);

        query_body = flb_sds_create_size(query_end - query_start);
        if (query_body == NULL) {
            flb_sds_destroy(output);
            return -1;
        }

        query_selects = 0;
        element_start = query_open_end;
        while ((element_start = strchr(element_start, '<')) != NULL &&
               element_start < query_close) {
            if (xml_tag_is(element_start, "Select", FLB_FALSE)) {
                element_name = "Select";
            }
            else if (xml_tag_is(element_start, "Suppress", FLB_FALSE)) {
                element_name = "Suppress";
            }
            else {
                element_start++;
                continue;
            }

            element_open_end = xml_tag_end(element_start);
            if (element_open_end == NULL || element_open_end > query_close) {
                flb_sds_destroy(query_body);
                flb_sds_destroy(output);
                return -1;
            }

            element_end = xml_element_end(element_start, query_close, element_name);
            if (element_end == NULL) {
                flb_sds_destroy(query_body);
                flb_sds_destroy(output);
                return -1;
            }

            element_path = NULL;
            element_path_length = 0;
            if (xml_attribute(element_start, element_open_end, "Path",
                              &element_path, &element_path_length)) {
                effective_path = element_path;
                effective_path_length = element_path_length;
            }
            else {
                effective_path = query_path;
                effective_path_length = query_path_length;
            }

            if (path_matches_channel(effective_path, effective_path_length, channel)) {
                if (flb_sds_cat_safe(&query_body, element_start,
                                     element_end - element_start) != 0) {
                    flb_sds_destroy(query_body);
                    flb_sds_destroy(output);
                    return -1;
                }
                if (strcasecmp(element_name, "Select") == 0) {
                    query_selects++;
                }
            }
            element_start = element_end;
        }

        if (query_selects > 0) {
            if (flb_sds_cat_safe(&output, query_start,
                                 query_open_end - query_start) != 0 ||
                flb_sds_cat_safe(&output, query_body,
                                 flb_sds_len(query_body)) != 0 ||
                flb_sds_cat_safe(&output, query_close,
                                 query_end - query_close) != 0) {
                flb_sds_destroy(query_body);
                flb_sds_destroy(output);
                return -1;
            }
            matches++;
        }

        flb_sds_destroy(query_body);
        cursor = query_end;
    }

    if (matches == 0) {
        flb_sds_destroy(output);
        return 1;
    }

    if (flb_sds_cat_safe(&output, "</QueryList>", 12) != 0) {
        flb_sds_destroy(output);
        return -1;
    }

    *channel_query = output;
    return 0;
}

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
    int structured_query;

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
    ch->remote = NULL;
    structured_query = query_is_structured_xml(query);

    signal_event = CreateEvent(NULL, TRUE, TRUE, NULL);

    if (!structured_query) {
        /* channel : To wide char */
        len = MultiByteToWideChar(CP_UTF8, 0, channel, -1, NULL, 0);
        wide_channel = flb_malloc(sizeof(WCHAR) * len);
        if (wide_channel == NULL) {
            if (signal_event) {
                CloseHandle(signal_event);
            }
            flb_free(ch->name);
            if (ch->query) {
                flb_free(ch->query);
            }
            flb_free(ch);
            return NULL;
        }
        if (0 == MultiByteToWideChar(CP_UTF8, 0, channel, -1, wide_channel, len)) {
            if (signal_event) {
                CloseHandle(signal_event);
            }
            flb_free(wide_channel);
            flb_free(ch->name);
            if (ch->query) {
                flb_free(ch->query);
            }
            flb_free(ch);
            return NULL;
        }
    }
    if (query != NULL) {
        /* query : To wide char */
        len = MultiByteToWideChar(CP_UTF8, 0, query, -1, NULL, 0);
        wide_query = flb_malloc(sizeof(WCHAR) * len);
       if (wide_query == NULL) {
            if (signal_event) {
                CloseHandle(signal_event);
            }
            flb_free(wide_channel);
            flb_free(ch->name);
            if (ch->query) {
                flb_free(ch->query);
            }
            flb_free(ch);
            return NULL;
        }
        if (0 == MultiByteToWideChar(CP_UTF8, 0, query, -1, wide_query, len)) {
            if (signal_event) {
                CloseHandle(signal_event);
            }
            flb_free(wide_query);
            flb_free(wide_channel);
            flb_free(ch->name);
            if (ch->query) {
                flb_free(ch->query);
            }
            flb_free(ch);
            return NULL;
        }
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
     * ChannelPath must be NULL for structured XML queries because Windows ignores
     * it and the query itself defines all subscribed channels.
     * ref. https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe
     */
    ch->subscription = EvtSubscribe(remote_handle, signal_event, wide_channel, wide_query,
                                    stored_bookmark, NULL, NULL, flags);
    err = GetLastError();
    if (!ch->subscription) {
        flb_plg_error(ctx->ins, "cannot subscribe '%s' (%i)", channel, err);
        if (signal_event) {
            CloseHandle(signal_event);
        }
        if (ch->remote) {
            EvtClose(ch->remote);
        }
        if (wide_channel) {
            flb_free(wide_channel);
        }
        if (wide_query) {
            flb_free(wide_query);
        }
        flb_free(ch->name);
        if (ch->query != NULL) {
            flb_free(ch->query);
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

PWSTR get_description(EVT_HANDLE handle, LANGID langID, unsigned int *message_size, HANDLE remote)
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
                remote,
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
    PEVT_VARIANT values = NULL;
    DWORD buffer_size = 0;
    DWORD buffer_size_used = 0;
    DWORD count = 0;
    BOOL succeeded = FLB_TRUE;

    if (string_inserts_values == NULL || prop_count == NULL ||
        string_inserts_size == NULL) {
        return FLB_FALSE;
    }

    *string_inserts_values = NULL;
    *prop_count = 0;
    *string_inserts_size = 0;

    EVT_HANDLE context = EvtCreateRenderContext(0, NULL, EvtRenderContextUser);
    if (context == NULL) {
        flb_error("Failed to create renderContext");
        succeeded = FLB_FALSE;
        goto cleanup;
    }

    // Get the size of the buffer
    if (EvtRender(context, handle, EvtRenderEventValues, 0, NULL,
                  &buffer_size, &count)) {
        if (count == 0) {
            goto cleanup;
        }
        flb_error("Unexpected successful string inserts size query");
        succeeded = FLB_FALSE;
        goto cleanup;
    }
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        flb_error("Failed to get string inserts size with %d", GetLastError());
        succeeded = FLB_FALSE;
        goto cleanup;
    }

    values = (PEVT_VARIANT)flb_malloc(buffer_size);
    if (values == NULL) {
        flb_errno();
        succeeded = FLB_FALSE;
        goto cleanup;
    }

    succeeded = EvtRender(context,
                          handle,
                          EvtRenderEventValues,
                          buffer_size,
                          values,
                          &buffer_size_used,
                          &count);

    if (!succeeded) {
        flb_error("Failed to get string inserts with %d", GetLastError());
        goto cleanup;
    }

    *prop_count = count;
    *string_inserts_values = values;
    *string_inserts_size = buffer_size;

cleanup:

    if (!succeeded && values != NULL) {
        flb_free(values);
    }

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
                /* Consume this flag and return early */
                ch->cancelled_by_us = FALSE;
                return FLB_FALSE;
            }
            ch->reconnect_needed = TRUE;
            ch->last_error = status;
            flb_warn("[in_winevtlog] subscription cancelled unexpectedly (err=%lu), will reconnect", status);
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

static const struct winevtlog_backoff WINEVTLOG_BACKOFF_DEFAULTS = {
    500,     /* base_ms */
    30000,   /* max_ms  */
    2000,    /* multiplier_x1000 == x2.0 */
    20,      /* jitter_pct */
    8        /* max_retries */
};

static inline void backoff_effective(struct winevtlog_backoff *dst,
                                     const struct winevtlog_backoff *src)
{
    if (src) {
        *dst = *src;
    }
    else {
        *dst = WINEVTLOG_BACKOFF_DEFAULTS;
    }
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
    DWORD jitter = 0;
    double mult = (double)cfg->multiplier_x1000 / 1000.0;
    double t = (double)cfg->base_ms;

    for (i = 0; i < attempt; i++) {
        t *= mult;
        if (t >= (double)cfg->max_ms) { t = (double)cfg->max_ms; break; }
    }
    ms = (DWORD)((t > (double)cfg->max_ms) ? cfg->max_ms : t);
    /* ±jitter% (clamped 0..100) */
    jitter = cfg->jitter_pct > 100 ? 100 : cfg->jitter_pct;
    span = (LONG)((ms * jitter) / 100);
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
    backoff_effective(&cfg, ctx ? &ctx->backoff : NULL);
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

    if (!query_is_structured_xml(ch->query)) {
        len = MultiByteToWideChar(CP_UTF8, 0, ch->name, -1, NULL, 0);
        if (len == 0) {
            return -1;
        }
        wide_channel = flb_malloc(sizeof(WCHAR) * len);
        if (!wide_channel) {
            return -1;
        }
        if (MultiByteToWideChar(CP_UTF8, 0, ch->name, -1,
                                wide_channel, len) == 0) {
            flb_free(wide_channel);
            return -1;
        }
    }

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
    unsigned int system_xml_size = 0;
    unsigned int message_size = 0;
    unsigned int string_inserts_size = 0;
    int hit_threshold = FLB_FALSE;
    unsigned int read_size = 0;
    PWSTR message = NULL;
    PEVT_VARIANT rendered_system = NULL;
    PEVT_VARIANT string_inserts = NULL;
    struct winevtlog_event_template *event_template = NULL;
    UINT count_inserts = 0;
    DWORD i = 0;
    int rc = 0;

    while (winevtlog_next(ch, hit_threshold)) {
        for (i = 0; i < ch->count; i++) {
            system_xml = NULL;
            rendered_system = NULL;
            message = NULL;
            string_inserts = NULL;
            system_size = 0;
            system_xml_size = 0;
            message_size = 0;
            string_inserts_size = 0;
            count_inserts = 0;
            event_template = NULL;

            if (ctx->render_event_as_xml) {
                system_xml = render_event(ch->events[i], EvtRenderEventXml,
                                          &system_xml_size);
                message = get_description(ch->events[i], LANG_NEUTRAL, &message_size, ch->remote);
                if (ctx->event_data_as_map) {
                    render_system_event(ch->events[i], &rendered_system,
                                        &system_size);
                    if (rendered_system != NULL) {
                        event_template = winevtlog_event_template_get(rendered_system,
                                                                       ch->remote, ctx);
                    }
                }
                if (get_string_inserts(ch->events[i], &string_inserts,
                                       &count_inserts,
                                       &string_inserts_size) && system_xml) {
                    /* Calculate allocated size: XML + system + message + inserts. */
                    read_size += (system_xml_size + system_size + message_size +
                                  string_inserts_size);
                    winevtlog_pack_xml_event(system_xml, message, string_inserts,
                                             count_inserts, event_template, ch, ctx);
                }

                flb_free(string_inserts);
                flb_free(system_xml);
                flb_free(rendered_system);
                if (message) {
                    flb_free(message);
                }
            }
            else if (ctx->render_event_as_text) {
                render_system_event(ch->events[i], &rendered_system, &system_size);
                message = get_description(ch->events[i], LANG_NEUTRAL, &message_size, ch->remote);
                if (ctx->event_data_as_map && rendered_system != NULL) {
                    event_template = winevtlog_event_template_get(rendered_system,
                                                                   ch->remote, ctx);
                }
                if (get_string_inserts(ch->events[i], &string_inserts,
                                       &count_inserts,
                                       &string_inserts_size) && rendered_system) {
                    /* Calculate allocated size: system + message + inserts. */
                    read_size += (system_size + message_size + string_inserts_size);
                    winevtlog_pack_text_event(rendered_system, message, string_inserts,
                                              count_inserts, event_template, ch, ctx);

                }

                flb_free(string_inserts);
                flb_free(rendered_system);
                if (message) {
                    flb_free(message);
                }
            }
            else {
                render_system_event(ch->events[i], &rendered_system, &system_size);
                message = get_description(ch->events[i], LANG_NEUTRAL, &message_size, ch->remote);
                if (ctx->event_data_as_map && rendered_system != NULL) {
                    event_template = winevtlog_event_template_get(rendered_system,
                                                                   ch->remote, ctx);
                }
                if (get_string_inserts(ch->events[i], &string_inserts,
                                       &count_inserts,
                                       &string_inserts_size) && rendered_system) {
                    /* Calculate allocated size: system + message + inserts. */
                    read_size += (system_size + message_size + string_inserts_size);
                    winevtlog_pack_event(rendered_system, message, string_inserts,
                                         count_inserts, event_template, ch, ctx);
                }

                flb_free(string_inserts);
                flb_free(rendered_system);
                if (message) {
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
                backoff_effective(&eff, ctx ? &ctx->backoff : NULL);
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
    int ret;
    flb_sds_t channel_query;
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
        channel = trim_spaces(channel);
        ret = query_for_channel(ctx->event_query, channel, &channel_query);
        if (ret == 1) {
            flb_plg_debug(ctx->ins,
                          "channel '%s' is not selected by the structured query",
                          channel);
            channel = strtok_s(NULL, ",", &state);
            continue;
        }
        else if (ret != 0) {
            flb_plg_error(ctx->ins,
                          "could not create the event query for channel '%s'",
                          channel);
            flb_free(tmp);
            winevtlog_close_all(list);
            return NULL;
        }

        ch = winevtlog_subscribe(channel, ctx, NULL, channel_query,
                                 ctx->session);
        flb_sds_destroy(channel_query);
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

    buf = flb_malloc(sizeof(WCHAR) * size);
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
