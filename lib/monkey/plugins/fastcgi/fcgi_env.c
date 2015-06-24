/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
 *  Copyright 2012, Sonny Karlsson
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

#include <monkey/mk_api.h>
#include <ctype.h> /* toupper */
#include <sys/socket.h> /* getsockname, getpeername */
#include <arpa/inet.h> /* inet_ntop */


#include "dbg.h"
#include "protocol.h"

#define __write_param(env, len, pos, key, value) do { \
		check(len - pos > 8 + key.len + value.len, "Out of memory.");   \
		pos += fcgi_param_write(env + pos, key, value);                 \
	} while (0)

size_t fcgi_env_write(uint8_t *ptr,
                      const size_t len,
                      struct mk_http_session *cs,
                      struct mk_http_request *sr)
{
    unsigned int i;
	mk_ptr_t key, value;
	char buffer[256];
	char *tmpuri = NULL;
	size_t pos = 0;
	socklen_t addr_len;
	struct sockaddr_in addr;
    struct mk_http_parser *parser;
    struct mk_http_header *header;
    struct mk_list *head;

    parser = &cs->parser;

	mk_api->pointer_set(&key,   "GATEWAY_INTERFACE");
	mk_api->pointer_set(&value, "CGI/1.1");
	__write_param(ptr, len, pos, key, value);

	mk_api->pointer_set(&key,   "REDIRECT_STATUS");
	mk_api->pointer_set(&value, "200");
	__write_param(ptr, len, pos, key, value);

	mk_api->pointer_set(&key,   "SERVER_SOFTWARE");
	mk_api->pointer_set(&value, mk_api->config->server_signature);
	__write_param(ptr, len, pos, key, value);

	mk_api->pointer_set(&key,   "DOCUMENT_ROOT");
	value = sr->host_conf->documentroot;
	__write_param(ptr, len, pos, key, value);

	mk_api->pointer_set(&key,   "SERVER_PROTOCOL");
	value = sr->protocol_p;
	__write_param(ptr, len, pos, key, value);

	mk_api->pointer_set(&key,   "SERVER_NAME");
	value.data = sr->host_alias->name;
	value.len  = sr->host_alias->len;
	__write_param(ptr, len, pos, key, value);

	addr_len = sizeof(addr);
	if (!getsockname(cs->socket, (struct sockaddr *)&addr, &addr_len)) {
		if (!inet_ntop(AF_INET, &addr.sin_addr, buffer, 256)) {
			log_warn("Failed to get bound address.");
			buffer[0] = '\0';
		}
		mk_api->pointer_set(&key,   "SERVER_ADDR");
		mk_api->pointer_set(&value, buffer);
		__write_param(ptr, len, pos, key, value);

		snprintf(buffer, 256, "%d", ntohs(addr.sin_port));
		mk_api->pointer_set(&key,   "SERVER_PORT");
		mk_api->pointer_set(&value, buffer);
		__write_param(ptr, len, pos, key, value);
	} else {
		log_warn("%s", clean_errno());
		errno = 0;
	}

	mk_api->pointer_set(&key,   "SCRIPT_FILENAME");
	value = sr->real_path;
	__write_param(ptr, len, pos, key, value);

	mk_api->pointer_set(&key,   "SCRIPT_NAME");
	value = sr->uri_processed;
	__write_param(ptr, len, pos, key, value);

	mk_api->pointer_set(&key,   "REQUEST_METHOD");
	value = sr->method_p;
	__write_param(ptr, len, pos, key, value);

	addr_len = sizeof(addr);
	if (!getpeername(cs->socket, (struct sockaddr *)&addr, &addr_len)) {
		inet_ntop(AF_INET, &addr.sin_addr, buffer, 256);
		mk_api->pointer_set(&key,   "REMOTE_ADDR");
		mk_api->pointer_set(&value, buffer);
		__write_param(ptr, len, pos, key, value);

		snprintf(buffer, 256, "%d", ntohs(addr.sin_port));
		mk_api->pointer_set(&key,   "REMOTE_PORT");
		mk_api->pointer_set(&value, buffer);
		__write_param(ptr, len, pos, key, value);
	} else {
		log_warn("%s", clean_errno());
		errno = 0;
	}

	mk_api->pointer_set(&key,   "REQUEST_URI");
	if (sr->query_string.len > 0) {
		value.len = sr->uri.len + sr->query_string.len + 2;
		tmpuri = mk_api->mem_alloc(value.len);
		check_mem(tmpuri);
		value.data = tmpuri;
		snprintf(value.data, value.len, "%.*s?%.*s",
			(int)sr->uri.len, sr->uri.data,
			(int)sr->query_string.len, sr->query_string.data);
	} else {
		value = sr->uri;
	}
	__write_param(ptr, len, pos, key, value);

	mk_api->pointer_set(&key,   "QUERY_STRING");
	value = sr->query_string;
	__write_param(ptr, len, pos, key, value);

	mk_api->pointer_set(&key,   "CONTENT_TYPE");
	value = sr->content_type;
	__write_param(ptr, len, pos, key, value);

	if (sr->content_length > 0) {
		mk_api->pointer_set(&key,   "CONTENT_LENGTH");
		snprintf(buffer, 256, "%d", sr->content_length);
		mk_api->pointer_set(&value, buffer);
		__write_param(ptr, len, pos, key, value);
	}

	if (!strcmp(mk_api->config->transport, MK_TRANSPORT_HTTPS)) {
		mk_api->pointer_set(&key, "HTTPS");
		mk_api->pointer_set(&value, "on");
		__write_param(ptr, len, pos, key, value);
	}

	strcpy(buffer, "HTTP_");

    mk_list_foreach(head, &parser->header_list) {
        header = mk_list_entry(head, struct mk_http_header, _head);

        for (i = 0; i < header->key.len; i++) {
            if (header->key.data[i] != '-') {
                buffer[5 + i] = toupper(header->key.data[i]);
            }
			else {
				buffer[5 + i] = '_';
			}
        }

		key = (mk_ptr_t){.len = 5 + i, .data = buffer};
		value = (mk_ptr_t){.len = header->val.len, .data = header->val.data};

		__write_param(ptr, len, pos, key, value);

    }

	if (tmpuri) mk_api->mem_free(tmpuri);
	return pos;
error:
	if (tmpuri) mk_api->mem_free(tmpuri);
	return pos;
}

#undef __write_param
