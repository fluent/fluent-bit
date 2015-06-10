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
#include "dbg.h"
#include "protocol.h"

const char *fcgi_msg_type_str[] = {
	[0]                      = "NULL MSG TYPE",
	[FCGI_BEGIN_REQUEST]     = "FCGI_BEGIN_REQUEST",
	[FCGI_ABORT_REQUEST]     = "FCGI_ABORT_REQUEST",
	[FCGI_END_REQUEST]       = "FCGI_END_REQUEST",
	[FCGI_PARAMS]            = "FCGI_PARAMS",
	[FCGI_STDIN]             = "FCGI_STDIN",
	[FCGI_STDOUT]            = "FCGI_STDOUT",
	[FCGI_STDERR]            = "FCGI_STDERR",
	[FCGI_DATA]              = "FCGI_DATA",
	[FCGI_GET_VALUES]        = "FCGI_GET_VALUES",
	[FCGI_GET_VALUES_RESULT] = "FCGI_GET_VALUES_RESULT",
	[FCGI_UNKNOWN_TYPE]      = "FCGI_UNKNOWN_TYPE",
};

const char *fcgi_role_str[] = {
	[0]               = "NULL ROLE",
	[FCGI_RESPONDER]  = "FCGI_RESPONDER",
	[FCGI_AUTHORIZER] = "FCGI_AUTHORIZER",
	[FCGI_FILTER]     = "FCGI_FILTER",
};

const char *fcgi_protocol_status_str[] = {
	[FCGI_REQUEST_COMPLETE] = "FCGI_REQUEST_COMPLETE",
	[FCGI_CANT_MPX_CONN]    = "FCGI_CANT_MPX_CONN",
	[FCGI_OVERLOADED]       = "FCGI_OVERLOADED",
	[FCGI_UNKNOWN_ROLE]     = "FCGI_UNKNOWN_ROLE",
};

int fcgi_validate_struct_sizes(void)
{
	struct fcgi_header header;
	struct fcgi_begin_req_body begin_body;
	struct fcgi_end_req_body end_body;

	check(FCGI_HEADER_LEN == sizeof(header),
		"sizeof(header) does not match FCGI_HEADER_LEN.");
	check(FCGI_BEGIN_BODY_LEN == sizeof(begin_body),
		"sizeof(begin_body) does not match FCGI_BEGIN_BODY_LEN.");
	check(FCGI_END_BODY_LEN == sizeof(end_body),
		"sizeof(end_body) does not match FCGI_END_BODY_LEN.");

	return 0;
error:
	return -1;
}

size_t fcgi_read_header(uint8_t *p, struct fcgi_header *h)
{
	h->version  = p[0];
	h->type     = p[1];
	h->req_id   = (p[2] << 8) + p[3];
	h->body_len = (p[4] << 8) + p[5];
	h->body_pad = p[6];

	return sizeof(*h);
}

size_t fcgi_write_header(uint8_t *p, const struct fcgi_header *h)
{
	p[0] = h->version;
	p[1] = h->type;
	p[2] = (h->req_id >> 8)   & 0xff;
	p[3] = (h->req_id)        & 0xff;
	p[4] = (h->body_len >> 8) & 0xff;
	p[5] = (h->body_len)      & 0xff;
	p[6] = h->body_pad;

	return sizeof(*h);
}

size_t fcgi_read_end_req_body(uint8_t *p, struct fcgi_end_req_body *b)
{
	b->app_status      = (p[0] << 24) + (p[1] << 16);
	b->app_status     += (p[2] << 8)  + p[3];
	b->protocol_status = p[4];

	return sizeof(*b);
}

size_t fcgi_write_begin_req_body(uint8_t *p, const struct fcgi_begin_req_body *b)
{
	p[0] = (b->role >> 8) & 0xff;
	p[1] = (b->role)      & 0xff;
	p[2] = b->flags;

	return sizeof(*b);
}


static uint32_t fcgi_param_read_length(uint8_t *p)
{
	size_t len;

	if (p[0] >> 7 == 1) {
		len  = (p[0] & 0x7f) << 24;
		len += (p[1])        << 16;
		len += (p[2])        <<  8;
		len += (p[3]);
	} else {
		len = p[0];
	}

	return len;
}

static size_t write_length(uint8_t *p, size_t len)
{
	if (len > 127) {
		p[0]  = 1 << 7;
		p[0] += (len >> 24) & 0x7f;
		p[1]  = (len >> 16) & 0xff;
		p[2]  = (len >>  8) & 0xff;
		p[3]  = (len)       & 0xff;

		return 4;
	} else {
		p[0] = len & 0x7f;

		return 1;
	}
}

size_t fcgi_param_write(uint8_t *p,
	mk_ptr_t key,
	mk_ptr_t value)
{
	size_t ret, cnt;

	if (!p) {
		cnt  = (key.len > 127 ? 4 : 1) + (value.len > 127 ? 4 : 1);
		cnt += key.len + value.len;
		return cnt;
	}

	cnt  = 0;
	ret  = write_length(p + cnt, key.len);
	cnt += ret;

	ret  = write_length(p + cnt, value.len);
	cnt += ret;

	memcpy(p + cnt, key.data, key.len);
	cnt += key.len;

	memcpy(p + cnt, value.data, value.len);
	cnt += value.len;

	return cnt;
}

int fcgi_param_entry_next(struct fcgi_param_entry *e)
{
	e->position += e->key_len + e->value_len;
	check_debug(e->position < e->base_len, "At end of buffer.");

	e->key_len = fcgi_param_read_length(e->base + e->position);
	e->position += e->key_len > 127 ? 4 : 1;

	e->value_len = fcgi_param_read_length(e->base + e->position);
	e->position += e->value_len > 127 ? 4 : 1;

	return 0;
error:
	return -1;
}

void fcgi_param_entry_init(struct fcgi_param_entry *e,
		uint8_t *p,
		size_t p_len)
{
	e->key_len   = 0;
	e->value_len = 0;
	e->position  = 0;
	e->base_len  = p_len;
	e->base      = p;

	fcgi_param_entry_next(e);
}

void fcgi_param_entry_reset(struct fcgi_param_entry *e)
{
	e->key_len   = 0;
	e->value_len = 0;
	e->position  = 0;

	fcgi_param_entry_next(e);
}

int fcgi_param_entry_search(struct fcgi_param_entry *e, mk_ptr_t key)
{
	mk_ptr_t e_key;

	do {
		e_key = fcgi_param_entry_key(e);
		if (e_key.len == key.len && !bcmp(e_key.data, key.data, key.len)) {
			return 0;
		}
	} while (fcgi_param_entry_next(e) != -1);

	return -1;
}

mk_ptr_t fcgi_param_entry_key(struct fcgi_param_entry *e)
{
	return (mk_ptr_t){
		.data = (char *)e->base + e->position,
		.len  = e->key_len,
	};
}

mk_ptr_t fcgi_param_entry_value(struct fcgi_param_entry *e)
{
	return (mk_ptr_t){
		.data = (char *)e->base + e->position + e->key_len,
		.len  = e->value_len,
	};
}
