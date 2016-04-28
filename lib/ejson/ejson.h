/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  eJSON
 *  =====
 *  Copyright 2016 Eduardo Silva <eduardo@monkey.io>
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

#ifndef EJS_H
#define EJS_H

#include <inttypes.h>

#define EJS_ENTRIES_MAX   16

#define EJS_ERROR_NOMEM   -1
#define EJS_ERROR_INVAL   -2
#define EJS_ERROR_PART    -3
#define EJS_ERROR_ENTRIES -4
#define EJS_OK             0

#define EJS_OBJECT         1
#define EJS_ARRAY          2
#define EJS_STRING         3
#define EJS_NUM            4
#define EJS_BOOL           5
#define EJS_MAP_KEY        6

#define EJS_TYPE(c)        (c->entries_toc[c->entries_pos])
#define EJS_TYPE_ADD(c, t) (c->entries_toc[c->entries_pos++] = t)
#define EJS_TYPE_DEL(c)    (c->entries_pos--)

struct ejs_ctx {
    uint8_t entries_pos;
    uint8_t entries_toc[EJS_ENTRIES_MAX];
    unsigned int buf_pos;
    size_t buf_size;
};

int ejs_init(struct ejs_ctx *ctx, unsigned int buf_size);
int ejs_buf_size(struct ejs_ctx *ctx, unsigned int buf_size);
int ejs_add_array(struct ejs_ctx *ctx, unsigned char *buf);
int ejs_end_array(struct ejs_ctx *ctx, unsigned char *buf);
int ejs_add_string(struct ejs_ctx *ctx, unsigned char *buf,
                   unsigned char *str, size_t length);
int ejs_add_map(struct ejs_ctx *ctx, unsigned char *buf);
int ejs_add_map_key(struct ejs_ctx *ctx, unsigned char *buf,
                    unsigned char *k_buf, size_t k_length);
int ejs_end_map(struct ejs_ctx *ctx, unsigned char *buf);
int ejs_add_num(struct ejs_ctx *ctx, unsigned char *buf, double val);

#endif
