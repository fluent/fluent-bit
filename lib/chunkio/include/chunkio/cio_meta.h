/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018 Eduardo Silva <eduardo@monkey.io>
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

#ifndef CIO_META_H
#define CIO_META_H

#include <chunkio/cio_file.h>
#include <chunkio/cio_chunk.h>

int cio_meta_write(struct cio_chunk *ch, char *buf, size_t size);
int cio_meta_read(struct cio_chunk *ch, char **meta_buf, int *meta_len);
int cio_meta_cmp(struct cio_chunk *ch, char *meta_buf, int meta_len);
int cio_meta_size(struct cio_chunk *ch);

#endif
