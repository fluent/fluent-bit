/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018-2021 Eduardo Silva <eduardo@monkey.io>
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

#ifndef CIO_ERROR_H
#define CIO_ERROR_H

#include <chunkio/chunkio.h>
#include <chunkio/cio_chunk.h>

/*
 * Error status (do not confuse with return statuses!)
 */
#define CIO_ERR_BAD_CHECKSUM  -10      /* Chunk has a bad checksum */
#define CIO_ERR_BAD_LAYOUT    -11      /* Bad magic bytes or general layout */
#define CIO_ERR_PERMISSION    -12      /* Permission error */
#define CIO_ERR_BAD_FILE_SIZE -13      /* Chunk has a bad file size */

char *cio_error_get_str(struct cio_chunk *ch);
int cio_error_get(struct cio_chunk *ch);
void cio_error_set(struct cio_chunk *ch, int status);
void cio_error_reset(struct cio_chunk *ch);

#endif