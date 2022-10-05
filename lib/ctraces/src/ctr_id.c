/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CTraces
 *  =======
 *  Copyright 2022 The CTraces Authors
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

#include <ctraces/ctraces.h>

/* create an ID with random bytes of length CTR_ID_BUFFER_SIZE (16 bytes) */
struct ctrace_id *ctr_id_create_random()
{
    char *buf;
    ssize_t ret;
    struct ctrace_id *cid;

    buf = calloc(1, CTR_ID_BUFFER_SIZE);
    if (!buf) {
        ctr_errno();
        return NULL;
    }

    ret = ctr_random_get(buf, CTR_ID_BUFFER_SIZE);
    if (ret < 0) {
        free(buf);
        return NULL;
    }

    cid = ctr_id_create(buf, CTR_ID_BUFFER_SIZE);
    free(buf);

    return cid;
}

void ctr_id_destroy(struct ctrace_id *cid)
{
    cfl_sds_destroy(cid->buf);
    free(cid);
}

struct ctrace_id *ctr_id_create(void *buf, size_t len)
{
    int ret;
    struct ctrace_id *cid;

    if (len <= 0) {
        return NULL;
    }

    cid = calloc(1, sizeof(struct ctrace_id));
    if (!cid) {
        ctr_errno();
        return NULL;
    }

    ret = ctr_id_set(cid, buf, len);
    if (ret == -1) {
        free(cid);
        return NULL;
    }

    return cid;
}

int ctr_id_set(struct ctrace_id *cid, void *buf, size_t len)
{
    if (cid->buf) {
        cfl_sds_destroy(cid->buf);
    }

    cid->buf = cfl_sds_create_len(buf, len);
    if (!cid->buf) {
        return -1;
    }

    return 0;
}

int ctr_id_cmp(struct ctrace_id *cid1, struct ctrace_id *cid2)
{
    int len1;
    int len2;

    if (!cid1 || !cid2) {
        return -1;
    }

    len1 = cfl_sds_len(cid1->buf);
    len2 = cfl_sds_len(cid2->buf);

    if (len1 != len2) {
        return -1;
    }

    if (memcmp(cid1->buf, cid2->buf, len1) == 0) {
        return 0;
    }

    return -1;
}

size_t ctr_id_get_len(struct ctrace_id *cid)
{
    return cfl_sds_len(cid->buf);
}

void *ctr_id_get_buf(struct ctrace_id *cid)
{
    return cid->buf;
}

cfl_sds_t ctr_id_to_lower_base16(struct ctrace_id *cid)
{
    int i;
    int len;
    cfl_sds_t out;
    const char hex[] = "0123456789abcdef";

    if (!cid->buf) {
        return NULL;
    }

    len = cfl_sds_len(cid->buf);
    out = cfl_sds_create_size(len * 2);
    if (!out) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        out[i * 2] = hex[(cid->buf[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[(cid->buf[i] >> 0) & 0xF];
    }

    return out;
}
