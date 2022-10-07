/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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


/*
 * This file is a helper utility just to try out all the encoders: given a specific
 * CMetrics context, encode to all possible formats and destroy them. This is
 * useful to trap potential memory leaks or errors when doing changes to the
 * metric types.
 */

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_encode_prometheus_remote_write.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_encode_opentelemetry.h>
#include <cmetrics/cmt_encode_text.h>
#include <cmetrics/cmt_encode_influx.h>

int cmt_test_encode_all(struct cmt *cmt)
{
    char *out_buf;
    size_t out_size;
    cfl_sds_t sds_buf;

    /* text */
    sds_buf = cmt_encode_text_create(cmt);
    cmt_encode_text_destroy(sds_buf);

    /* prometheus */
    sds_buf = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    cmt_encode_prometheus_destroy(sds_buf);

    /* prometheus remote write */
    sds_buf = cmt_encode_prometheus_remote_write_create(cmt);
    cmt_encode_prometheus_remote_write_destroy(sds_buf);

    /* msgpack */
    cmt_encode_msgpack_create(cmt, &out_buf, &out_size);
    cmt_encode_msgpack_destroy(out_buf);

    /* influx */
    sds_buf = cmt_encode_influx_create(cmt);
    cmt_encode_influx_destroy(sds_buf);

    /* opentelemetry */
    sds_buf = cmt_encode_opentelemetry_create(cmt);
    cmt_encode_opentelemetry_destroy(sds_buf);

    return 0;
}
