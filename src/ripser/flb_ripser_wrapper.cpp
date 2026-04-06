/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2025 The Fluent Bit Authors
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

#include <vector>
#include <limits>
#include <cstring>
#include <cmath>
#include <algorithm>

/*
 * Include ripser core implementation.
 * Either include a header-only version or include ripser.cpp directly.
 * Only one compilation unit should compile ripser.cpp.
 */
#include <ripser_internal.hpp>

#include <fluent-bit/ripser/flb_ripser_wrapper.h>

/* -------------------------
 * Convert dense matrix → compressed lower-triangular matrix
 * -------------------------
 */
static compressed_lower_distance_matrix make_compressed_from_dense(
    const float *dist_matrix,
    size_t n_points)
{
    std::vector<value_t> lower;
    lower.reserve(n_points * (n_points - 1) / 2);

    for (size_t i = 0; i < n_points; ++i) {
        for (size_t j = 0; j < i; ++j) {
            float d = dist_matrix[i * n_points + j];
            lower.push_back(static_cast<value_t>(d));
        }
    }

    return compressed_lower_distance_matrix(std::move(lower));
}

/* -------------------------
 * Accumulate intervals into Betti numbers
 * -------------------------
 */
struct betti_accumulator {
    int max_dim;
    int num_dims;
    int betti[8];
};

/* Internal callback that increments Betti numbers.
 *
 * We treat intervals with death < 0 as "infinite" (i.e. essential
 * homology classes). This matches ripser.py's default Betti numbers,
 * where Betti_k is defined as the number of infinite bars in
 * dimension k.
 */
static void betti_interval_cb_impl(std::ptrdiff_t dim,
                                   float birth,
                                   float death,
                                   void *user_data)
{
    auto *acc = static_cast<betti_accumulator *>(user_data);
    if (dim < 0) {
        return;
    }
    size_t dim_index = static_cast<size_t>(dim);
    if (dim_index >= FLB_RIPSER_MAX_BETTI_DIM) {
        return;
    }

    if (!std::isfinite(birth) || !std::isfinite(death)) {
        return;
    }
    if (death <= birth) {
        return;
    }

    float persistence = death - birth;

    const float MIN_PERSIST = 1e-3f;
    if (persistence < MIN_PERSIST) {
        return;
    }

    int dim_i = (int)dim_index + 1;
    if (dim_i > acc->num_dims) {
        acc->num_dims = dim_i;
    }
    acc->betti[dim_index]++;
}

/* Bridge function: adapts ripser's interval callback to Betti accumulator */
static void interval_recorder_cb_bridge(
    int dim, value_t birth, value_t death, void *user_data)
{
    betti_interval_cb_impl(dim, birth, death, user_data);
}

/* -------------------------
 * Public C API: Betti numbers
 * -------------------------
 */
int flb_ripser_compute_betti_from_dense_distance(
    const float *dist_matrix,
    size_t       n_points,
    int          max_dim,
    float        threshold,
    flb_ripser_betti *out_betti)
{
    if (!dist_matrix || !out_betti || n_points == 0 || max_dim < 0) {
        return -1;
    }
    if (max_dim > 8) {
        max_dim = 8;
    }

    /* Initialize accumulator */
    betti_accumulator acc;
    std::memset(&acc, 0, sizeof(acc));
    acc.max_dim = max_dim + 1;

    /* Set up callback recorder */
    interval_recorder recorder;
    recorder.cb = &interval_recorder_cb_bridge;
    recorder.user_data = &acc;

    /* Convert matrix */
    compressed_lower_distance_matrix dist =
        make_compressed_from_dense(dist_matrix, n_points);

    /* threshold <= 0 → use Ripser's enclosing radius mode */
    value_t thr = (threshold > 0.0f)
                    ? static_cast<value_t>(threshold)
                    : std::numeric_limits<value_t>::max();

    /* Run Ripser */
    ripser_run_from_compressed_lower(
        std::move(dist),
        /*dim_max=*/max_dim,
        /*threshold=*/thr,
        /*ratio=*/1.0f,
        recorder);

    /* Fill output */
    out_betti->max_dim  = max_dim;
    out_betti->num_dims = acc.num_dims;
    for (int d = 0; d < out_betti->num_dims; ++d) {
        out_betti->betti[d] = acc.betti[d];
    }
    for (int d = out_betti->num_dims; d < 8; ++d) {
        out_betti->betti[d] = 0;
    }

    return 0;
}

/* -------------------------
 * Public C API: interval callback
 * -------------------------
 */

struct generic_interval_cb_bridge_ctx {
    flb_ripser_interval_cb user_cb;
    void *user_data;
};

/* Bridge Ripser→C-ABI callback */
static void generic_interval_cb_bridge(
    int dim, value_t birth, value_t death, void *user_data)
{
    generic_interval_cb_bridge_ctx *ctx =
        static_cast<generic_interval_cb_bridge_ctx*>(user_data);

    if (!ctx || !ctx->user_cb) return;

    flb_ripser_interval interval;
    interval.dim   = dim;
    interval.birth = static_cast<float>(birth);
    interval.death = static_cast<float>(death);  // negative means ∞

    ctx->user_cb(&interval, ctx->user_data);
}

int flb_ripser_compute_intervals_from_dense_distance(
    const float *dist_matrix,
    size_t       n_points,
    int          max_dim,
    float        threshold,
    flb_ripser_interval_cb interval_cb,
    void *user_data)
{
    if (!dist_matrix || n_points == 0 || max_dim < 0 || !interval_cb) {
        return -1;
    }

    generic_interval_cb_bridge_ctx ctx;
    ctx.user_cb   = interval_cb;
    ctx.user_data = user_data;

    interval_recorder recorder;
    recorder.cb        = &generic_interval_cb_bridge;
    recorder.user_data = &ctx;

    compressed_lower_distance_matrix dist =
        make_compressed_from_dense(dist_matrix, n_points);

    value_t thr = (threshold > 0.0f)
                    ? static_cast<value_t>(threshold)
                    : std::numeric_limits<value_t>::max();

    ripser_run_from_compressed_lower(
        std::move(dist),
        /*dim_max=*/max_dim,
        /*threshold=*/thr,
        /*ratio=*/1.0f,
        recorder);

    return 0;
}
