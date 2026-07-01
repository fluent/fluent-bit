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

#ifndef FLB_RIPSER_WRAPPER_H
#define FLB_RIPSER_WRAPPER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FLB_RIPSER_MAX_BETTI_DIM 3
/* Represents a single persistent homology interval [birth, death).
 * death < 0 indicates an infinite interval.
 */
typedef struct flb_ripser_interval {
    int   dim;     /* homology dimension (0,1,2,...) */
    float birth;   /* birth radius */
    float death;   /* death radius; negative means "infinity" */
} flb_ripser_interval;

/* Summary of Betti numbers.
 * Up to 8 dimensions supported for practical purposes.
 */
typedef struct flb_ripser_betti {
    int max_dim;       /* maximum computed dimension */
    int num_dims;      /* number of valid dimensions (0..num_dims-1) */
    int betti[8];      /* Betti numbers for each dimension */
} flb_ripser_betti;

/*
 * Compute Betti numbers from a dense distance matrix.
 *
 * Parameters:
 *   dist_matrix: row-major dense matrix [n_points * n_points], diagonal = 0
 *   n_points:    number of points
 *   max_dim:     maximum homology dimension to compute
 *   threshold:   Rips complex cutoff; if <= 0, use "enclosing radius" (Ripser default)
 *   out_betti:   filled with Betti number results
 *
 * Returns:
 *   0  on success
 *  <0  on error (e.g., invalid arguments)
 */
int flb_ripser_compute_betti_from_dense_distance(
    const float *dist_matrix,
    size_t       n_points,
    int          max_dim,
    float        threshold,
    flb_ripser_betti *out_betti);

/*
 * Callback type for retrieving each persistent interval.
 *
 * interval_cb is invoked once for every interval [birth, death).
 * `user_data` is passed through unchanged.
 */
typedef void (*flb_ripser_interval_cb)(
    const flb_ripser_interval *interval,
    void *user_data);

/*
 * Compute all persistent intervals from a dense distance matrix,
 * delivering the result through a callback.
 *
 * Returns:
 *   0 on success
 *  <0 on error
 */
int flb_ripser_compute_intervals_from_dense_distance(
    const float *dist_matrix,
    size_t       n_points,
    int          max_dim,
    float        threshold,
    flb_ripser_interval_cb interval_cb,
    void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* FLB_RIPSER_WRAPPER_H */
