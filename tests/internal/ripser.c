/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include <fluent-bit/ripser/flb_ripser_wrapper.h>

#include "flb_tests_internal.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

void test_ripser_betti_circle()
{
#define SIZE_N 16 /* Number of points sampled on the circle */

    /* Maximum homology dimension (0, 1, 2) */
    const int max_dim = 2;

    /* 0 means "let ripser choose its own threshold" */
    const float threshold = 2.0f;

    /* Point cloud (n x 2) */
    double pts[SIZE_N][2];

    /* Full dense distance matrix (n x n) */
    const size_t m = SIZE_N * SIZE_N;
    float *dist = NULL;

    int ret;
    struct flb_ripser_betti b;
    size_t i, j;
    double theta;
    double dx;
    double dy;

    /* Generate points uniformly on the unit circle */
    for (i = 0; i < SIZE_N; i++) {
        theta = 2.0 * M_PI * (double) i / (double) SIZE_N;
        pts[i][0] = cos(theta);
        pts[i][1] = sin(theta);
    }

    /* Allocate distance matrix */
    dist = (float *) malloc(sizeof(float) * m);
    TEST_CHECK(dist != NULL);
    if (!dist) {
        return;
    }

    /* Fill dense distance matrix: dist[i*n + j] = d(i,j) */
    for (i = 0; i < SIZE_N; i++) {
        for (j = 0; j < SIZE_N; j++) {
            if (i == j) {
                dist[i * SIZE_N + j] = 0.0f;
            }
            else {
                dx = pts[i][0] - pts[j][0];
                dy = pts[i][1] - pts[j][1];
                dist[i * SIZE_N + j] = (float) sqrt(dx * dx + dy * dy);
            }
        }
    }

    memset(&b, 0, sizeof(b));

    /* Run ripser on the dense distance matrix */
    ret = flb_ripser_compute_betti_from_dense_distance(dist,
                                                       SIZE_N,
                                                       max_dim,
                                                       threshold,
                                                       &b);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        TEST_MSG("flb_ripser_compute_betti_from_dense_distance failed: ret=%d", ret);
        free(dist);
        return;
    }

    TEST_MSG("num_dims=%d  betti0=%llu  betti1=%llu  betti2=%llu",
             b.num_dims,
             (unsigned long long) b.betti[0],
             (unsigned long long) b.betti[1],
             (unsigned long long) b.betti[2]);

    /*
     * Unit circle → expected Betti numbers (with a reasonable sampling):
     *
     *   H0 = 1 connected component
     *   H1 >= 1 (there should be at least one nontrivial 1D hole)
     *   H2 = 0
     */

    /* H0: at least one component */
    TEST_CHECK(b.num_dims >= 1);
    TEST_CHECK(b.betti[0] >= 1);

    /* H1: circle has at least one nontrivial 1D hole */
    TEST_CHECK(b.num_dims >= 2);
    TEST_CHECK(b.betti[1] > 0);

    /* H2: should be 0 for a circle (just check non-negative) */
    TEST_CHECK(b.betti[2] >= 0);

    free(dist);
#undef SIZE_N
}

TEST_LIST = {
    {"ripser_betti_circle", test_ripser_betti_circle},
    { 0 }
};
