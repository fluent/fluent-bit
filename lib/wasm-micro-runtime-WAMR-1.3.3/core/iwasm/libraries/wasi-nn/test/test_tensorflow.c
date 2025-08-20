/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <math.h>

#include "utils.h"
#include "logger.h"

void
test_sum(execution_target target)
{
    int dims[] = { 1, 5, 5, 1 };
    input_info input = create_input(dims);

    uint32_t output_size = 0;
    float *output = run_inference(target, input.input_tensor, input.dim,
                                  &output_size, "./models/sum.tflite", 1);

    assert(output_size == 1);
    assert(fabs(output[0] - 300.0) < EPSILON);

    free(input.dim);
    free(input.input_tensor);
    free(output);
}

void
test_max(execution_target target)
{
    int dims[] = { 1, 5, 5, 1 };
    input_info input = create_input(dims);

    uint32_t output_size = 0;
    float *output = run_inference(target, input.input_tensor, input.dim,
                                  &output_size, "./models/max.tflite", 1);

    assert(output_size == 1);
    assert(fabs(output[0] - 24.0) < EPSILON);
    NN_INFO_PRINTF("Result: max is %f", output[0]);

    free(input.dim);
    free(input.input_tensor);
    free(output);
}

void
test_average(execution_target target)
{
    int dims[] = { 1, 5, 5, 1 };
    input_info input = create_input(dims);

    uint32_t output_size = 0;
    float *output = run_inference(target, input.input_tensor, input.dim,
                                  &output_size, "./models/average.tflite", 1);

    assert(output_size == 1);
    assert(fabs(output[0] - 12.0) < EPSILON);
    NN_INFO_PRINTF("Result: average is %f", output[0]);

    free(input.dim);
    free(input.input_tensor);
    free(output);
}

void
test_mult_dimensions(execution_target target)
{
    int dims[] = { 1, 3, 3, 1 };
    input_info input = create_input(dims);

    uint32_t output_size = 0;
    float *output = run_inference(target, input.input_tensor, input.dim,
                                  &output_size, "./models/mult_dim.tflite", 1);

    assert(output_size == 9);
    for (int i = 0; i < 9; i++)
        assert(fabs(output[i] - i) < EPSILON);

    free(input.dim);
    free(input.input_tensor);
    free(output);
}

void
test_mult_outputs(execution_target target)
{
    int dims[] = { 1, 4, 4, 1 };
    input_info input = create_input(dims);

    uint32_t output_size = 0;
    float *output = run_inference(target, input.input_tensor, input.dim,
                                  &output_size, "./models/mult_out.tflite", 2);

    assert(output_size == 8);
    // first tensor check
    for (int i = 0; i < 4; i++)
        assert(fabs(output[i] - (i * 4 + 24)) < EPSILON);
    // second tensor check
    for (int i = 0; i < 4; i++)
        assert(fabs(output[i + 4] - (i + 6)) < EPSILON);

    free(input.dim);
    free(input.input_tensor);
    free(output);
}

int
main()
{
    char *env = getenv("TARGET");
    if (env == NULL) {
        NN_INFO_PRINTF("Usage:\n--env=\"TARGET=[cpu|gpu]\"");
        return 1;
    }
    execution_target target;
    if (strcmp(env, "cpu") == 0)
        target = cpu;
    else if (strcmp(env, "gpu") == 0)
        target = gpu;
    else {
        NN_ERR_PRINTF("Wrong target!");
        return 1;
    }
    NN_INFO_PRINTF("################### Testing sum...");
    test_sum(target);
    NN_INFO_PRINTF("################### Testing max...");
    test_max(target);
    NN_INFO_PRINTF("################### Testing average...");
    test_average(target);
    NN_INFO_PRINTF("################### Testing multiple dimensions...");
    test_mult_dimensions(target);
    NN_INFO_PRINTF("################### Testing multiple outputs...");
    test_mult_outputs(target);

    NN_INFO_PRINTF("Tests: passed!");
    return 0;
}
