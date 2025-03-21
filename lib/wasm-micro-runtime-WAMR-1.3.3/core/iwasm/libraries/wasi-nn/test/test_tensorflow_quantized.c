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

#undef EPSILON
#define EPSILON 1e-2

void
test_average_quantized(execution_target target)
{
    int dims[] = { 1, 5, 5, 1 };
    input_info input = create_input(dims);

    uint32_t output_size = 0;
    float *output =
        run_inference(target, input.input_tensor, input.dim, &output_size,
                      "./models/quantized_model.tflite", 1);

    NN_INFO_PRINTF("Output size: %d", output_size);
    NN_INFO_PRINTF("Result: average is %f", output[0]);
    // NOTE: 11.95 instead of 12 because of errors due quantization
    assert(fabs(output[0] - 11.95) < EPSILON);

    free(input.dim);
    free(input.input_tensor);
    free(output);
}

int
main()
{
    char *env = getenv("TARGET");
    if (env == NULL) {
        NN_INFO_PRINTF("Usage:\n--env=\"TARGET=[cpu|gpu|tpu]\"");
        return 1;
    }
    execution_target target;
    if (strcmp(env, "cpu") == 0)
        target = cpu;
    else if (strcmp(env, "gpu") == 0)
        target = gpu;
    else if (strcmp(env, "tpu") == 0)
        target = tpu;
    else {
        NN_ERR_PRINTF("Wrong target!");
        return 1;
    }
    NN_INFO_PRINTF("################### Testing quantized model...");
    test_average_quantized(target);

    NN_INFO_PRINTF("Tests: passed!");
    return 0;
}
