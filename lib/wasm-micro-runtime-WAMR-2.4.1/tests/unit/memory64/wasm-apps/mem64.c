/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

int
add_a_and_b_to_c(int *array, int *b, int *c)
{
    int i;
    // Perform computation: multiply each element by 2
    for (i = 0; i < 5; i++) {
        array[i] = array[i] * 2;
    }
    // Compute the product of corresponding elements of a and b
    for (i = 0; i < 5; i++) {
        c[i] = array[i] * b[i];
    }
    return i;
}

int
test()
{
    // Initialize an array with some values
    int array[5] = { 1, 2, 3, 4, 5 };
    int b[5] = { 6, 7, 8, 9, 10 };
    int c[5], i, j, res = 0;

    j = add_a_and_b_to_c(array, b, c);

    for (i = 0; i < 5; i++) {
        res += c[i];
    }

    return res + j;
}

int
main(int argc, char *argv[])
{
    // Initialize an array with some values
    int array[5] = { 1, 2, 3, 4, 5 };
    int b[5] = { 6, 7, 8, 9, 10 };
    int c[5], i;

    // Perform computation: multiply each element by 2
    for (i = 0; i < 5; i++) {
        array[i] = array[i] * 2;
    }
    // Compute the product of corresponding elements of a and b
    for (i = 0; i < 5; i++) {
        c[i] = array[i] * b[i];
    }

    return c[4];
}
