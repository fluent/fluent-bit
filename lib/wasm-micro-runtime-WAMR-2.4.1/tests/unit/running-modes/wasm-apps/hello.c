/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

double
foo(double d)
{
    return d / 3.0;
}

double
maybe_min(double d, double e)
{
    return d < e ? d : e;
}

double
factor(double a, double b, double c)
{
    return (a * c) + (b * c);
}

int
echo(int a)
{
    double b = foo(14.5);
    double c = maybe_min(12.2, 15.4);
    double d = factor(a, b, c);
    return 2 * a;
}