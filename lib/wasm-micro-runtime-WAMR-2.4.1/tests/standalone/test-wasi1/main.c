/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int
main(int argc, char **argv)
{
    int n, m;
    char buf[BUFSIZ];

    if (argc != 3) {
        fprintf(stderr, "usage: %s <from> <to>\n", argv[0]);
        exit(1);
    }

    printf("##open %s\n", argv[1]);
    int in = open(argv[1], O_RDONLY);
    if (in < 0) {
        fprintf(stderr, "error opening input %s: %s\n", argv[1],
                strerror(errno));
        exit(1);
    }

    printf("##open %s\n", argv[2]);
    int out = open(argv[2], O_WRONLY | O_CREAT, 0660);
    if (out < 0) {
        fprintf(stderr, "error opening output %s: %s\n", argv[2],
                strerror(errno));
        exit(1);
    }

    printf("##read content of %s, and write it to %s\n", argv[1], argv[2]);
    while ((n = read(in, buf, BUFSIZ)) > 0) {
        while (n > 0) {
            m = write(out, buf, n);
            if (m < 0) {
                fprintf(stderr, "write error: %s\n", strerror(errno));
                exit(1);
            }
            n -= m;
        }
    }

    if (n < 0) {
        fprintf(stderr, "read error: %s\n", strerror(errno));
        exit(1);
    }

    printf("##success.\n");
    return EXIT_SUCCESS;
}
