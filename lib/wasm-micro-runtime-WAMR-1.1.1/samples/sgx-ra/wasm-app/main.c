/*
 * Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include "lib_rats_wrapper.h"

int
main(int argc, char **argv)
{
    char *evidence_json = NULL;
    const char *hash = "12345678123456781234567812345678";
    evidence_json = librats_collect((const uint8_t *)hash);
    if (evidence_json == NULL) {
        printf("Librats collect evidence failed.\n");
        return -1;
    }
    printf("evidence json:\n%s\n", evidence_json);

    if (librats_verify(evidence_json, (const uint8_t *)hash) != 0) {
        printf("Evidence is not trusted.\n");
    }
    else {
        printf("Evidence is trusted.\n");
    }

    if (evidence_json) {
        free(evidence_json);
    }

    return 0;
}
