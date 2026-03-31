/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WAMR_LIB_SEMAPHORE_H
#define _WAMR_LIB_SEMAPHORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef unsigned int sem_t;

/* Semaphore APIs */

sem_t *
sem_open(const char *name, int oflag, int mode, int val);

int
sem_wait(sem_t *sem);

int
sem_trywait(sem_t *sem);

int
sem_post(sem_t *sem);

int
sem_getvalue(sem_t *restrict sem, int *sval);

int
sem_unlink(const char *name);

int
sem_close(sem_t *sem);

#ifdef __cplusplus
}
#endif

#endif /* end of _WAMR_LIB_SEMAPHORE_H */
