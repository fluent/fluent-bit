/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef CONN_LINUX_UART_H_
#define CONN_LINUX_UART_H_

#include "bh_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

int
uart_open(char *device, int baudrate);

int
uart_send(int fd, const char *data, int size);

int
uart_recv(int fd, char *buffer, int buf_size);

#ifdef __cplusplus
}
#endif

#endif
