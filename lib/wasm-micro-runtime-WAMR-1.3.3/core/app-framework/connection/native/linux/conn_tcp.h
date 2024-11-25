/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef CONN_LINUX_TCP_H_
#define CONN_LINUX_TCP_H_

#include "bh_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

int
tcp_open(char *address, uint16 port);

int
tcp_send(int sock, const char *data, int size);

int
tcp_recv(int sock, char *buffer, int buf_size);

#ifdef __cplusplus
}
#endif

#endif
