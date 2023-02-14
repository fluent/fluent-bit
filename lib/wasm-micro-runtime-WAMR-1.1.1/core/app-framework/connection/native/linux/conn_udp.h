/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef CONN_LINUX_UDP_H_
#define CONN_LINUX_UDP_H_

#include "bh_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

int
udp_open(uint16 port);

int
udp_send(int sock, struct sockaddr *dest, const char *data, int size);

int
udp_recv(int sock, char *buffer, int buf_size);

#ifdef __cplusplus
}
#endif

#endif
