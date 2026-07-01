/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef PACKETS_H
#define PACKETS_H

#include "gdbserver.h"

void
write_data_raw(WASMGDBServer *gdbserver, const uint8 *data, ssize_t len);

void
write_packet(WASMGDBServer *gdbserver, const char *data);

#endif
