/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_OUT_KAFKA_CALLBACKS_H
#define FLB_OUT_KAFKA_CALLBACKS_H

#include "rdkafka.h"

void cb_kafka_msg(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage,
                  void *opaque);

void cb_kafka_logger(const rd_kafka_t *rk, int level,
                     const char *fac, const char *buf);

#endif
