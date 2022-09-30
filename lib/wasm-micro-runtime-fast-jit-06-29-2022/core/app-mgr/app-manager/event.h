/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _EVENT_H_
#define _EVENT_H_

#include "bh_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Handle event request from host agent
 *
 * @param code the coap packet code
 * @param event_url the event url
 *
 * @return true if success, false otherwise
 */
bool
event_handle_event_request(uint8_t code, const char *event_url,
                           uint32_t register);

/**
 * Test whether the event is registered
 *
 * @param event_url the event url
 *
 * @return true for registered, false for not registered
 */
bool
event_is_registered(const char *event_url);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* _EVENT_H_ */
