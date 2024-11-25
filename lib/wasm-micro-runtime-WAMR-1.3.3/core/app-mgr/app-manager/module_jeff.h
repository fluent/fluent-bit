/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _MODULE_JEFF_H_
#define _MODULE_JEFF_H_

#include "app_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

extern module_interface jeff_module_interface;

/* sensor event */
typedef struct bh_sensor_event_t {
    /* Java sensor object */
    void *sensor;
    /* event of attribute container from context core */
    void *event;
} bh_sensor_event_t;

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* _MODULE_JEFF_H_ */
