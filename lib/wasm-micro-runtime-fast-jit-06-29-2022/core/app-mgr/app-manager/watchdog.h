/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WATCHDOG_H_
#define _WATCHDOG_H_

#include "app_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
watchdog_timer_init(module_data *module_data);

void
watchdog_timer_destroy(watchdog_timer *wd_timer);

void
watchdog_timer_start(watchdog_timer *wd_timer);

void
watchdog_timer_stop(watchdog_timer *wd_timer);

watchdog_timer *
app_manager_get_watchdog_timer(void *timer);

bool
watchdog_startup();

void
watchdog_destroy();

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* _WATCHDOG_H_ */
