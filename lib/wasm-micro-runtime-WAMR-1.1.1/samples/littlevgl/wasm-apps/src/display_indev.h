/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef DISPLAY_INDEV_H_
#define DISPLAY_INDEV_H_
#include <stdio.h>
#include <inttypes.h>

#include "lvgl/lv_misc/lv_color.h"
#include "lvgl/lv_hal/lv_hal_indev.h"

extern void
display_init(void);

extern void
display_deinit(void);

extern void
display_flush(int32_t x1, int32_t y1, int32_t x2, int32_t y2,
              const lv_color_t *color);

extern bool
display_input_read(lv_indev_data_t *data);

extern void
display_vdb_write(void *buf, lv_coord_t buf_w, lv_coord_t x, lv_coord_t y,
                  lv_color_t *color, lv_opa_t opa);

void
display_fill(int32_t x1, int32_t y1, int32_t x2, int32_t y2,
             const lv_color_t *color);

void
display_map(int32_t x1, int32_t y1, int32_t x2, int32_t y2,
            const lv_color_t *color);

extern uint32_t
time_get_ms(void);

#endif
