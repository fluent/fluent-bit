/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdlib.h>
#include "wasm_app.h"
#include "wa-inc/lvgl/lvgl.h"
#include "wa-inc/timer_wasm_app.h"

extern char g_widget_text[];

static void
btn_event_cb(lv_obj_t *btn, lv_event_t event);

uint32_t count = 0;
char count_str[11] = { 0 };
lv_obj_t *hello_world_label;
lv_obj_t *count_label;
lv_obj_t *btn1;
lv_obj_t *label_count1;
int label_count1_value = 1;
char label_count1_str[11] = { 0 };

void
timer1_update(user_timer_t timer1)
{
    if ((count % 100) == 0) {
        snprintf(count_str, sizeof(count_str), "%d", count / 100);
        lv_label_set_text(count_label, count_str);
    }
    ++count;
}

void
on_init()
{
    char *text;

    hello_world_label = lv_label_create(NULL, NULL);
    lv_label_set_text(hello_world_label, "Hello world!");
    text = lv_label_get_text(hello_world_label);
    printf("Label text %lu %s \n", strlen(text), text);
    lv_obj_align(hello_world_label, NULL, LV_ALIGN_IN_TOP_LEFT, 0, 0);

    count_label = lv_label_create(NULL, NULL);
    lv_obj_align(count_label, NULL, LV_ALIGN_IN_TOP_MID, 0, 0);

    /* Create a button on the current loaded screen */
    btn1 = lv_btn_create(NULL, NULL);
    /* Set function to be called when the button is released */
    lv_obj_set_event_cb(btn1, (lv_event_cb_t)btn_event_cb);
    /* Align below the label */
    lv_obj_align(btn1, NULL, LV_ALIGN_CENTER, 0, 0);

    /* Create a label on the button */
    lv_obj_t *btn_label = lv_label_create(btn1, NULL);
    lv_label_set_text(btn_label, "Click ++");

    label_count1 = lv_label_create(NULL, NULL);
    lv_label_set_text(label_count1, "1");
    lv_obj_align(label_count1, NULL, LV_ALIGN_IN_BOTTOM_MID, 0, 0);

    /* Set up a timer */
    user_timer_t timer;
    timer = api_timer_create(10, true, false, timer1_update);
    if (timer)
        api_timer_restart(timer, 10);
    else
        printf("Fail to create timer.\n");
}

static void
btn_event_cb(lv_obj_t *btn, lv_event_t event)
{
    if (event == LV_EVENT_RELEASED) {
        label_count1_value++;
        snprintf(label_count1_str, sizeof(label_count1_str), "%d",
                 label_count1_value);
        lv_label_set_text(label_count1, label_count1_str);
        if (label_count1_value == 100)
            label_count1_value = 0;
    }
}
