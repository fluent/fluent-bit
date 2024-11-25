/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef WAMR_GRAPHIC_LIBRARY_SHARED_UTILS_H
#define WAMR_GRAPHIC_LIBRARY_SHARED_UTILS_H

#include "bh_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/* Object native function IDs */
enum {
    OBJ_FUNC_ID_DEL,
    OBJ_FUNC_ID_DEL_ASYNC,
    OBJ_FUNC_ID_CLEAN,
    OBJ_FUNC_ID_SET_EVT_CB,
    OBJ_FUNC_ID_ALIGN,

    /* Number of functions */
    _OBJ_FUNC_ID_NUM,
};

/* Button native function IDs */
enum {
    BTN_FUNC_ID_CREATE,
    BTN_FUNC_ID_SET_TOGGLE,
    BTN_FUNC_ID_SET_STATE,
    BTN_FUNC_ID_TOGGLE,
    BTN_FUNC_ID_SET_INK_IN_TIME,
    BTN_FUNC_ID_SET_INK_WAIT_TIME,
    BTN_FUNC_ID_SET_INK_OUT_TIME,
    BTN_FUNC_ID_GET_STATE,
    BTN_FUNC_ID_GET_TOGGLE,
    BTN_FUNC_ID_GET_INK_IN_TIME,
    BTN_FUNC_ID_GET_INK_WAIT_TIME,
    BTN_FUNC_ID_GET_INK_OUT_TIME,
    /* Number of functions */
    _BTN_FUNC_ID_NUM,
};

/* Check box native function IDs */
enum {
    CB_FUNC_ID_CREATE,
    CB_FUNC_ID_SET_TEXT,
    CB_FUNC_ID_SET_STATIC_TEXT,
    CB_FUNC_ID_GET_TEXT,
    CB_FUNC_ID_GET_TEXT_LENGTH,

    /* Number of functions */
    _CB_FUNC_ID_NUM,
};

/* List native function IDs */
enum {
    LIST_FUNC_ID_CREATE,
    LIST_FUNC_ID_ADD_BTN,

    /* Number of functions */
    _LIST_FUNC_ID_NUM,
};

/* Label native function IDs */
enum {
    LABEL_FUNC_ID_CREATE,
    LABEL_FUNC_ID_SET_TEXT,
    LABEL_FUNC_ID_SET_ARRAY_TEXT,
    LABEL_FUNC_ID_SET_STATIC_TEXT,
    LABEL_FUNC_ID_SET_LONG_MODE,
    LABEL_FUNC_ID_SET_ALIGN,
    LABEL_FUNC_ID_SET_RECOLOR,
    LABEL_FUNC_ID_SET_BODY_DRAW,
    LABEL_FUNC_ID_SET_ANIM_SPEED,
    LABEL_FUNC_ID_SET_TEXT_SEL_START,
    LABEL_FUNC_ID_SET_TEXT_SEL_END,
    LABEL_FUNC_ID_GET_TEXT,
    LABEL_FUNC_ID_GET_TEXT_LENGTH,
    LABEL_FUNC_ID_GET_LONG_MODE,
    LABEL_FUNC_ID_GET_ALIGN,
    LABEL_FUNC_ID_GET_RECOLOR,
    LABEL_FUNC_ID_GET_BODY_DRAW,
    LABEL_FUNC_ID_GET_ANIM_SPEED,
    LABEL_FUNC_ID_GET_LETTER_POS,
    LABEL_FUNC_ID_GET_TEXT_SEL_START,
    LABEL_FUNC_ID_GET_TEXT_SEL_END,
    LABEL_FUNC_ID_INS_TEXT,
    LABEL_FUNC_ID_CUT_TEXT,
    /* Number of functions */
    _LABEL_FUNC_ID_NUM,
};

#ifdef __cplusplus
}
#endif

#endif /* WAMR_GRAPHIC_LIBRARY_SHARED_UTILS_H */
