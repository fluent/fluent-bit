/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_EMIT_AOT_FILE_H_
#define _AOT_EMIT_AOT_FILE_H_

#include "aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AOTObjectData AOTObjectData;

AOTObjectData *
aot_obj_data_create(AOTCompContext *comp_ctx);

void
aot_obj_data_destroy(AOTObjectData *obj_data);

uint32
aot_get_aot_file_size(AOTCompContext *comp_ctx, AOTCompData *comp_data,
                      AOTObjectData *obj_data);

bool
aot_emit_aot_file(AOTCompContext *comp_ctx, AOTCompData *comp_data,
                  const char *file_name);

uint8 *
aot_emit_aot_file_buf(AOTCompContext *comp_ctx, AOTCompData *comp_data,
                      uint32 *p_aot_file_size);

bool
aot_emit_aot_file_buf_ex(AOTCompContext *comp_ctx, AOTCompData *comp_data,
                         AOTObjectData *obj_data, uint8 *aot_file_buf,
                         uint32 aot_file_size);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _AOT_EMIT_AOT_FILE_H_ */
