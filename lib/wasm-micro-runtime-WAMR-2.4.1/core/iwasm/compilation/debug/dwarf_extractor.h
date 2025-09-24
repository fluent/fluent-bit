/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _DWARF_EXTRACTOR_H_
#define _DWARF_EXTRACTOR_H_

#include "llvm-c/DebugInfo.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int LLDBLangType;
#define LLDB_TO_LLVM_LANG_TYPE(lldb_lang_type) \
    (LLVMDWARFSourceLanguage)(((lldb_lang_type) > 0 ? (lldb_lang_type)-1 : 1))

struct AOTCompData;
typedef struct AOTCompData *aot_comp_data_t;
typedef void *dwarf_extractor_handle_t;

struct AOTCompContext;
typedef struct AOTCompContext AOTCompContext;

struct AOTFuncContext;

typedef struct AOTFuncContext AOTFuncContext;
dwarf_extractor_handle_t
create_dwarf_extractor(aot_comp_data_t comp_data, char *file_name);

LLVMMetadataRef
dwarf_gen_file_info(const AOTCompContext *comp_ctx);

LLVMMetadataRef
dwarf_gen_comp_unit_info(const AOTCompContext *comp_ctx);

LLVMMetadataRef
dwarf_gen_func_info(const AOTCompContext *comp_ctx,
                    const AOTFuncContext *func_ctx);

LLVMMetadataRef
dwarf_gen_location(const AOTCompContext *comp_ctx,
                   const AOTFuncContext *func_ctx, uint64_t vm_offset);

LLVMMetadataRef
dwarf_gen_func_ret_location(const AOTCompContext *comp_ctx,
                            const AOTFuncContext *func_ctx);

void
dwarf_get_func_name(const AOTCompContext *comp_ctx,
                    const AOTFuncContext *func_ctx, char *name, int len);

#ifdef __cplusplus
}
#endif

#endif
