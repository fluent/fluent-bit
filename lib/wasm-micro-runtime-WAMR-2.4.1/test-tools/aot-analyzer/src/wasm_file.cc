/*
 * Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_file.h"

#include <cstring>

#include "analyzer_error.h"
#include "common.h"

namespace analyzer {

WasmFile::WasmFile(const char *file_name)
  : BinaryFile(file_name)
{}

Result
WasmFile::Scan()
{
    WASMModuleMemConsumption mem_conspn = GetMemConsumption();
    wasm_get_module_mem_consumption((WASMModule *)GetModule(), &mem_conspn);
    return Result::Ok;
}

} // namespace analyzer
