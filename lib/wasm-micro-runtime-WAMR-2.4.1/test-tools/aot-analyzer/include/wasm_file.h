/*
 * Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef WASM_FILE_H_
#define WASM_FILE_H_

#include "binary_file.h"

namespace analyzer {

class WasmFile : public BinaryFile
{
  public:
    WasmFile(const char *file_name);

    Result Scan();
};

} // namespace analyzer
#endif
