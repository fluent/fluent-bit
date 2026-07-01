/*
 * Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef BINARY_FILE_H_
#define BINARY_FILE_H_

#include "aot_runtime.h"
#include "bh_read_file.h"
#include "common.h"
#include "config.h"
#include "wasm_export.h"

namespace analyzer {

class BinaryFile
{
  public:
    BinaryFile(const char *file_name);
    ~BinaryFile();

    Result ReadModule();

    virtual Result Scan();

    void ANALYZER_PRINTF_FORMAT(2, 3) PrintError(const char *format, ...);
    Result UpdateCurrentPos(uint32_t steps);

    const char *GetFileName() { return file_name_; }
    uint8_t *GetFileData() { return file_data_; }
    uint32_t GetFileSize() { return file_size_; }
    size_t GetCurrentPos() { return current_pos_; }
    wasm_module_t GetModule() { return module_; }
    WASMModuleMemConsumption GetMemConsumption() { return mem_conspn_; }

  private:
    const char *file_name_;
    uint8_t *file_data_;
    uint32_t file_size_;
    size_t current_pos_;
    wasm_module_t module_;
    WASMModuleMemConsumption mem_conspn_;
};

template<typename T>
Result
ReadT(T *out_value, BinaryFile *file, const char *type_name)
{
    if (file == NULL
        || file->GetCurrentPos() + sizeof(T) > file->GetFileSize()) {
        return Result::Error;
    }
#if WAMR_BIG_ENDIAN
    uint8_t tmp[sizeof(T)];
    memcpy(tmp, file->GetFileData() + file->GetCurrentPos(), sizeof(tmp));
    SwapBytesSized(tmp, sizeof(tmp));
    memcpy(out_value, tmp, sizeof(T));
#else
    memcpy(out_value, file->GetFileData() + file->GetCurrentPos(), sizeof(T));
#endif
    file->UpdateCurrentPos(sizeof(T));
    return Result::Ok;
}

} // namespace analyzer
#endif
