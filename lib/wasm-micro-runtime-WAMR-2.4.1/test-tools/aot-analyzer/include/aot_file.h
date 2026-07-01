/*
 * Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef AOT_FILE_H_
#define AOT_FILE_H_

#include "binary_file.h"

namespace analyzer {

class AoTFile : public BinaryFile
{
  public:
    AoTFile(const char *file_name);

    Result Scan();

    Result ParseTargetInfo();
    AOTTargetInfo GetTargetInfo();

    std::string GetBinTypeName(uint16_t bin_type);
    std::string GetExectuionTypeName(uint16_t e_type);
    std::string GetExectuionMachineName(uint16_t e_machine);

  private:
    AOTTargetInfo target_info_;
};

} // namespace analyzer
#endif
