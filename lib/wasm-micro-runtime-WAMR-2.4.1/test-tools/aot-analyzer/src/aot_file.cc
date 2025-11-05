/*
 * Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_file.h"

#include <cstring>

#include "analyzer_error.h"
#include "common.h"

namespace analyzer {

AoTFile::AoTFile(const char *file_name)
  : BinaryFile(file_name)
{
    memset(&target_info_, 0, sizeof(AOTTargetInfo));
}

Result
AoTFile::Scan()
{
    CHECK_RESULT(ParseTargetInfo());
    WASMModuleMemConsumption mem_conspn = GetMemConsumption();
    aot_get_module_mem_consumption((AOTModule *)GetModule(), &mem_conspn);
    return Result::Ok;
}

Result
AoTFile::ParseTargetInfo()
{
    uint32_t section_id = 0;
    uint32_t section_size = 0;
    // skip AOT_MAGIC_NUMBER + AOT_CURRENT_VERSION
    UpdateCurrentPos(sizeof(uint32_t) + sizeof(uint32_t));

    ReadT(&section_id, this, "uint32_t");
    ReadT(&section_size, this, "uint32_t");

    // bin type
    uint16_t bin_type = 0;
    CHECK_RESULT(ReadT(&bin_type, this, "uint16_t"));
    target_info_.bin_type = bin_type;

    // abi type
    uint16_t abi_type = 0;
    CHECK_RESULT(ReadT(&abi_type, this, "uint16_t"));
    target_info_.abi_type = abi_type;

    // execution type
    uint16_t e_type = 0;
    CHECK_RESULT(ReadT(&e_type, this, "uint16_t"));
    target_info_.e_type = e_type;

    // execution machine
    uint16_t e_machine = 0;
    CHECK_RESULT(ReadT(&e_machine, this, "uint16_t"));
    target_info_.e_machine = e_machine;

    // execution version
    uint32_t e_version = 0;
    CHECK_RESULT(ReadT(&e_version, this, "uint32_t"));
    target_info_.e_version = e_version;

    // execution flags
    uint32_t e_flags = 0;
    CHECK_RESULT(ReadT(&e_flags, this, "uint32_t"));
    target_info_.e_flags = e_flags;

    // feature flags
    uint64_t feature_flags = 0;
    CHECK_RESULT(ReadT(&feature_flags, this, "uint64_t"));
    target_info_.feature_flags = feature_flags;

    // reserved
    uint64_t reserved = 0;
    CHECK_RESULT(ReadT(&reserved, this, "uint64_t"));
    target_info_.reserved = reserved;

    // Arch name
    const uint32_t section_end =
        section_size - (GetCurrentPos() - sizeof(uint32_t) - sizeof(uint32_t));
    for (size_t i = 0; i < section_end; ++i) {
        ReadT(&target_info_.arch[i], this, "uint8_t");
    }
    return Result::Ok;
}

AOTTargetInfo
AoTFile::GetTargetInfo()
{
    return target_info_;
}

std::string
AoTFile::GetBinTypeName(uint16_t bin_type)
{
    std::string name = "";
    switch (bin_type) {
        case BIN_TYPE_ELF32L:
        {
            name = "ELF32L";
            break;
        }
        case BIN_TYPE_ELF32B:
        {
            name = "ELF32B";
            break;
        }
        case BIN_TYPE_ELF64L:
        {
            name = "ELF64L";
            break;
        }
        case BIN_TYPE_ELF64B:
        {
            name = "ELF64B";
            break;
        }
        case BIN_TYPE_COFF32:
        {
            name = "COFF32";
            break;
        }
        case BIN_TYPE_COFF64:
        {
            name = "COFF64";
            break;
        }
        default:
            name = "bad bin type";
    }
    return name;
}

std::string
AoTFile::GetExectuionTypeName(uint16_t e_type)
{
    std::string name = "";
    switch (e_type) {
        case E_TYPE_NONE:
        {
            name = "NONE";
            break;
        }
        case E_TYPE_REL:
        {
            name = "REL";
            break;
        }
        case E_TYPE_EXEC:
        {
            name = "EXEC";
            break;
        }
        case E_TYPE_DYN:
        {
            name = "DYN";
            break;
        }
        case E_TYPE_XIP:
        {
            name = "XIP";
            break;
        }
        default:
            name = "bad execution type";
    }
    return name;
}

std::string
AoTFile::GetExectuionMachineName(uint16_t e_machine)
{
    std::string machine = "";
    switch (e_machine) {
        case E_MACHINE_386:
        {
            machine = "386";
            break;
        }
        case E_MACHINE_MIPS:
        {
            machine = "MIPS";
            break;
        }
        case E_MACHINE_MIPS_RS3_LE:
        {
            machine = "MIPS_RS3_LE";
            break;
        }
        case E_MACHINE_ARM:
        {
            machine = "ARM";
            break;
        }
        case E_MACHINE_AARCH64:
        {
            machine = "AARCH64";
            break;
        }
        case E_MACHINE_ARC:
        {
            machine = "ARC";
            break;
        }
        case E_MACHINE_IA_64:
        {
            machine = "IA_64";
            break;
        }
        case E_MACHINE_MIPS_X:
        {
            machine = "MIPS_X";
            break;
        }
        case E_MACHINE_X86_64:
        {
            machine = "X86_64";
            break;
        }
        case E_MACHINE_ARC_COMPACT:
        {
            machine = "ARC_COMPACT";
            break;
        }
        case E_MACHINE_ARC_COMPACT2:
        {
            machine = "ARC_COMPACT2";
            break;
        }
        case E_MACHINE_XTENSA:
        {
            machine = "XTENSA";
            break;
        }
        case E_MACHINE_RISCV:
        {
            machine = "RISCV";
            break;
        }
        case E_MACHINE_WIN_I386:
        {
            machine = "WIN_I386";
            break;
        }
        case E_MACHINE_WIN_X86_64:
        {
            machine = "WIN_X86_64";
            break;
        }
        default:
            machine = "bad execution machine type";
    }
    return machine;
}

} // namespace analyzer
