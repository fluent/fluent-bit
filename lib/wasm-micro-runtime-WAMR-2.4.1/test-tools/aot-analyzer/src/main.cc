/*
 * Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "aot_file.h"
#include "common.h"
#include "option_parser.h"
#include "wasm_file.h"

using namespace analyzer;

static const char s_description[] =
    R"(  Print information about the contents of AoT binaries.

examples:
  $ aot-analyzer example.aot
)";

struct func_info {
    uint32_t idx;
    void *ptr;
};

static int
compare_func_ptrs(const void *f1, const void *f2)
{
    return (intptr_t)((struct func_info *)f1)->ptr
           - (intptr_t)((struct func_info *)f2)->ptr;
}

static struct func_info *
sort_func_ptrs(const AOTModule *module)
{
    uint64_t content_len;
    struct func_info *sorted_func_ptrs;
    unsigned i;

    content_len = (uint64_t)sizeof(struct func_info) * module->func_count;
    sorted_func_ptrs = (struct func_info *)wasm_runtime_malloc(content_len);
    if (!sorted_func_ptrs) {
        return NULL;
    }

    for (i = 0; i < module->func_count; i++) {
        sorted_func_ptrs[i].idx = i;
        sorted_func_ptrs[i].ptr = module->func_ptrs[i];
    }

    qsort(sorted_func_ptrs, module->func_count, sizeof(struct func_info),
          compare_func_ptrs);
    return sorted_func_ptrs;
}

static ObjdumpOptions s_objdump_options;

static std::vector<const char *> s_infiles;

static void
ParseOptions(int argc, char **argv)
{
    OptionParser parser("aot-analyzer", s_description);

    parser.AddOption('i', "info", "Print basic information about AoT",
                     []() { s_objdump_options.info = true; });
    parser.AddOption('t', "text-size", "Print text size",
                     []() { s_objdump_options.text_size = true; });
    parser.AddOption('x', "details", "Show AoT details",
                     []() { s_objdump_options.details = true; });
    parser.AddOption('c', "compare",
                     "Show the differences between AoT and WASM",
                     []() { s_objdump_options.compare = true; });
    parser.AddArgument(
        "filename", OptionParser::ArgumentCount::OneOrMore,
        [](const char *argument) { s_infiles.push_back(argument); });
    parser.Parse(argc, argv);
}

void
InitStdio()
{
#if COMPILER_IS_MSVC
    int result = _setmode(_fileno(stdout), _O_BINARY);
    if (result == -1) {
        perror("Cannot set mode binary to stdout");
    }
    result = _setmode(_fileno(stderr), _O_BINARY);
    if (result == -1) {
        perror("Cannot set mode binary to stderr");
    }
#endif
}

void
dump_value_type(uint8 type)
{
    switch (type) {
        case VALUE_TYPE_I32:
            printf("i32");
            break;
        case VALUE_TYPE_I64:
            printf("i64");
            break;
        case VALUE_TYPE_F32:
            printf("f32");
            break;
        case VALUE_TYPE_F64:
            printf("f64");
            break;
        case VALUE_TYPE_V128:
            printf("v128");
            break;
        case PACKED_TYPE_I8:
            printf("i8");
            break;
        case PACKED_TYPE_I16:
            printf("i16");
            break;
        case REF_TYPE_FUNCREF:
            printf("funcref");
            break;
        case REF_TYPE_EXTERNREF:
            printf("externref");
            break;
        case REF_TYPE_ANYREF:
            printf("anyref");
            break;
        case REF_TYPE_EQREF:
            printf("eqref");
            break;
        case REF_TYPE_I31REF:
            printf("i31ref");
            break;
        case REF_TYPE_STRUCTREF:
            printf("structref");
            break;
        case REF_TYPE_ARRAYREF:
            printf("arrayref");
            break;
        case REF_TYPE_NULLREF:
            printf("nullref");
            break;
        case REF_TYPE_NULLFUNCREF:
            printf("nullfuncref");
            break;
        case REF_TYPE_NULLEXTERNREF:
            printf("nullexternref");
            break;
        default:
            printf("unknown");
    }
}

void
DumpInfo(AoTFile *aot)
{
    const AOTTargetInfo target_info = aot->GetTargetInfo();
    printf("AOT File Information:\n\n");
    printf("Binary type: %s\n",
           aot->GetBinTypeName(target_info.bin_type).c_str());
    printf("ABI type: %d\n", target_info.abi_type);
    printf("Execution type: %s\n",
           aot->GetExectuionTypeName(target_info.e_type).c_str());
    printf("Execution machine: %s\n",
           aot->GetExectuionMachineName(target_info.e_machine).c_str());
    printf("Execution version: %u\n", target_info.e_version);
    printf("Execution flags: %u\n", target_info.e_flags);
    printf("Feature flags: %" PRId64 "\n", target_info.feature_flags);
    printf("Reserved: %" PRId64 "\n", target_info.reserved);
    printf("Arch: %s\n", target_info.arch);
}

void
DumpTextSize(AoTFile *aot)
{
    const AOTTargetInfo target_info = aot->GetTargetInfo();
    printf("%s:       file format <%s>\n\n", aot->GetFileName(),
           aot->GetBinTypeName(target_info.bin_type).c_str());
    printf("Text size:\n");

    const uint32_t literal_size =
        ((AOTModule *)(aot->GetModule()))->literal_size;
    const uint32_t code_size = ((AOTModule *)(aot->GetModule()))->code_size;
    printf("   literal size= %u Bytes\n", literal_size);
    printf("      code size= %u Bytes\n", code_size);
}

void
DumpDetails(AoTFile *aot)
{
    const AOTTargetInfo target_info = aot->GetTargetInfo();
    printf("%s:          file format <%s>\n\n", aot->GetFileName(),
           aot->GetBinTypeName(target_info.bin_type).c_str());
    printf("Details:\n\n");

    // Types
    const uint32_t type_count = ((AOTModule *)(aot->GetModule()))->type_count;
    AOTType **types = ((AOTModule *)(aot->GetModule()))->types;
    printf("Types[%u]\n", type_count);
#if WASM_ENABLE_GC != 0
    const char *wasm_type[] = { "function", "struct", "array" };
    for (uint32_t index = 0; index < type_count; index++) {
        AOTType *type = types[index];
        const uint16_t type_flag = type->type_flag;
        printf("  -[%u] ", index);
        if (type_flag == WASM_TYPE_FUNC) {
            wasm_dump_func_type(((AOTFuncType *)type));
        }
        else if (type_flag == WASM_TYPE_STRUCT) {
            wasm_dump_struct_type(((AOTStructType *)type));
        }
        else if (type_flag == WASM_TYPE_ARRAY) {
            wasm_dump_array_type(((AOTArrayType *)type));
        }
        else {
            printf("  -[%u] unknown type\n", index);
        }
    }
#else
    for (uint32_t index = 0; index < type_count; index++) {
        printf("  -[%u] ", index);
        AOTType *type = types[index];
        uint32_t i = 0;
        printf("func [");

        for (i = 0; i < type->param_count; i++) {
            dump_value_type(type->types[i]);
            if (i < (uint32)type->param_count - 1)
                printf(" ");
        }

        printf("] -> [");

        for (; i < (uint32)(type->param_count + type->result_count); i++) {
            dump_value_type(type->types[i]);
            if (i < (uint32)type->param_count + type->result_count - 1)
                printf(" ");
        }

        printf("]\n");
    }
#endif
    printf("\n\n");

    // Imports
    const uint32_t import_memory_count =
        ((AOTModule *)(aot->GetModule()))->import_memory_count;
    AOTImportMemory *import_memories =
        ((AOTModule *)(aot->GetModule()))->import_memories;
    const uint32_t import_table_count =
        ((AOTModule *)(aot->GetModule()))->import_table_count;
    AOTImportTable *import_tables =
        ((AOTModule *)(aot->GetModule()))->import_tables;
    const uint32_t import_global_count =
        ((AOTModule *)(aot->GetModule()))->import_global_count;
    AOTImportGlobal *import_globals =
        ((AOTModule *)(aot->GetModule()))->import_globals;
    const uint32_t import_func_count =
        ((AOTModule *)(aot->GetModule()))->import_func_count;
    AOTImportFunc *import_funcs =
        ((AOTModule *)(aot->GetModule()))->import_funcs;
    printf("Imports[%u]\n", import_memory_count + import_table_count
                                + import_global_count + import_func_count);

    // import memories
    printf("  -import_memories[%u]\n", import_memory_count);
    for (uint32_t index = 0; index < import_memory_count; index++) {
        AOTImportMemory memory = import_memories[index];
        printf("    -[%u] num_bytes_per_page:%5u    init_page_count:%5u    "
               "max_page_count:%5u    module_name: %s    memory_name: %s\n",
               index, memory.mem_type.num_bytes_per_page,
               memory.mem_type.init_page_count, memory.mem_type.max_page_count,
               memory.module_name, memory.memory_name);
    }
    printf("\n");

    // import tables
    printf("  -import_tables[%u]\n", import_table_count);
    for (uint32_t index = 0; index < import_table_count; index++) {
        AOTImportTable table = import_tables[index];
        printf("    -[%u] ", index);
        printf("elem_type: ");
#if WASM_ENABLE_GC != 0
        wasm_dump_value_type(table.table_type.elem_type,
                             table.table_type.elem_ref_type);
#else
        dump_value_type(table.table_type.elem_type);
#endif
        printf("    init_size:%5u    max_size:%5u    "
               "module_name: %s    table_name: %s\n",
               table.table_type.init_size, table.table_type.max_size,
               table.module_name, table.table_name);
    }
    printf("\n");

    // import globals
    printf("  -import_globals[%u]\n", import_global_count);
    for (uint32_t index = 0; index < import_global_count; index++) {
        AOTImportGlobal global = import_globals[index];
        printf("    -[%u] ", index);
        printf("type: ");
        dump_value_type(global.type.val_type);
        printf("    module_name: %s    global_name: %s\n", global.module_name,
               global.global_name);
    }
    printf("\n");

    // import functions
    printf("  -import_functions[%u]\n", import_func_count);
    for (uint32_t index = 0; index < import_func_count; index++) {
        AOTImportFunc func = import_funcs[index];
        printf("    -[%u] module_name: %s    function_name: %s\n", index,
               func.module_name, func.func_name);
    }
    printf("\n\n");

    // Functions
    const uint32_t func_count = ((AOTModule *)(aot->GetModule()))->func_count;
    const uint32_t code_size = ((AOTModule *)(aot->GetModule()))->code_size;
    struct func_info *sorted_func_ptrs = NULL;
    sorted_func_ptrs = sort_func_ptrs(((AOTModule *)(aot->GetModule())));

    if (sorted_func_ptrs) {
        printf("Function[%u]\n", func_count);
        for (uint32_t index = 0; index < func_count; index++) {
            const uint32_t func_size =
                index + 1 < func_count
                    ? (uintptr_t)(sorted_func_ptrs[index + 1].ptr)
                          - (uintptr_t)(sorted_func_ptrs[index].ptr)
                    : code_size
                          + (uintptr_t)(((AOTModule *)(aot->GetModule()))->code)
                          - (uintptr_t)(sorted_func_ptrs[index].ptr);
            printf("  -[%u] code_size= %u Bytes\n", index, func_size);
        }
        wasm_runtime_free(sorted_func_ptrs);
        printf("\n\n");
    }

    // Tables
    const uint32_t table_count = ((AOTModule *)(aot->GetModule()))->table_count;
    AOTTable *tables = ((AOTModule *)(aot->GetModule()))->tables;
    printf("Tables[%u]\n", table_count);
    for (uint32_t index = 0; index < table_count; index++) {
        AOTTable table = tables[index];
        printf("  -[%u] ", index);
        printf("elem_type: ");
#if WASM_ENABLE_GC != 0
        wasm_dump_value_type(table.table_type.elem_type,
                             table.table_type.elem_ref_type);
#else
        dump_value_type(table.table_type.elem_type);
#endif
        printf("    init_size:%5u    max_size:%5u\n",
               table.table_type.init_size, table.table_type.max_size);
    }
    printf("\n\n");

    // Memories
    const uint32_t memory_count =
        ((AOTModule *)(aot->GetModule()))->memory_count;
    AOTMemory *memories = ((AOTModule *)(aot->GetModule()))->memories;
    printf("Memories[%u]\n", memory_count);

    for (uint32_t index = 0; index < memory_count; index++) {
        AOTMemory memory = memories[index];
        printf("  -[%u] flags:%5u    bytes_per_page:%5u    "
               "init_page_count:%5u    max_page_count:%5u\n",
               index, memory.flags, memory.num_bytes_per_page,
               memory.init_page_count, memory.max_page_count);
    }
    printf("\n\n");

    // Globals
    const uint32_t global_count =
        ((AOTModule *)(aot->GetModule()))->global_count;
    AOTGlobal *globals = ((AOTModule *)(aot->GetModule()))->globals;
    printf("Globals[%u]\n", global_count);

    for (uint32_t index = 0; index < global_count; index++) {
        AOTGlobal global = globals[index];
        printf("  -[%u] ", index);
        printf("type: ");
        dump_value_type(global.type.val_type);
        printf("    is_mutable: %d    size: %u    data_offset: %u\n",
               global.type.is_mutable, global.size, global.data_offset);
    }
    printf("\n\n");

    // Exports
    const uint32_t export_count =
        ((AOTModule *)(aot->GetModule()))->export_count;
    AOTExport *exports = ((AOTModule *)(aot->GetModule()))->exports;
    printf("Exports[%u]\n", export_count);

    for (uint32_t index = 0; index < export_count; index++) {
        AOTExport expt = exports[index];
        printf("  -[%u] kind:%5d    index:%5u    name: %s\n", index, expt.kind,
               expt.index, expt.name);
    }
    printf("\n\n");

    // Code
    const uint32_t aot_code_size = (aot->GetMemConsumption()).aot_code_size;
    const uint32_t literal_size =
        ((AOTModule *)(aot->GetModule()))->literal_size;
    const uint32_t data_section_count =
        ((AOTModule *)(aot->GetModule()))->data_section_count;

    printf("Codes[%u]\n", aot_code_size);
    printf("  -code\n");
    printf("    -code_size: %u Bytes\n", code_size);
    printf("\n");
    printf("  -literal\n");
    printf("    -literal_size: %u Bytes\n", literal_size);
    printf("\n");
    printf("  -data section\n");
    for (uint32_t index = 0; index < data_section_count; index++) {
        AOTObjectDataSection *obj_data =
            ((AOTModule *)(aot->GetModule()))->data_sections + index;
        printf("    -[%u] code_size:%5u Bytes    name: %s\n", index,
               obj_data->size, obj_data->name);
    }
    printf("\n\n");
}

void
DumpCompare(AoTFile *aot, WasmFile *wasm)
{
    const AOTTargetInfo target_info = aot->GetTargetInfo();
    AOTModule *aot_module = (AOTModule *)(aot->GetModule());
    WASMModuleMemConsumption aot_mem_conspn = aot->GetMemConsumption();

    WASMModule *wasm_module = (WASMModule *)(wasm->GetModule());

    const uint32_t aot_func_count = aot_module->func_count;
    const uint32_t aot_code_size = aot_module->code_size;
    struct func_info *sorted_func_ptrs = NULL;
    sorted_func_ptrs = sort_func_ptrs(((AOTModule *)(aot->GetModule())));
    if (!sorted_func_ptrs) {
        printf("sort AoT functions failed.\n");
        return;
    }

    const uint32_t wasm_func_count = wasm_module->function_count;
    WASMFunction **wasm_functions = wasm_module->functions;

    if (aot_func_count != wasm_func_count) {
        printf("The number of AoT functions does not match the number of Wasm "
               "functions.\n");
        wasm_runtime_free(sorted_func_ptrs);
        return;
    }

    uint32_t wasm_code_size = 0;
    // print function Comparison Details
    printf(
        "|--------------------------------------------------------------------"
        "-------------------|\n");
    printf(
        "|                             Function Code Size Compare             "
        "                   |\n");
    printf(
        "|--------------------------------------------------------------------"
        "-------------------|\n");
    printf(
        "|   ID   |  AoT Function Code Size   |  Wasm Function Code Size   |  "
        "expansion multiple |\n");
    printf(
        "|--------------------------------------------------------------------"
        "-------------------|\n");

    for (uint32_t index = 0; index < aot_func_count; index++) {
        const uint32_t aot_func_size =
            index + 1 < aot_func_count
                ? (uintptr_t)(sorted_func_ptrs[index + 1].ptr)
                      - (uintptr_t)(sorted_func_ptrs[index].ptr)
                : aot_code_size + (uintptr_t)(aot_module->code)
                      - (uintptr_t)(sorted_func_ptrs[index].ptr);
        const uint32_t wasm_func_size = wasm_functions[index]->code_size;
        wasm_code_size += wasm_func_size;
        printf(
            "|  %4d  |    %10d Bytes       |    %10d Bytes        |  %10.2f    "
            " "
            "    |\n",
            index, aot_func_size, wasm_func_size,
            (aot_func_size * 1.0) / wasm_func_size);
        printf(
            "|-----------------------------------------------------------------"
            "-"
            "---------------------|\n");
    }
    wasm_runtime_free(sorted_func_ptrs);

    printf("\n\n");

    printf(
        "|--------------------------------------------------------------------"
        "---|\n");
    printf(
        "|                        Total Code Size Compare                     "
        "   |\n");
    printf(
        "|--------------------------------------------------------------------"
        "---|\n");
    printf("|  AoT code size= %10d Bytes  |  Wasm code size= %10d Bytes |\n",
           aot_code_size, wasm_code_size);
    printf(
        "|--------------------------------------------------------------------"
        "---|\n");
}

int
ProgramMain(int argc, char **argv)
{
    InitStdio();

    ParseOptions(argc, argv);
    if (!s_objdump_options.info && !s_objdump_options.text_size
        && !s_objdump_options.details && !s_objdump_options.compare) {
        fprintf(stderr,
                "At least one of the following switches must be given:\n");
        fprintf(stderr, " -i/ --info\n");
        fprintf(stderr, " -t/ --text-size\n");
        fprintf(stderr, " -x/ --details\n");
        fprintf(stderr, " -c/ --compare\n");
        return 1;
    }

    std::vector<BinaryFile *> readers;
    for (const char *filename : s_infiles) {
        BinaryFile *reader = NULL;
        const char *dot = strrchr(filename, '.');
        if (!dot) {
            printf("bad file name: %s\n", filename);
            continue;
        }

        if (strncmp(dot, ".aot", 4) == 0) {
            reader = new AoTFile(filename);
        }
        else if (strncmp(dot, ".wasm", 4) == 0) {
            reader = new WasmFile(filename);
        }
        else {
            printf("unknown file extension: %s\n", dot);
            continue;
        }

        if (reader && reader->ReadModule() == Result::Error) {
            printf("read module failed.\n");
            continue;
        }

        CHECK_RESULT(reader->Scan());
        readers.push_back(reader);
    }

    // -i/ --info
    if (s_objdump_options.info == 1) {
        for (size_t i = 0; i < readers.size(); ++i) {
            printf("\n");

            BinaryFile *reader = readers[i];
            const uint32_t module_type = reader->GetModule()->module_type;
            if (module_type == Wasm_Module_AoT) {
                AoTFile *aot = dynamic_cast<AoTFile *>(reader);
                if (!aot) {
                    printf("[DumpInfo]: Reader cast failed.\n");
                    continue;
                }
                DumpInfo(aot);
            }
            else {
                printf("[DumpInfo]: Wrong file format, not an AoT file.\n");
            }
        }
    }

    // -t/ --text-size
    if (s_objdump_options.text_size == 1) {
        for (size_t i = 0; i < readers.size(); ++i) {
            printf("\n");

            BinaryFile *reader = readers[i];
            const uint32_t module_type = reader->GetModule()->module_type;
            if (module_type == Wasm_Module_AoT) {
                AoTFile *aot = dynamic_cast<AoTFile *>(reader);
                if (!aot) {
                    printf("[DumpTextSize]: Reader cast failed.\n");
                    continue;
                }
                DumpTextSize(aot);
            }
            else {
                printf("[DumpTextSize]: Wrong file format, not an AoT file.\n");
            }
        }
    }

    // -x/ --details
    if (s_objdump_options.details == 1) {
        for (size_t i = 0; i < readers.size(); ++i) {
            printf("\n");

            BinaryFile *reader = readers[i];
            const uint32_t module_type = reader->GetModule()->module_type;
            if (module_type == Wasm_Module_AoT) {
                AoTFile *aot = dynamic_cast<AoTFile *>(reader);
                if (!aot) {
                    printf("[DumpDetails]: Reader cast failed.\n");
                    continue;
                }
                DumpDetails(aot);
            }
            else {
                printf("[DumpDetails]: Wrong file format, not an AoT file.\n");
            }
        }
    }

    // -c/ --compare
    if (s_objdump_options.compare == 1) {
        printf("\n");

        if (readers.size() != 2) {
            printf("[DumpCompare]: Illegal number of file parameters.\n");
            return 1;
        }

        AoTFile *aot = NULL;
        WasmFile *wasm = NULL;
        for (size_t i = 0; i < readers.size(); ++i) {
            BinaryFile *reader = readers[i];
            const uint32_t module_type = reader->GetModule()->module_type;
            if (module_type == Wasm_Module_AoT) {
                aot = dynamic_cast<AoTFile *>(reader);
            }
            else if (module_type == Wasm_Module_Bytecode) {
                wasm = dynamic_cast<WasmFile *>(reader);
            }
        }
        if (!aot) {
            printf("[DumpCompare]: an aot file is required for comparison.\n");
            return 1;
        }
        if (!wasm) {
            printf("[DumpCompare]: a wasm file is required for comparison.\n");
            return 1;
        }
        DumpCompare(aot, wasm);
    }
    return 0;
}

int
main(int argc, char **argv)
{
    ANALYZER_TRY
    return ProgramMain(argc, argv);
    ANALYZER_CATCH_BAD_ALLOC_AND_EXIT
}
