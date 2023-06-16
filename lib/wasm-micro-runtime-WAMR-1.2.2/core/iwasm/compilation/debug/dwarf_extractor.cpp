/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "lldb/API/SBBlock.h"
#include "lldb/API/SBCompileUnit.h"
#include "lldb/API/SBCommandReturnObject.h"
#include "lldb/API/SBCommandInterpreter.h"
#include "lldb/API/SBBreakpointLocation.h"
#include "lldb/API/SBDebugger.h"
#include "lldb/API//SBFunction.h"
#include "lldb/API//SBModule.h"
#include "lldb/API//SBProcess.h"
#include "lldb/API//SBStream.h"
#include "lldb/API//SBSymbol.h"
#include "lldb/API//SBTarget.h"
#include "lldb/API//SBThread.h"
#include "lldb/API/SBDeclaration.h"

#include "dwarf_extractor.h"
#include "../aot_llvm.h"

#include "bh_log.h"
#include "../../aot/aot_runtime.h"

#include "llvm/BinaryFormat/Dwarf.h"

using namespace lldb;

typedef struct dwar_extractor {
    SBDebugger debugger;
    SBTarget target;
    SBModule module;

} dwar_extractor;

#define TO_HANDLE(extractor) (dwar_extractor_handle_t)(extractor)

#define TO_EXTACTOR(handle) (dwar_extractor *)(handle)

static bool is_debugger_initialized;

dwar_extractor_handle_t
create_dwarf_extractor(AOTCompData *comp_data, char *file_name)
{
    char *arch = NULL;
    char *platform = NULL;
    dwar_extractor *extractor = NULL;

    //__attribute__((constructor)) may be better?
    if (!is_debugger_initialized) {
        SBError error = SBDebugger::InitializeWithErrorHandling();
        if (error.Fail()) {
            LOG_ERROR("Init Dwarf Debugger failed");
            return TO_HANDLE(NULL);
        }
        is_debugger_initialized = true;
    }

    SBError error;
    SBFileSpec exe_file_spec(file_name, true);

    if (!(extractor = new dwar_extractor())) {
        LOG_ERROR("Create Dwarf Extractor error: failed to allocate memory");
        goto fail3;
    }

    extractor->debugger = SBDebugger::Create();
    if (!extractor->debugger.IsValid()) {
        LOG_ERROR("Create Dwarf Debugger failed");
        goto fail2;
    }

    extractor->target = extractor->debugger.CreateTarget(
        file_name, arch, platform, false, error);

    if (!error.Success()) {
        LOG_ERROR("Create Dwarf target failed:%s", error.GetCString());
        goto fail1;
    }

    if (!extractor->target.IsValid()) {
        LOG_ERROR("Create Dwarf target not valid");
        goto fail1;
    }

    extractor->module = extractor->target.FindModule(exe_file_spec);
    comp_data->extractor = TO_HANDLE(extractor);

    return TO_HANDLE(extractor);

fail1:
    SBDebugger::Destroy(extractor->debugger);

fail2:
    wasm_runtime_free(extractor);

fail3:
    return TO_HANDLE(NULL);
}

void
destroy_dwarf_extractor(dwar_extractor_handle_t handle)
{
    dwar_extractor *extractor = TO_EXTACTOR(handle);
    if (!extractor)
        return;
    extractor->debugger.DeleteTarget(extractor->target);
    SBDebugger::Destroy(extractor->debugger);
    delete extractor;
    SBDebugger::Terminate();
    is_debugger_initialized = false;
}

LLVMMetadataRef
dwarf_gen_file_info(AOTCompContext *comp_ctx)
{
    dwar_extractor *extractor;
    int units_number;
    LLVMMetadataRef file_info = NULL;
    const char *file_name;
    const char *dir_name;

    if (!(extractor = TO_EXTACTOR(comp_ctx->comp_data->extractor)))
        return NULL;

    units_number = extractor->module.GetNumCompileUnits();

    if (units_number > 0) {
        SBCompileUnit compile_unit = extractor->module.GetCompileUnitAtIndex(0);
        auto filespec = compile_unit.GetFileSpec();
        file_name = filespec.GetFilename();
        dir_name = filespec.GetDirectory();
        if (file_name || dir_name) {
            file_info = LLVMDIBuilderCreateFile(comp_ctx->debug_builder,
                                                file_name, strlen(file_name),
                                                dir_name, strlen(dir_name));
        }
    }
    return file_info;
}

#if 0
void
dwarf_gen_mock_vm_info(AOTCompContext *comp_ctx)
{
    LLVMMetadataRef file_info = NULL;
    LLVMMetadataRef comp_unit = NULL;
    file_info = LLVMDIBuilderCreateFile(comp_ctx->debug_builder,
                                        "ant_runtime_mock.c", 18, ".", 1);

    comp_unit = LLVMDIBuilderCreateCompileUnit(
      comp_ctx->debug_builder, LLVMDWARFSourceLanguageC, file_info,
      "ant compiler", 12, 0, NULL, 0, 1, NULL, 0, LLVMDWARFEmissionFull, 0, 0,
      0, "/", 1, "", 0);

    LLVMTypeRef ParamTys[] = {
        LLVMVoidType(),
    };

    LLVMTypeRef FuncTy = LLVMFunctionType(LLVMVoidType(), ParamTys, 0, 0);

    LLVMValueRef Function =
      LLVMAddFunction(comp_ctx->module, "ant_runtime_mock", FuncTy);

    LLVMMetadataRef ParamTypes[0];
    LLVMMetadataRef FunctionTy = LLVMDIBuilderCreateSubroutineType(
      comp_ctx->debug_builder, file_info, ParamTypes, 0, LLVMDIFlagZero);

    /* 0x0015 is subroutine_type */
    LLVMMetadataRef ReplaceableFunctionMetadata =
      LLVMDIBuilderCreateReplaceableCompositeType(
        comp_ctx->debug_builder, 0x15, "ant_runtime_mock", 16, file_info,
        file_info, 2, 0, 0, 0, LLVMDIFlagFwdDecl, "", 0);

    LLVMMetadataRef FunctionMetadata = LLVMDIBuilderCreateFunction(
      comp_ctx->debug_builder, file_info, "ant_runtime_mock", 16,
      "ant_runtime_mock", 16, file_info, 2, FunctionTy, true, true, 2, LLVMDIFlagZero,
      false);

    LLVMMetadataReplaceAllUsesWith(ReplaceableFunctionMetadata,
                                   FunctionMetadata);

    LLVMSetSubprogram(Function, FunctionMetadata);

    comp_ctx->vm_debug_comp_unit = comp_unit;
    comp_ctx->vm_debug_file = file_info;
    comp_ctx->vm_debug_func = FunctionMetadata;
}
#endif

LLVMMetadataRef
dwarf_gen_comp_unit_info(AOTCompContext *comp_ctx)
{
    dwar_extractor *extractor;
    int units_number;
    LLVMMetadataRef comp_unit = NULL;

    if (!(extractor = TO_EXTACTOR(comp_ctx->comp_data->extractor)))
        return NULL;

    units_number = extractor->module.GetNumCompileUnits();

    if (units_number > 0) {
        SBCompileUnit compile_unit = extractor->module.GetCompileUnitAtIndex(0);
        auto lang_type = compile_unit.GetLanguage();

        comp_unit = LLVMDIBuilderCreateCompileUnit(
            comp_ctx->debug_builder, LLDB_TO_LLVM_LANG_TYPE(lang_type),
            comp_ctx->debug_file, "ant compiler", 12, 0, NULL, 0, 1, NULL, 0,
            LLVMDWARFEmissionFull, 0, 0, 0, "/", 1, "", 0);
    }
    return comp_unit;
}

static LLVMDWARFTypeEncoding
lldb_get_basic_type_encoding(BasicType basic_type)
{
    LLVMDWARFTypeEncoding encoding = 0;
    switch (basic_type) {
        case eBasicTypeUnsignedChar:
            encoding = llvm::dwarf::DW_ATE_unsigned_char;
            break;
        case eBasicTypeSignedChar:
            encoding = llvm::dwarf::DW_ATE_signed_char;
            break;
        case eBasicTypeUnsignedInt:
        case eBasicTypeUnsignedLong:
        case eBasicTypeUnsignedLongLong:
        case eBasicTypeUnsignedWChar:
        case eBasicTypeUnsignedInt128:
        case eBasicTypeUnsignedShort:
            encoding = llvm::dwarf::DW_ATE_unsigned;
            break;
        case eBasicTypeInt:
        case eBasicTypeLong:
        case eBasicTypeLongLong:
        case eBasicTypeWChar:
        case eBasicTypeInt128:
        case eBasicTypeShort:
            encoding = llvm::dwarf::DW_ATE_signed;
            break;
        case eBasicTypeBool:
            encoding = llvm::dwarf::DW_ATE_boolean;
            break;
        case eBasicTypeHalf:
        case eBasicTypeFloat:
        case eBasicTypeDouble:
        case eBasicTypeLongDouble:
            encoding = llvm::dwarf::DW_ATE_float;
            break;
        default:
            break;
    }
    return encoding;
}

static LLVMMetadataRef
lldb_type_to_type_dbi(AOTCompContext *comp_ctx, SBType &type)
{
    LLVMMetadataRef type_info = NULL;
    BasicType basic_type = type.GetBasicType();
    uint64_t bit_size = type.GetByteSize() * 8;
    LLVMDIBuilderRef DIB = comp_ctx->debug_builder;
    LLVMDWARFTypeEncoding encoding;

    if (basic_type != eBasicTypeInvalid) {
        encoding = lldb_get_basic_type_encoding(basic_type);
        type_info = LLVMDIBuilderCreateBasicType(
            DIB, type.GetName(), strlen(type.GetName()), bit_size, encoding,
            LLVMDIFlagZero);
    }
    else if (type.IsPointerType()) {
        SBType pointee_type = type.GetPointeeType();
        type_info = LLVMDIBuilderCreatePointerType(
            DIB, lldb_type_to_type_dbi(comp_ctx, pointee_type), bit_size, 0, 0,
            "", 0);
    }

    return type_info;
}

static LLVMMetadataRef
lldb_function_to_function_dbi(AOTCompContext *comp_ctx, SBSymbolContext &sc,
                              AOTFuncContext *func_ctx)
{
    SBFunction function(sc.GetFunction());
    const char *function_name = function.GetName();
    const char *link_name = function.GetName();
    SBTypeList function_args = function.GetType().GetFunctionArgumentTypes();
    SBType return_type = function.GetType().GetFunctionReturnType();
    const size_t num_function_args = function_args.GetSize();
    dwar_extractor *extractor;

    if (!(extractor = TO_EXTACTOR(comp_ctx->comp_data->extractor)))
        return NULL;

    LLVMDIBuilderRef DIB = comp_ctx->debug_builder;
    LLVMMetadataRef File = comp_ctx->debug_file;

    LLVMMetadataRef ParamTypes[num_function_args + 1];

    ParamTypes[0] = lldb_type_to_type_dbi(comp_ctx, return_type);

    for (uint32_t function_arg_idx = 0; function_arg_idx < num_function_args;
         ++function_arg_idx) {
        SBType function_arg_type =
            function_args.GetTypeAtIndex(function_arg_idx);

        if (function_arg_type.IsValid()) {
            ParamTypes[function_arg_idx + 1] =
                lldb_type_to_type_dbi(comp_ctx, function_arg_type);
        }
    }

    LLVMMetadataRef FunctionTy = LLVMDIBuilderCreateSubroutineType(
        DIB, File, ParamTypes, num_function_args + 1, LLVMDIFlagZero);

    auto line_entry = sc.GetLineEntry();
    LLVMMetadataRef ReplaceableFunctionMetadata =
        LLVMDIBuilderCreateReplaceableCompositeType(
            DIB, 0x15, function_name, strlen(function_name), File, File,
            line_entry.GetLine(), 0, 0, 0, LLVMDIFlagFwdDecl, "", 0);

    LLVMMetadataRef FunctionMetadata = LLVMDIBuilderCreateFunction(
        DIB, File, function_name, strlen(function_name), link_name,
        strlen(link_name), File, line_entry.GetLine(), FunctionTy, true, true,
        line_entry.GetLine(), LLVMDIFlagZero, false);

    LLVMMetadataReplaceAllUsesWith(ReplaceableFunctionMetadata,
                                   FunctionMetadata);

    LLVMSetSubprogram(func_ctx->func, FunctionMetadata);

    LLVMMetadataRef ParamExpression =
        LLVMDIBuilderCreateExpression(DIB, NULL, 0);
    auto variable_list =
        function.GetBlock().GetVariables(extractor->target, true, false, false);
    if (num_function_args != variable_list.GetSize()) {
        LOG_ERROR(
            "function args number dismatch!:value number=%d, function args=%d",
            variable_list.GetSize(), num_function_args);
    }

    LLVMMetadataRef ParamLocation = LLVMDIBuilderCreateDebugLocation(
        comp_ctx->context, line_entry.GetLine(), 0, FunctionMetadata, NULL);

    // TODO:change to void *  or WasmExenv * ？
    LLVMMetadataRef voidtype =
        LLVMDIBuilderCreateBasicType(DIB, "void", 4, 0, 0, LLVMDIFlagZero);
    LLVMMetadataRef voidpionter =
        LLVMDIBuilderCreatePointerType(DIB, voidtype, 64, 0, 0, "void *", 6);

    LLVMMetadataRef ParamVar = LLVMDIBuilderCreateParameterVariable(
        DIB, FunctionMetadata, "exenv", 5, 1,
        File, // starts form 1, and 1 is exenv,
        line_entry.GetLine(), voidpionter, true, LLVMDIFlagZero);
    LLVMValueRef Param = LLVMGetParam(func_ctx->func, 0);
    LLVMBasicBlockRef block_curr = LLVMGetEntryBasicBlock(func_ctx->func);
    LLVMDIBuilderInsertDbgValueAtEnd(DIB, Param, ParamVar, ParamExpression,
                                     ParamLocation, block_curr);

    for (uint32_t function_arg_idx = 0;
         function_arg_idx < variable_list.GetSize(); ++function_arg_idx) {
        SBValue variable(variable_list.GetValueAtIndex(function_arg_idx));
        if (variable.IsValid()) {
            SBDeclaration dec(variable.GetDeclaration());
            auto valtype = variable.GetType();
            LLVMMetadataRef ParamLocation = LLVMDIBuilderCreateDebugLocation(
                comp_ctx->context, dec.GetLine(), dec.GetColumn(),
                FunctionMetadata, NULL);
            LLVMMetadataRef ParamVar = LLVMDIBuilderCreateParameterVariable(
                DIB, FunctionMetadata, variable.GetName(),
                strlen(variable.GetName()), function_arg_idx + 1 + 1,
                File, // starts form 1, and 1 is exenv,
                dec.GetLine(), ParamTypes[function_arg_idx + 1], true,
                LLVMDIFlagZero);
            LLVMValueRef Param =
                LLVMGetParam(func_ctx->func, function_arg_idx + 1);
            LLVMDIBuilderInsertDbgValueAtEnd(DIB, Param, ParamVar,
                                             ParamExpression, ParamLocation,
                                             block_curr);
        }
    }

    return FunctionMetadata;
}

LLVMMetadataRef
dwarf_gen_func_info(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMMetadataRef func_info = NULL;
    dwar_extractor *extractor;
    uint64_t vm_offset;
    AOTFunc *func = func_ctx->aot_func;

    if (!(extractor = TO_EXTACTOR(comp_ctx->comp_data->extractor)))
        return NULL;

    // A code address in DWARF for WebAssembly is the offset of an
    // instruction relative within the Code section of the WebAssembly file.
    // For this reason Section::GetFileAddress() must return zero for the
    // Code section. (refert to ObjectFileWasm.cpp)
    vm_offset = func->code - comp_ctx->comp_data->wasm_module->buf_code;

    auto sbaddr = extractor->target.ResolveFileAddress(vm_offset);
    SBSymbolContext sc(sbaddr.GetSymbolContext(eSymbolContextFunction
                                               | eSymbolContextLineEntry));
    if (sc.IsValid()) {
        SBFunction function(sc.GetFunction());
        if (function.IsValid()) {
            func_info = lldb_function_to_function_dbi(comp_ctx, sc, func_ctx);
        }
    }
    return func_info;
}

void
dwarf_get_func_name(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                    char *name, int len)
{
    LLVMMetadataRef func_info = NULL;
    dwar_extractor *extractor;
    uint64_t vm_offset;
    AOTFunc *func = func_ctx->aot_func;

    name[0] = '\0';

    if (!(extractor = TO_EXTACTOR(comp_ctx->comp_data->extractor)))
        return;

    // A code address in DWARF for WebAssembly is the offset of an
    // instruction relative within the Code section of the WebAssembly file.
    // For this reason Section::GetFileAddress() must return zero for the
    // Code section. (refert to ObjectFileWasm.cpp)
    vm_offset = func->code - comp_ctx->comp_data->wasm_module->buf_code;

    auto sbaddr = extractor->target.ResolveFileAddress(vm_offset);
    SBSymbolContext sc(sbaddr.GetSymbolContext(eSymbolContextFunction
                                               | eSymbolContextLineEntry));
    if (sc.IsValid()) {
        SBFunction function(sc.GetFunction());
        if (function.IsValid()) {
            bh_strcpy_s(name, len, function.GetName());
        }
    }
}

LLVMMetadataRef
dwarf_gen_location(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                   uint64_t vm_offset)
{
    LLVMMetadataRef location_info = NULL;
    dwar_extractor *extractor;
    AOTFunc *func = func_ctx->aot_func;

    if (!(extractor = TO_EXTACTOR(comp_ctx->comp_data->extractor)))
        return NULL;

    auto sbaddr = extractor->target.ResolveFileAddress(vm_offset);
    SBSymbolContext sc(sbaddr.GetSymbolContext(eSymbolContextFunction
                                               | eSymbolContextLineEntry));
    if (sc.IsValid()) {
        // TODO:need to check if the vm_offset is belong to
        SBFunction function(sc.GetFunction());
        if (function.IsValid()) {
            uint64_t start = func_ctx->aot_func->code
                             - comp_ctx->comp_data->wasm_module->buf_code;
            uint64_t end = func_ctx->aot_func->code
                           - comp_ctx->comp_data->wasm_module->buf_code
                           + func_ctx->aot_func->code_size;
            if (function.GetStartAddress().GetOffset() <= start
                && end <= function.GetEndAddress().GetOffset()) {
                auto line_entry = sc.GetLineEntry();
                location_info = LLVMDIBuilderCreateDebugLocation(
                    comp_ctx->context, line_entry.GetLine(),
                    line_entry.GetColumn(), func_ctx->debug_func, NULL);
                // LOG_VERBOSE("Gen the location l:%d, c:%d at %lx",
                // line_entry.GetLine(), line_entry.GetColumn(), vm_offset);
            }
            else
                LOG_WARNING("the offset and function is not matched");
        }
    }
    return location_info;
}

LLVMMetadataRef
dwarf_gen_func_ret_location(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMMetadataRef func_info = NULL;
    dwar_extractor *extractor;
    uint64_t vm_offset;
    AOTFunc *func = func_ctx->aot_func;
    LLVMMetadataRef location_info = NULL;

    if (!(extractor = TO_EXTACTOR(comp_ctx->comp_data->extractor)))
        return NULL;

    // A code address in DWARF for WebAssembly is the offset of an
    // instruction relative within the Code section of the WebAssembly file.
    // For this reason Section::GetFileAddress() must return zero for the
    // Code section. (refert to ObjectFileWasm.cpp)
    vm_offset = (func->code + func->code_size - 1)
                - comp_ctx->comp_data->wasm_module->buf_code;
    location_info = dwarf_gen_location(comp_ctx, func_ctx, vm_offset);

    return location_info;
}
