/*
 * Copyright (c)2023 YAMAMOTO Takashi.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <llvm-c/TargetMachine.h>
#if LLVM_VERSION_MAJOR < 17
#include <llvm/ADT/None.h>
#include <llvm/ADT/Optional.h>
#endif
#include <llvm/IR/Instructions.h>
#if LLVM_VERSION_MAJOR >= 14
#include <llvm/MC/TargetRegistry.h>
#else
#include <llvm/Support/TargetRegistry.h>
#endif
#include <llvm/Target/TargetMachine.h>

#include "bh_assert.h"

#include "aot_llvm_extra2.h"

#if LLVM_VERSION_MAJOR >= 17
namespace llvm {
template<typename T>
using Optional = std::optional<T>;
}
#endif

static llvm::Optional<llvm::Reloc::Model>
convert(LLVMRelocMode reloc_mode)
{
    switch (reloc_mode) {
        case LLVMRelocDefault:
#if LLVM_VERSION_MAJOR >= 16
            return std::nullopt;
#else
            return llvm::None;
#endif
        case LLVMRelocStatic:
            return llvm::Reloc::Static;
        case LLVMRelocPIC:
            return llvm::Reloc::PIC_;
        case LLVMRelocDynamicNoPic:
            return llvm::Reloc::DynamicNoPIC;
        case LLVMRelocROPI:
            return llvm::Reloc::ROPI;
        case LLVMRelocRWPI:
            return llvm::Reloc::RWPI;
        case LLVMRelocROPI_RWPI:
            return llvm::Reloc::ROPI_RWPI;
    }
    bh_assert(0);
#if LLVM_VERSION_MAJOR >= 16
    return std::nullopt;
#else
    return llvm::None;
#endif
}

#if LLVM_VERSION_MAJOR < 18
static llvm::CodeGenOpt::Level
convert(LLVMCodeGenOptLevel opt_level)
{
    switch (opt_level) {
        case LLVMCodeGenLevelNone:
            return llvm::CodeGenOpt::None;
        case LLVMCodeGenLevelLess:
            return llvm::CodeGenOpt::Less;
        case LLVMCodeGenLevelDefault:
            return llvm::CodeGenOpt::Default;
        case LLVMCodeGenLevelAggressive:
            return llvm::CodeGenOpt::Aggressive;
    }
    bh_assert(0);
    return llvm::CodeGenOpt::None;
}
#else
static llvm::CodeGenOptLevel
convert(LLVMCodeGenOptLevel opt_level)
{
    switch (opt_level) {
        case LLVMCodeGenLevelNone:
            return llvm::CodeGenOptLevel::None;
        case LLVMCodeGenLevelLess:
            return llvm::CodeGenOptLevel::Less;
        case LLVMCodeGenLevelDefault:
            return llvm::CodeGenOptLevel::Default;
        case LLVMCodeGenLevelAggressive:
            return llvm::CodeGenOptLevel::Aggressive;
    }
    bh_assert(0);
    return llvm::CodeGenOptLevel::None;
}
#endif

static llvm::Optional<llvm::CodeModel::Model>
convert(LLVMCodeModel code_model, bool *jit)
{
    *jit = false;
    switch (code_model) {
        case LLVMCodeModelDefault:
#if LLVM_VERSION_MAJOR >= 16
            return std::nullopt;
#else
            return llvm::None;
#endif
        case LLVMCodeModelJITDefault:
            *jit = true;
#if LLVM_VERSION_MAJOR >= 16
            return std::nullopt;
#else
            return llvm::None;
#endif
        case LLVMCodeModelTiny:
            return llvm::CodeModel::Tiny;
        case LLVMCodeModelSmall:
            return llvm::CodeModel::Small;
        case LLVMCodeModelKernel:
            return llvm::CodeModel::Kernel;
        case LLVMCodeModelMedium:
            return llvm::CodeModel::Medium;
        case LLVMCodeModelLarge:
            return llvm::CodeModel::Large;
    }
    bh_assert(0);
#if LLVM_VERSION_MAJOR >= 16
    return std::nullopt;
#else
    return llvm::None;
#endif
}

LLVMTargetMachineRef
LLVMCreateTargetMachineWithOpts(LLVMTargetRef ctarget, const char *triple,
                                const char *cpu, const char *features,
                                LLVMCodeGenOptLevel opt_level,
                                LLVMRelocMode reloc_mode,
                                LLVMCodeModel code_model,
                                bool EmitStackSizeSection,
                                const char *StackUsageOutput)
{
    llvm::TargetOptions opts;

    // -fstack-size-section equiv
    // emit it to ".stack_sizes" section in case of ELF
    // you can read it with "llvm-readobj --stack-sizes"
    opts.EmitStackSizeSection = EmitStackSizeSection;

    // -fstack-usage equiv
    if (StackUsageOutput != NULL) {
        opts.StackUsageOutput = StackUsageOutput;
    }

    auto target = reinterpret_cast<llvm::Target *>(ctarget);
    auto rm = convert(reloc_mode);
    auto ol = convert(opt_level);
    bool jit;
    auto cm = convert(code_model, &jit);
    auto targetmachine = target->createTargetMachine(triple, cpu, features,
                                                     opts, rm, cm, ol, jit);
    return reinterpret_cast<LLVMTargetMachineRef>(targetmachine);
}

/* https://reviews.llvm.org/D153107 */
#if LLVM_VERSION_MAJOR < 18
using namespace llvm;

LLVMTailCallKind
LLVMGetTailCallKind(LLVMValueRef Call)
{
    return (LLVMTailCallKind)unwrap<CallInst>(Call)->getTailCallKind();
}

void
LLVMSetTailCallKind(LLVMValueRef Call, LLVMTailCallKind kind)
{
    unwrap<CallInst>(Call)->setTailCallKind((CallInst::TailCallKind)kind);
}
#endif
