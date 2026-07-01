/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_ORC_LAZINESS_H_
#define _AOT_ORC_LAZINESS_H_

#include "llvm-c/Error.h"
#include "llvm-c/ExternC.h"
#include "llvm-c/LLJIT.h"
#include "llvm-c/Orc.h"
#include "llvm-c/Types.h"

LLVM_C_EXTERN_C_BEGIN

typedef struct LLVMOrcOpaqueLLLazyJITBuilder *LLVMOrcLLLazyJITBuilderRef;
typedef struct LLVMOrcOpaqueLLLazyJIT *LLVMOrcLLLazyJITRef;

// Extra bindings for LLJIT
void
LLVMOrcLLJITBuilderSetNumCompileThreads(LLVMOrcLLJITBuilderRef Builder,
                                        unsigned NumCompileThreads);

// Extra bindings for LLLazyJIT
LLVMOrcLLLazyJITBuilderRef
LLVMOrcCreateLLLazyJITBuilder(void);

void
LLVMOrcDisposeLLLazyJITBuilder(LLVMOrcLLLazyJITBuilderRef Builder);

void
LLVMOrcLLLazyJITBuilderSetJITTargetMachineBuilder(
    LLVMOrcLLLazyJITBuilderRef Builder, LLVMOrcJITTargetMachineBuilderRef JTMP);

void
LLVMOrcLLLazyJITBuilderSetNumCompileThreads(LLVMOrcLLLazyJITBuilderRef Builder,
                                            unsigned NumCompileThreads);

LLVMErrorRef
LLVMOrcCreateLLLazyJIT(LLVMOrcLLLazyJITRef *Result,
                       LLVMOrcLLLazyJITBuilderRef Builder);

LLVMErrorRef
LLVMOrcDisposeLLLazyJIT(LLVMOrcLLLazyJITRef J);

LLVMErrorRef
LLVMOrcLLLazyJITAddLLVMIRModule(LLVMOrcLLLazyJITRef J, LLVMOrcJITDylibRef JD,
                                LLVMOrcThreadSafeModuleRef TSM);

LLVMErrorRef
LLVMOrcLLLazyJITLookup(LLVMOrcLLLazyJITRef J, LLVMOrcExecutorAddress *Result,
                       const char *Name);

LLVMOrcSymbolStringPoolEntryRef
LLVMOrcLLLazyJITMangleAndIntern(LLVMOrcLLLazyJITRef J,
                                const char *UnmangledName);

LLVMOrcJITDylibRef
LLVMOrcLLLazyJITGetMainJITDylib(LLVMOrcLLLazyJITRef J);

const char *
LLVMOrcLLLazyJITGetTripleString(LLVMOrcLLLazyJITRef J);

LLVMOrcExecutionSessionRef
LLVMOrcLLLazyJITGetExecutionSession(LLVMOrcLLLazyJITRef J);

LLVMOrcIRTransformLayerRef
LLVMOrcLLLazyJITGetIRTransformLayer(LLVMOrcLLLazyJITRef J);

LLVMOrcObjectTransformLayerRef
LLVMOrcLLLazyJITGetObjTransformLayer(LLVMOrcLLLazyJITRef J);

void
LLVMOrcLLJITBuilderSetCompileFunctionCreatorWithStackSizesCallback(
    LLVMOrcLLLazyJITBuilderRef Builder,
    void (*cb)(void *, const char *, size_t, size_t), void *cb_data);

LLVMOrcObjectLayerRef
LLVMOrcLLLazyJITGetObjLinkingLayer(LLVMOrcLLLazyJITRef J);

LLVM_C_EXTERN_C_END
#endif
