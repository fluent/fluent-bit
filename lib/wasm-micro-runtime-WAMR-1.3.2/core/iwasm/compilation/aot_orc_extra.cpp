/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "llvm-c/LLJIT.h"
#include "llvm-c/Orc.h"
#include "llvm-c/OrcEE.h"
#include "llvm-c/TargetMachine.h"

#if LLVM_VERSION_MAJOR < 17
#include "llvm/ADT/None.h"
#include "llvm/ADT/Optional.h"
#endif
#include "llvm/ExecutionEngine/JITEventListener.h"
#include "llvm/ExecutionEngine/Orc/CompileOnDemandLayer.h"
#include "llvm/ExecutionEngine/Orc/JITTargetMachineBuilder.h"
#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "llvm/ExecutionEngine/Orc/ObjectLinkingLayer.h"
#include "llvm/ExecutionEngine/Orc/ObjectTransformLayer.h"
#include "llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/Support/CBindingWrapping.h"

#include "aot_orc_extra.h"
#include "aot.h"

#if LLVM_VERSION_MAJOR >= 17
namespace llvm {
template<typename T>
using Optional = std::optional<T>;
}
#endif

using namespace llvm;
using namespace llvm::orc;
using GlobalValueSet = std::set<const GlobalValue *>;

namespace llvm {
namespace orc {

class InProgressLookupState;

class OrcV2CAPIHelper
{
  public:
#if LLVM_VERSION_MAJOR < 18
    using PoolEntry = SymbolStringPtr::PoolEntry;
    using PoolEntryPtr = SymbolStringPtr::PoolEntryPtr;

    // Move from SymbolStringPtr to PoolEntryPtr (no change in ref count).
    static PoolEntryPtr moveFromSymbolStringPtr(SymbolStringPtr S)
    {
        PoolEntryPtr Result = nullptr;
        std::swap(Result, S.S);
        return Result;
    }

    // Move from a PoolEntryPtr to a SymbolStringPtr (no change in ref count).
    static SymbolStringPtr moveToSymbolStringPtr(PoolEntryPtr P)
    {
        SymbolStringPtr S;
        S.S = P;
        return S;
    }

    // Copy a pool entry to a SymbolStringPtr (increments ref count).
    static SymbolStringPtr copyToSymbolStringPtr(PoolEntryPtr P)
    {
        return SymbolStringPtr(P);
    }

    static PoolEntryPtr getRawPoolEntryPtr(const SymbolStringPtr &S)
    {
        return S.S;
    }

    static void retainPoolEntry(PoolEntryPtr P)
    {
        SymbolStringPtr S(P);
        S.S = nullptr;
    }

    static void releasePoolEntry(PoolEntryPtr P)
    {
        SymbolStringPtr S;
        S.S = P;
    }

#endif
    static InProgressLookupState *extractLookupState(LookupState &LS)
    {
        return LS.IPLS.release();
    }

    static void resetLookupState(LookupState &LS, InProgressLookupState *IPLS)
    {
        return LS.reset(IPLS);
    }
};

} // namespace orc
} // namespace llvm

// ORC.h
#if LLVM_VERSION_MAJOR >= 18
inline LLVMOrcSymbolStringPoolEntryRef
wrap(SymbolStringPoolEntryUnsafe E)
{
    return reinterpret_cast<LLVMOrcSymbolStringPoolEntryRef>(E.rawPtr());
}

inline SymbolStringPoolEntryUnsafe
unwrap(LLVMOrcSymbolStringPoolEntryRef E)
{
    return reinterpret_cast<SymbolStringPoolEntryUnsafe::PoolEntry *>(E);
}
#endif

DEFINE_SIMPLE_CONVERSION_FUNCTIONS(ExecutionSession, LLVMOrcExecutionSessionRef)
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(IRTransformLayer, LLVMOrcIRTransformLayerRef)
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(JITDylib, LLVMOrcJITDylibRef)
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(JITTargetMachineBuilder,
                                   LLVMOrcJITTargetMachineBuilderRef)
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(ObjectTransformLayer,
                                   LLVMOrcObjectTransformLayerRef)
#if LLVM_VERSION_MAJOR < 18
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(OrcV2CAPIHelper::PoolEntry,
                                   LLVMOrcSymbolStringPoolEntryRef)
#endif
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(ObjectLayer, LLVMOrcObjectLayerRef)
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(SymbolStringPool, LLVMOrcSymbolStringPoolRef)
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(ThreadSafeModule, LLVMOrcThreadSafeModuleRef)

// LLJIT.h
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(LLJITBuilder, LLVMOrcLLJITBuilderRef)
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(LLLazyJITBuilder, LLVMOrcLLLazyJITBuilderRef)
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(LLLazyJIT, LLVMOrcLLLazyJITRef)

void
LLVMOrcLLJITBuilderSetNumCompileThreads(LLVMOrcLLJITBuilderRef Builder,
                                        unsigned NumCompileThreads)
{
    unwrap(Builder)->setNumCompileThreads(NumCompileThreads);
}

LLVMOrcLLLazyJITBuilderRef
LLVMOrcCreateLLLazyJITBuilder(void)
{
    return wrap(new LLLazyJITBuilder());
}

void
LLVMOrcDisposeLLLazyJITBuilder(LLVMOrcLLLazyJITBuilderRef Builder)
{
    delete unwrap(Builder);
}

void
LLVMOrcLLLazyJITBuilderSetNumCompileThreads(LLVMOrcLLLazyJITBuilderRef Builder,
                                            unsigned NumCompileThreads)
{
    unwrap(Builder)->setNumCompileThreads(NumCompileThreads);
}

void
LLVMOrcLLLazyJITBuilderSetJITTargetMachineBuilder(
    LLVMOrcLLLazyJITBuilderRef Builder, LLVMOrcJITTargetMachineBuilderRef JTMP)
{
    unwrap(Builder)->setJITTargetMachineBuilder(*unwrap(JTMP));
    /* Destroy the JTMP, similar to
       LLVMOrcLLJITBuilderSetJITTargetMachineBuilder */
    LLVMOrcDisposeJITTargetMachineBuilder(JTMP);
}

static Optional<CompileOnDemandLayer::GlobalValueSet>
PartitionFunction(GlobalValueSet Requested)
{
    std::vector<const GlobalValue *> GVsToAdd;

    for (auto *GV : Requested) {
        if (isa<Function>(GV) && GV->hasName()) {
            auto &F = cast<Function>(*GV);       /* get LLVM function */
            const Module *M = F.getParent();     /* get LLVM module */
            auto GVName = GV->getName();         /* get the function name */
            const char *gvname = GVName.begin(); /* C function name */
            const char *wrapper;
            uint32 prefix_len = strlen(AOT_FUNC_PREFIX);

            LOG_DEBUG("requested func %s", gvname);
            /* Convert "aot_func#n_wrapper" to "aot_func#n" */
            if (strstr(gvname, AOT_FUNC_PREFIX)) {
                char buf[16] = { 0 };
                char func_name[64];
                int group_stride, i, j;
                int num;

                /*
                 * if the jit wrapper (which has "_wrapper" suffix in
                 * the name) is requested, compile others in the group too.
                 * otherwise, only compile the requested one.
                 * (and possibly the correspondig wrapped function,
                 * which has AOT_FUNC_INTERNAL_PREFIX.)
                 */
                wrapper = strstr(gvname + prefix_len, "_wrapper");
                if (wrapper != NULL) {
                    num = WASM_ORC_JIT_COMPILE_THREAD_NUM;
                }
                else {
                    num = 1;
                    wrapper = strchr(gvname + prefix_len, 0);
                }
                bh_assert(wrapper - (gvname + prefix_len) > 0);
                /* Get AOT function index */
                bh_memcpy_s(buf, (uint32)sizeof(buf), gvname + prefix_len,
                            (uint32)(wrapper - (gvname + prefix_len)));
                i = atoi(buf);

                group_stride = WASM_ORC_JIT_BACKEND_THREAD_NUM;

                /* Compile some functions each time */
                for (j = 0; j < num; j++) {
                    Function *F1;
                    snprintf(func_name, sizeof(func_name), "%s%d",
                             AOT_FUNC_PREFIX, i + j * group_stride);
                    F1 = M->getFunction(func_name);
                    if (F1) {
                        LOG_DEBUG("compile func %s", func_name);
                        GVsToAdd.push_back(cast<GlobalValue>(F1));
                    }
                    snprintf(func_name, sizeof(func_name), "%s%d",
                             AOT_FUNC_INTERNAL_PREFIX, i + j * group_stride);
                    F1 = M->getFunction(func_name);
                    if (F1) {
                        LOG_DEBUG("compile func %s", func_name);
                        GVsToAdd.push_back(cast<GlobalValue>(F1));
                    }
                }
            }
        }
    }

    for (auto *GV : GVsToAdd) {
        Requested.insert(GV);
    }

    return Requested;
}

LLVMErrorRef
LLVMOrcCreateLLLazyJIT(LLVMOrcLLLazyJITRef *Result,
                       LLVMOrcLLLazyJITBuilderRef Builder)
{
    assert(Result && "Result can not be null");

    if (!Builder)
        Builder = LLVMOrcCreateLLLazyJITBuilder();

    auto J = unwrap(Builder)->create();
    LLVMOrcDisposeLLLazyJITBuilder(Builder);

    if (!J) {
        Result = nullptr;
        return 0;
    }

    LLLazyJIT *lazy_jit = J->release();
    lazy_jit->setPartitionFunction(PartitionFunction);

    *Result = wrap(lazy_jit);
    return LLVMErrorSuccess;
}

LLVMErrorRef
LLVMOrcDisposeLLLazyJIT(LLVMOrcLLLazyJITRef J)
{
    delete unwrap(J);
    return LLVMErrorSuccess;
}

LLVMErrorRef
LLVMOrcLLLazyJITAddLLVMIRModule(LLVMOrcLLLazyJITRef J, LLVMOrcJITDylibRef JD,
                                LLVMOrcThreadSafeModuleRef TSM)
{
    std::unique_ptr<ThreadSafeModule> TmpTSM(unwrap(TSM));
    return wrap(unwrap(J)->addLazyIRModule(*unwrap(JD), std::move(*TmpTSM)));
}

LLVMErrorRef
LLVMOrcLLLazyJITLookup(LLVMOrcLLLazyJITRef J, LLVMOrcExecutorAddress *Result,
                       const char *Name)
{
    assert(Result && "Result can not be null");

    auto Sym = unwrap(J)->lookup(Name);
    if (!Sym) {
        *Result = 0;
        return wrap(Sym.takeError());
    }

#if LLVM_VERSION_MAJOR < 15
    *Result = Sym->getAddress();
#else
    *Result = Sym->getValue();
#endif
    return LLVMErrorSuccess;
}

LLVMOrcSymbolStringPoolEntryRef
LLVMOrcLLLazyJITMangleAndIntern(LLVMOrcLLLazyJITRef J,
                                const char *UnmangledName)
{
#if LLVM_VERSION_MAJOR < 18
    return wrap(OrcV2CAPIHelper::moveFromSymbolStringPtr(
        unwrap(J)->mangleAndIntern(UnmangledName)));
#else
    return wrap(SymbolStringPoolEntryUnsafe::take(
        unwrap(J)->mangleAndIntern(UnmangledName)));
#endif
}

LLVMOrcJITDylibRef
LLVMOrcLLLazyJITGetMainJITDylib(LLVMOrcLLLazyJITRef J)
{
    return wrap(&unwrap(J)->getMainJITDylib());
}

const char *
LLVMOrcLLLazyJITGetTripleString(LLVMOrcLLLazyJITRef J)
{
    return unwrap(J)->getTargetTriple().str().c_str();
}

LLVMOrcExecutionSessionRef
LLVMOrcLLLazyJITGetExecutionSession(LLVMOrcLLLazyJITRef J)
{
    return wrap(&unwrap(J)->getExecutionSession());
}

LLVMOrcIRTransformLayerRef
LLVMOrcLLLazyJITGetIRTransformLayer(LLVMOrcLLLazyJITRef J)
{
    return wrap(&unwrap(J)->getIRTransformLayer());
}

LLVMOrcObjectTransformLayerRef
LLVMOrcLLLazyJITGetObjTransformLayer(LLVMOrcLLLazyJITRef J)
{
    return wrap(&unwrap(J)->getObjTransformLayer());
}

LLVMOrcObjectLayerRef
LLVMOrcLLLazyJITGetObjLinkingLayer(LLVMOrcLLLazyJITRef J)
{
    return wrap(&unwrap(J)->getObjLinkingLayer());
}
