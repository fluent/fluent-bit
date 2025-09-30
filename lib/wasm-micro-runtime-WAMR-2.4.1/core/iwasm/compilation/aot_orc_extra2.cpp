/*
 * Copyright (C) 2023 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "llvm/ExecutionEngine/Orc/CompileUtils.h"
#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/SmallVectorMemoryBuffer.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"

#include "aot_orc_extra.h"
#include "bh_log.h"

typedef void (*cb_t)(void *, const char *, size_t, size_t);

class MyCompiler : public llvm::orc::IRCompileLayer::IRCompiler
{
  public:
    MyCompiler(llvm::orc::JITTargetMachineBuilder JTMB, cb_t cb, void *cb_data);
    llvm::Expected<llvm::orc::SimpleCompiler::CompileResult> operator()(
        llvm::Module &M) override;

  private:
    llvm::orc::JITTargetMachineBuilder JTMB;

    cb_t cb;
    void *cb_data;
};

MyCompiler::MyCompiler(llvm::orc::JITTargetMachineBuilder JTMB, cb_t cb,
                       void *cb_data)
  : IRCompiler(llvm::orc::irManglingOptionsFromTargetOptions(JTMB.getOptions()))
  , JTMB(std::move(JTMB))
  , cb(cb)
  , cb_data(cb_data)
{}

class PrintStackSizes : public llvm::MachineFunctionPass
{
  public:
    PrintStackSizes(cb_t cb, void *cb_data);
    bool runOnMachineFunction(llvm::MachineFunction &MF) override;
    static char ID;

  private:
    cb_t cb;
    void *cb_data;
};

PrintStackSizes::PrintStackSizes(cb_t cb, void *cb_data)
  : MachineFunctionPass(ID)
  , cb(cb)
  , cb_data(cb_data)
{}

char PrintStackSizes::ID = 0;

bool
PrintStackSizes::runOnMachineFunction(llvm::MachineFunction &MF)
{
    auto name = MF.getName();
    auto MFI = &MF.getFrameInfo();
    size_t sz = MFI->getStackSize();
    cb(cb_data, name.data(), name.size(), sz);
    return false;
}

class MyPassManager : public llvm::legacy::PassManager
{
  public:
    void add(llvm::Pass *P) override;
};

void
MyPassManager::add(llvm::Pass *P)
{
    // a hack to avoid having a copy of the whole addPassesToEmitMC.
    // we want to add PrintStackSizes before FreeMachineFunctionPass.
    if (P->getPassName() == "Free MachineFunction") {
        return;
    }
    llvm::legacy::PassManager::add(P);
}

// a modified copy from llvm/lib/ExecutionEngine/Orc/CompileUtils.cpp
llvm::Expected<llvm::orc::SimpleCompiler::CompileResult>
MyCompiler::operator()(llvm::Module &M)
{
    auto TM = cantFail(JTMB.createTargetMachine());
    llvm::SmallVector<char, 0> ObjBufferSV;

    {
        llvm::raw_svector_ostream ObjStream(ObjBufferSV);

        MyPassManager PM;
        llvm::MCContext *Ctx;
        if (TM->addPassesToEmitMC(PM, Ctx, ObjStream))
            return llvm::make_error<llvm::StringError>(
                "Target does not support MC emission",
                llvm::inconvertibleErrorCode());
        PM.add(new PrintStackSizes(cb, cb_data));
        dynamic_cast<llvm::legacy::PassManager *>(&PM)->add(
            llvm::createFreeMachineFunctionPass());
        PM.run(M);
    }

#if LLVM_VERSION_MAJOR > 13
    auto ObjBuffer = std::make_unique<llvm::SmallVectorMemoryBuffer>(
        std::move(ObjBufferSV),
        M.getModuleIdentifier() + "-jitted-objectbuffer",
        /*RequiresNullTerminator=*/false);
#else
    auto ObjBuffer = std::make_unique<llvm::SmallVectorMemoryBuffer>(
        std::move(ObjBufferSV),
        M.getModuleIdentifier() + "-jitted-objectbuffer");
#endif

    return std::move(ObjBuffer);
}

DEFINE_SIMPLE_CONVERSION_FUNCTIONS(llvm::orc::LLLazyJITBuilder,
                                   LLVMOrcLLLazyJITBuilderRef)

void
LLVMOrcLLJITBuilderSetCompileFunctionCreatorWithStackSizesCallback(
    LLVMOrcLLLazyJITBuilderRef Builder,
    void (*cb)(void *, const char *, size_t, size_t), void *cb_data)
{
    auto b = unwrap(Builder);
    b->setCompileFunctionCreator(
        [cb, cb_data](llvm::orc::JITTargetMachineBuilder JTMB)
            -> llvm::Expected<
                std::unique_ptr<llvm::orc::IRCompileLayer::IRCompiler>> {
            return std::make_unique<MyCompiler>(
                MyCompiler(std::move(JTMB), cb, cb_data));
        });
}
