/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <llvm/Passes/StandardInstrumentations.h>
#include <llvm/Support/Error.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/Twine.h>
#include <llvm/ADT/Triple.h>
#include <llvm/Analysis/TargetTransformInfo.h>
#include <llvm/CodeGen/TargetPassConfig.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm-c/Core.h>
#include <llvm-c/ExecutionEngine.h>
#include <llvm-c/Initialization.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/ExecutionEngine/JITEventListener.h>
#include <llvm/ExecutionEngine/RTDyldMemoryManager.h>
#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Target/CodeGenCWrappers.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/Transforms/Utils/LowerMemIntrinsics.h>
#include <llvm/Transforms/Vectorize/LoopVectorize.h>
#include <llvm/Transforms/Vectorize/LoadStoreVectorizer.h>
#include <llvm/Transforms/Vectorize/SLPVectorizer.h>
#include <llvm/Transforms/Scalar/LoopRotation.h>
#include <llvm/Transforms/Scalar/SimpleLoopUnswitch.h>
#include <llvm/Transforms/Scalar/LICM.h>
#include <llvm/Transforms/Scalar/GVN.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#if LLVM_VERSION_MAJOR >= 12
#include <llvm/Analysis/AliasAnalysis.h>
#endif

#include <cstring>
#include "../aot/aot_runtime.h"
#include "aot_llvm.h"

using namespace llvm;
using namespace llvm::orc;

LLVM_C_EXTERN_C_BEGIN

bool
aot_check_simd_compatibility(const char *arch_c_str, const char *cpu_c_str);

void
aot_add_expand_memory_op_pass(LLVMPassManagerRef pass);

void
aot_add_simple_loop_unswitch_pass(LLVMPassManagerRef pass);

void
aot_apply_llvm_new_pass_manager(AOTCompContext *comp_ctx, LLVMModuleRef module);

LLVM_C_EXTERN_C_END

ExitOnError ExitOnErr;

class ExpandMemoryOpPass : public llvm::ModulePass
{
  public:
    static char ID;

    ExpandMemoryOpPass()
      : ModulePass(ID)
    {}

    bool runOnModule(Module &M) override;

    bool expandMemIntrinsicUses(Function &F);
    StringRef getPassName() const override
    {
        return "Expand memory operation intrinsics";
    }

    void getAnalysisUsage(AnalysisUsage &AU) const override
    {
        AU.addRequired<TargetTransformInfoWrapperPass>();
    }
};

char ExpandMemoryOpPass::ID = 0;

bool
ExpandMemoryOpPass::expandMemIntrinsicUses(Function &F)
{
    Intrinsic::ID ID = F.getIntrinsicID();
    bool Changed = false;

    for (auto I = F.user_begin(), E = F.user_end(); I != E;) {
        Instruction *Inst = cast<Instruction>(*I);
        ++I;

        switch (ID) {
            case Intrinsic::memcpy:
            {
                auto *Memcpy = cast<MemCpyInst>(Inst);
                Function *ParentFunc = Memcpy->getParent()->getParent();
                const TargetTransformInfo &TTI =
                    getAnalysis<TargetTransformInfoWrapperPass>().getTTI(
                        *ParentFunc);
                expandMemCpyAsLoop(Memcpy, TTI);
                Changed = true;
                Memcpy->eraseFromParent();
                break;
            }
            case Intrinsic::memmove:
            {
                auto *Memmove = cast<MemMoveInst>(Inst);
                expandMemMoveAsLoop(Memmove);
                Changed = true;
                Memmove->eraseFromParent();
                break;
            }
            case Intrinsic::memset:
            {
                auto *Memset = cast<MemSetInst>(Inst);
                expandMemSetAsLoop(Memset);
                Changed = true;
                Memset->eraseFromParent();
                break;
            }
            default:
                break;
        }
    }

    return Changed;
}

bool
ExpandMemoryOpPass::runOnModule(Module &M)
{
    bool Changed = false;

    for (Function &F : M) {
        if (!F.isDeclaration())
            continue;

        switch (F.getIntrinsicID()) {
            case Intrinsic::memcpy:
            case Intrinsic::memmove:
            case Intrinsic::memset:
                if (expandMemIntrinsicUses(F))
                    Changed = true;
                break;

            default:
                break;
        }
    }

    return Changed;
}

void
aot_add_expand_memory_op_pass(LLVMPassManagerRef pass)
{
    reinterpret_cast<legacy::PassManager *>(pass)->add(
        new ExpandMemoryOpPass());
}

void
aot_add_simple_loop_unswitch_pass(LLVMPassManagerRef pass)
{
    reinterpret_cast<legacy::PassManager *>(pass)->add(
        createSimpleLoopUnswitchLegacyPass());
}

bool
aot_check_simd_compatibility(const char *arch_c_str, const char *cpu_c_str)
{
#if WASM_ENABLE_SIMD != 0
    if (!arch_c_str || !cpu_c_str) {
        return false;
    }

    llvm::SmallVector<std::string, 1> targetAttributes;
    llvm::Triple targetTriple(arch_c_str, "", "");
    auto targetMachine =
        std::unique_ptr<llvm::TargetMachine>(llvm::EngineBuilder().selectTarget(
            targetTriple, "", std::string(cpu_c_str), targetAttributes));
    if (!targetMachine) {
        return false;
    }

    const llvm::Triple::ArchType targetArch =
        targetMachine->getTargetTriple().getArch();
    const llvm::MCSubtargetInfo *subTargetInfo =
        targetMachine->getMCSubtargetInfo();
    if (subTargetInfo == nullptr) {
        return false;
    }

    if (targetArch == llvm::Triple::x86_64) {
        return subTargetInfo->checkFeatures("+sse4.1");
    }
    else if (targetArch == llvm::Triple::aarch64) {
        return subTargetInfo->checkFeatures("+neon");
    }
    else {
        return false;
    }
#else
    (void)arch_c_str;
    (void)cpu_c_str;
    return true;
#endif /* WASM_ENABLE_SIMD */
}

void
aot_apply_llvm_new_pass_manager(AOTCompContext *comp_ctx, LLVMModuleRef module)
{
    TargetMachine *TM =
        reinterpret_cast<TargetMachine *>(comp_ctx->target_machine);
    PipelineTuningOptions PTO;
    PTO.LoopVectorization = true;
    PTO.SLPVectorization = true;
    PTO.LoopUnrolling = true;

#ifdef DEBUG_PASS
    PassInstrumentationCallbacks PIC;
    PassBuilder PB(TM, PTO, None, &PIC);
#else
#if LLVM_VERSION_MAJOR == 12
    PassBuilder PB(false, TM, PTO);
#else
    PassBuilder PB(TM, PTO);
#endif
#endif

    /* Register all the basic analyses with the managers */
    LoopAnalysisManager LAM;
    FunctionAnalysisManager FAM;
    CGSCCAnalysisManager CGAM;
    ModuleAnalysisManager MAM;

    /* Register the target library analysis directly and give it a
       customized preset TLI */
    std::unique_ptr<TargetLibraryInfoImpl> TLII(
        new TargetLibraryInfoImpl(Triple(TM->getTargetTriple())));
    FAM.registerPass([&] { return TargetLibraryAnalysis(*TLII); });

    /* Register the AA manager first so that our version is the one used */
    AAManager AA = PB.buildDefaultAAPipeline();
    FAM.registerPass([&] { return std::move(AA); });

#ifdef DEBUG_PASS
    StandardInstrumentations SI(true, false);
    SI.registerCallbacks(PIC, &FAM);
#endif

    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

#if LLVM_VERSION_MAJOR <= 13
    PassBuilder::OptimizationLevel OL;

    switch (comp_ctx->opt_level) {
        case 0:
            OL = PassBuilder::OptimizationLevel::O0;
            break;
        case 1:
            OL = PassBuilder::OptimizationLevel::O1;
            break;
        case 2:
            OL = PassBuilder::OptimizationLevel::O2;
            break;
        case 3:
        default:
            OL = PassBuilder::OptimizationLevel::O3;
            break;
    }
#else
    OptimizationLevel OL;

    switch (comp_ctx->opt_level) {
        case 0:
            OL = OptimizationLevel::O0;
            break;
        case 1:
            OL = OptimizationLevel::O1;
            break;
        case 2:
            OL = OptimizationLevel::O2;
            break;
        case 3:
        default:
            OL = OptimizationLevel::O3;
            break;
    }
#endif /* end of LLVM_VERSION_MAJOR */

    bool disable_llvm_lto = comp_ctx->disable_llvm_lto;
#if WASM_ENABLE_SPEC_TEST != 0
    disable_llvm_lto = true;
#endif

    Module *M = reinterpret_cast<Module *>(module);
    if (disable_llvm_lto) {
        for (Function &F : *M) {
            F.addFnAttr("disable-tail-calls", "true");
        }
    }

    ModulePassManager MPM;
    if (comp_ctx->is_jit_mode) {
        const char *Passes =
            "mem2reg,instcombine,simplifycfg,jump-threading,indvars";
        ExitOnErr(PB.parsePassPipeline(MPM, Passes));
    }
    else {
        FunctionPassManager FPM;

        /* Apply Vectorize related passes for AOT mode */
        FPM.addPass(LoopVectorizePass());
        FPM.addPass(SLPVectorizerPass());
        FPM.addPass(LoadStoreVectorizerPass());

        /*
        FPM.addPass(createFunctionToLoopPassAdaptor(LICMPass()));
        FPM.addPass(createFunctionToLoopPassAdaptor(LoopRotatePass()));
        FPM.addPass(createFunctionToLoopPassAdaptor(SimpleLoopUnswitchPass()));
        */

        MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));

        if (!disable_llvm_lto) {
            /* Apply LTO for AOT mode */
            if (comp_ctx->comp_data->func_count >= 10)
                /* Adds the pre-link optimizations if the func count
                   is large enough */
                MPM.addPass(PB.buildLTOPreLinkDefaultPipeline(OL));
            else
                MPM.addPass(PB.buildLTODefaultPipeline(OL, NULL));
        }
        else {
            MPM.addPass(PB.buildPerModuleDefaultPipeline(OL));
        }
    }

    MPM.run(*M, MAM);
}
