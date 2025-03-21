/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <llvm/Passes/StandardInstrumentations.h>
#include <llvm/Support/Error.h>
#if LLVM_VERSION_MAJOR < 17
#include <llvm/ADT/None.h>
#include <llvm/ADT/Optional.h>
#include <llvm/ADT/Triple.h>
#endif
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/Twine.h>
#include <llvm/Analysis/TargetTransformInfo.h>
#include <llvm/CodeGen/TargetPassConfig.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm-c/Core.h>
#include <llvm-c/ExecutionEngine.h>
#if LLVM_VERSION_MAJOR < 17
#include <llvm-c/Initialization.h>
#endif
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/ExecutionEngine/JITEventListener.h>
#include <llvm/ExecutionEngine/RTDyldMemoryManager.h>
#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/ErrorHandling.h>
#if LLVM_VERSION_MAJOR >= 17
#include <llvm/Support/PGOOptions.h>
#include <llvm/Support/VirtualFileSystem.h>
#endif
#include <llvm/Target/CodeGenCWrappers.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/Transforms/Utils/LowerMemIntrinsics.h>
#include <llvm/Transforms/Vectorize/LoopVectorize.h>
#include <llvm/Transforms/Vectorize/LoadStoreVectorizer.h>
#include <llvm/Transforms/Vectorize/SLPVectorizer.h>
#include <llvm/Transforms/Vectorize/VectorCombine.h>
#include <llvm/Transforms/Scalar/LoopRotation.h>
#include <llvm/Transforms/Scalar/SimpleLoopUnswitch.h>
#include <llvm/Transforms/Scalar/LICM.h>
#include <llvm/Transforms/Scalar/GVN.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#if LLVM_VERSION_MAJOR >= 12
#include <llvm/Analysis/AliasAnalysis.h>
#endif
#include <llvm/ProfileData/InstrProf.h>

#include <cstring>
#include "../aot/aot_runtime.h"
#include "aot_llvm.h"

using namespace llvm;
using namespace llvm::orc;

#if LLVM_VERSION_MAJOR >= 17
namespace llvm {
template<typename T>
using Optional = std::optional<T>;
}
#endif

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

class ExpandMemoryOpPass : public PassInfoMixin<ExpandMemoryOpPass>
{
  public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
};

PreservedAnalyses
ExpandMemoryOpPass::run(Function &F, FunctionAnalysisManager &AM)
{
    SmallVector<MemIntrinsic *, 16> MemCalls;

    /* Iterate over all instructions in the function, looking for memcpy,
     * memmove, and memset.  When we find one, expand it into a loop. */

    for (auto &BB : F) {
        for (auto &Inst : BB) {
            if (auto *Memcpy = dyn_cast_or_null<MemCpyInst>(&Inst)) {
                MemCalls.push_back(Memcpy);
            }
            else if (auto *Memmove = dyn_cast_or_null<MemMoveInst>(&Inst)) {
                MemCalls.push_back(Memmove);
            }
            else if (auto *Memset = dyn_cast_or_null<MemSetInst>(&Inst)) {
                MemCalls.push_back(Memset);
            }
        }
    }

    for (MemIntrinsic *MemCall : MemCalls) {
        if (MemCpyInst *Memcpy = dyn_cast<MemCpyInst>(MemCall)) {
            Function *ParentFunc = Memcpy->getParent()->getParent();
            const TargetTransformInfo &TTI =
                AM.getResult<TargetIRAnalysis>(*ParentFunc);
            expandMemCpyAsLoop(Memcpy, TTI);
            Memcpy->eraseFromParent();
        }
        else if (MemMoveInst *Memmove = dyn_cast<MemMoveInst>(MemCall)) {
#if LLVM_VERSION_MAJOR >= 17
            Function *ParentFunc = Memmove->getParent()->getParent();
            const TargetTransformInfo &TTI =
                AM.getResult<TargetIRAnalysis>(*ParentFunc);
            expandMemMoveAsLoop(Memmove, TTI);
#else
            expandMemMoveAsLoop(Memmove);
#endif
            Memmove->eraseFromParent();
        }
        else if (MemSetInst *Memset = dyn_cast<MemSetInst>(MemCall)) {
            expandMemSetAsLoop(Memset);
            Memset->eraseFromParent();
        }
    }

    PreservedAnalyses PA;
    PA.preserveSet<CFGAnalyses>();

    return PA;
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

#if LLVM_VERSION_MAJOR >= 16
    Optional<PGOOptions> PGO = std::nullopt;
#else
    Optional<PGOOptions> PGO = llvm::None;
#endif

    if (comp_ctx->enable_llvm_pgo) {
        /* Disable static counter allocation for value profiler,
           it will be allocated by runtime */
        const char *argv[] = { "", "-vp-static-alloc=false" };
        cl::ParseCommandLineOptions(2, argv);
#if LLVM_VERSION_MAJOR < 17
        PGO = PGOOptions("", "", "", PGOOptions::IRInstr);
#else
        auto FS = vfs::getRealFileSystem();
        PGO = PGOOptions("", "", "", "", FS, PGOOptions::IRInstr);
#endif
    }
    else if (comp_ctx->use_prof_file) {
#if LLVM_VERSION_MAJOR < 17
        PGO = PGOOptions(comp_ctx->use_prof_file, "", "", PGOOptions::IRUse);
#else
        auto FS = vfs::getRealFileSystem();
        PGO = PGOOptions(comp_ctx->use_prof_file, "", "", "", FS,
                         PGOOptions::IRUse);
#endif
    }

#ifdef DEBUG_PASS
    PassInstrumentationCallbacks PIC;
    PassBuilder PB(TM, PTO, PGO, &PIC);
#else
#if LLVM_VERSION_MAJOR == 12
    PassBuilder PB(false, TM, PTO, PGO);
#else
    PassBuilder PB(TM, PTO, PGO);
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
            "loop-vectorize,slp-vectorizer,"
            "load-store-vectorizer,vector-combine,"
            "mem2reg,instcombine,simplifycfg,jump-threading,indvars";
        ExitOnErr(PB.parsePassPipeline(MPM, Passes));
    }
    else {
        FunctionPassManager FPM;

        /* Apply Vectorize related passes for AOT mode */
        FPM.addPass(LoopVectorizePass());
        FPM.addPass(SLPVectorizerPass());
        FPM.addPass(LoadStoreVectorizerPass());
        FPM.addPass(VectorCombinePass());

        if (comp_ctx->enable_llvm_pgo || comp_ctx->use_prof_file) {
            /* LICM pass: loop invariant code motion, attempting to remove
               as much code from the body of a loop as possible. Experiments
               show it is good to enable it when pgo is enabled. */
#if LLVM_VERSION_MAJOR >= 15
            LICMOptions licm_opt;
            FPM.addPass(
                createFunctionToLoopPassAdaptor(LICMPass(licm_opt), true));
#else
            FPM.addPass(createFunctionToLoopPassAdaptor(LICMPass(), true));
#endif
        }

        /*
        FPM.addPass(createFunctionToLoopPassAdaptor(LoopRotatePass()));
        FPM.addPass(createFunctionToLoopPassAdaptor(SimpleLoopUnswitchPass()));
        */

        MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));

        if (comp_ctx->llvm_passes) {
            ExitOnErr(PB.parsePassPipeline(MPM, comp_ctx->llvm_passes));
        }

        if (
#if LLVM_VERSION_MAJOR <= 13
            PassBuilder::OptimizationLevel::O0 == OL
#else
            OptimizationLevel::O0 == OL
#endif
        ) {
            MPM.addPass(PB.buildO0DefaultPipeline(OL));
        }
        else {
            if (!disable_llvm_lto) {
                /* Apply LTO for AOT mode */
                if (comp_ctx->comp_data->func_count >= 10
                    || comp_ctx->enable_llvm_pgo || comp_ctx->use_prof_file)
                    /* Add the pre-link optimizations if the func count
                       is large enough or PGO is enabled */
                    MPM.addPass(PB.buildLTOPreLinkDefaultPipeline(OL));
                else
                    MPM.addPass(PB.buildLTODefaultPipeline(OL, NULL));
            }
            else {
                MPM.addPass(PB.buildPerModuleDefaultPipeline(OL));
            }
        }

        /* Run specific passes for AOT indirect mode in last since general
            optimization may create some intrinsic function calls like
            llvm.memset, so let's remove these function calls here. */
        if (comp_ctx->is_indirect_mode) {
            FunctionPassManager FPM1;
            FPM1.addPass(ExpandMemoryOpPass());
            MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM1)));
        }
    }

    MPM.run(*M, MAM);
}

char *
aot_compress_aot_func_names(AOTCompContext *comp_ctx, uint32 *p_size)
{
    std::vector<std::string> NameStrs;
    std::string Result;
    char buf[32], *compressed_str;
    uint32 compressed_str_len, i;

    for (i = 0; i < comp_ctx->func_ctx_count; i++) {
        snprintf(buf, sizeof(buf), "%s%d", AOT_FUNC_PREFIX, i);
        std::string str(buf);
        NameStrs.push_back(str);
    }

#if LLVM_VERSION_MAJOR < 18
#define collectGlobalObjectNameStrings collectPGOFuncNameStrings
#endif
    if (collectGlobalObjectNameStrings(NameStrs, true, Result)) {
        aot_set_last_error("collect pgo func name strings failed");
        return NULL;
    }

    compressed_str_len = Result.size();
    if (!(compressed_str = (char *)wasm_runtime_malloc(compressed_str_len))) {
        aot_set_last_error("allocate memory failed");
        return NULL;
    }

    bh_memcpy_s(compressed_str, compressed_str_len, Result.c_str(),
                compressed_str_len);
    *p_size = compressed_str_len;
    return compressed_str;
}
