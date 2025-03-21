#if defined(__SOFTFP__) || defined(_SOFT_FLOAT) || defined(_SOFT_DOUBLE) || defined(__mips_soft_float)
#define HAS_FPU 0
#else
#define HAS_FPU 1
#endif

#if !HAS_FPU
const char *str = "\0FPU IS Soft";
#else
const char *str = "\0FPU IS Hard";
#endif

#if defined(__SOFTFP__) || defined(_SOFT_FLOAT) || defined(_SOFT_DOUBLE) || defined(__mips_soft_float)
#define SOFT_FPU_ABI 1
#else
#if (defined(__arm__) || defined(__arm) || defined(__ARM__) || defined(__ARM)) && !defined(__ARM_PCS_VFP)
#define SOFT_FPU_ABI 1
#else
#define SOFT_FPU_ABI 0
#endif
#endif

#if SOFT_FPU_ABI
const char *fpu_abi_str = "\0FPU ABI IS Soft";
#else
const char *fpu_abi_str = "\0FPU ABI IS Hard";
#endif

int main(int argc, char **argv) {
    int require = str[argc];
    (void)argv;
    require += fpu_abi_str[argc];
    return require;
}
