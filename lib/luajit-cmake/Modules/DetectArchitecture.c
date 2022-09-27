#if defined(__aarch64__) || defined(__arm64__)
const char *str = "ARCHITECTURE IS AArch64";
#elif defined(__arm__) || defined(__arm) || defined(__ARM__) || defined(__ARM)
const char *str = "ARCHITECTURE IS ARM";
#elif defined(__alpha__)
const char *str = "ARCHITECTURE IS Alpha";
#elif defined(__mips64__) || defined(__mips64) || defined(__MIPS64__) || defined(__MIPS64)
const char *str = "ARCHITECTURE IS Mips64";
#elif defined(__mips__) || defined(__mips) || defined(__MIPS__) || defined(__MIPS)
const char *str = "ARCHITECTURE IS Mips";
#elif defined(__ppc__) || defined(__ppc) || defined(__PPC__) || defined(__PPC) || defined(__powerpc__) || defined(__powerpc) || defined(__POWERPC__) || defined(__POWERPC) || defined(_M_PPC)
const char *str = "ARCHITECTURE IS PowerPC";
#elif defined(__s390__)
const char *str = "ARCHITECTURE IS SystemZ";
#elif defined(__sparc__)
const char *str = "ARCHITECTURE IS Sparc";
#elif defined(__xcore__)
const char *str = "ARCHITECTURE IS XCore";
#elif defined(__i386__) || defined(__i686__) || defined(_M_IX86)
const char *str = "ARCHITECTURE IS x86";
#elif defined(__x86_64__) || defined(__x86_64) || defined(_M_X64) || defined(_M_AMD64)
const char *str = "ARCHITECTURE IS x86_64";
#endif

int main(int argc, char **argv) {
    int require = str[argc];
    (void)argv;
    return require;
}
