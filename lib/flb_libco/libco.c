/*
  libco
  license: public domain
*/

#if defined(__clang__)
  #pragma clang diagnostic ignored "-Wparentheses"
#endif

#if defined(__clang__) || defined(__GNUC__)
  #if defined(_WIN32)
    /*
     * Check Windows before the architecture: on x86_64 MinGW both __amd64__
     * and _WIN32 are defined, so amd64.c would win, but its co_swap executes
     * a machine-code blob held in a read-only array and faults under DEP on
     * the first coroutine switch (the same reason the MSVC branch below
     * disables amd64.c "due to SIGSEGV bug"). Use the fiber backend, which is
     * what MSVC already selects on Windows.
     */
    #include "fiber.c"
  #elif defined(__i386__)
    #include "x86.c"
  #elif defined(__amd64__)
    #include "amd64.c"
  #elif defined(__arm__)
    #include "arm.c"
  #elif defined(__aarch64__)
    #include "aarch64.c"
  #elif defined(__powerpc64__) && defined(_CALL_ELF) && _CALL_ELF == 2
    #include "ppc64le.c"
  #elif defined(_ARCH_PPC) && !defined(__LITTLE_ENDIAN__)
    #include "ppc.c"
  #else
    #include "sjlj.c"
  #endif
#elif defined(_MSC_VER)
  #if defined(_M_IX86)
    #include "x86.c"
// Commented out due to SIGSEGV bug
//  #elif defined(_M_AMD64)
//    #include "amd64.c"
  #else
    #include "fiber.c"
  #endif
#else
  #error "libco: unsupported processor, compiler or operating system"
#endif
