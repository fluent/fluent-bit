#ifdef LIBCO_C

/*[amd64, arm, ppc, x86]:
   by default, co_swap_function is marked as a text (code) section
   if not supported, uncomment the below line to use mprotect instead */

/*
 * Testing Fluent Bit on Windows when doing co_swap it crash if the
 * option LIBCO_MPROTECT is not defined.
 */
#ifdef _WIN32
#define LIBCO_MPROTECT
#endif

/*[amd64]:
   Win64 only: provides a substantial speed-up, but will thrash XMM regs
   do not use this unless you are certain your application won't use SSE */
/* #define LIBCO_NO_SSE */

#ifdef LIBCO_C
  #ifdef LIBCO_MP
    #ifdef _MSC_VER
      #define thread_local __declspec (thread)
    #else
      #define thread_local __thread
    #endif
  #else
    #define thread_local
  #endif
#endif

#if __STDC_VERSION__ >= 201112L
  #ifndef _MSC_VER
    #include <stdalign.h>
  #endif
#else
  #define alignas(bytes)
#endif

#if defined(_MSC_VER)
  #pragma data_seg(".text")
  #define text_section __declspec(allocate(".text"))
#elif defined(__APPLE__) && defined(__MACH__)
  #define text_section __attribute__((section("__TEXT,__text")))
#elif defined(__clang__)
  #define text_section __attribute__((section(".text")))
#else
  #define text_section __attribute__((section(".text#")))
#endif

/* ifdef LIBCO_C */
#endif
