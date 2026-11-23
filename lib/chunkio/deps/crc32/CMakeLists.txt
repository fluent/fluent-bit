include(CheckCSourceCompiles)

option(CIO_CRC32_SIMD "Enable hardware accelerated CRC32 kernels" On)

set(src
  crc32.c
  crc32_dispatch.c
  )

set(CIO_CRC32_DEFINITIONS "")
set(CIO_CRC32_SIMD_FLAGS "")

# The kernels in crc32_simd.c are selected at runtime, here we only find out
# which ones this compiler and target can build.
if(CIO_CRC32_SIMD)
  check_c_source_compiles("
    #if !defined(__x86_64__) && !defined(_M_X64)
    #error not x86-64
    #endif
    #include <immintrin.h>
    #if defined(__GNUC__) || defined(__clang__)
    __attribute__((__target__(\"sse4.2,pclmul\")))
    #endif
    int fold(void) {
        __m128i a = _mm_setzero_si128();
        a = _mm_clmulepi64_si128(a, a, 0x00);
        return _mm_extract_epi32(a, 1);
    }
    int main(void) {
        return fold();
    }" CIO_CRC32_HAVE_PCLMUL)

  if(CIO_CRC32_HAVE_PCLMUL)
    list(APPEND CIO_CRC32_DEFINITIONS CRC32_SIMD_SSE42_PCLMUL)

    check_c_source_compiles("
      #include <immintrin.h>
      #if defined(__GNUC__) || defined(__clang__)
      __attribute__((__target__(\"avx512f,pclmul,vpclmulqdq\")))
      #endif
      int fold(void) {
          __m512i a = _mm512_setzero_si512();
          a = _mm512_clmulepi64_epi128(a, a, 0x00);
          return _mm_extract_epi32(_mm512_extracti32x4_epi32(a, 0), 1);
      }
      int main(void) {
          return fold();
      }" CIO_CRC32_HAVE_AVX512_PCLMUL)

    if(CIO_CRC32_HAVE_AVX512_PCLMUL)
      list(APPEND CIO_CRC32_DEFINITIONS CRC32_SIMD_AVX512_PCLMUL)
    endif()
  endif()

  # Little-endian aarch64 with GCC or Clang: the CRC and PMULL extensions are
  # enabled for crc32_simd.c alone, nothing else may assume them.
  if(NOT CIO_CRC32_HAVE_PCLMUL AND NOT MSVC)
    set(CMAKE_REQUIRED_FLAGS_SAVED "${CMAKE_REQUIRED_FLAGS}")
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -march=armv8-a+crc+crypto")
    check_c_source_compiles("
      #if !defined(__aarch64__) || !defined(__AARCH64EL__)
      #error not little-endian aarch64
      #endif
      #if !defined(__linux__) && !defined(__APPLE__)
      #error no runtime detection for this system
      #endif
      #include <arm_acle.h>
      #include <arm_neon.h>
      int main(void) {
          return (int) __crc32d(0, 0);
      }" CIO_CRC32_HAVE_ARMV8_CRC32)
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS_SAVED}")

    if(CIO_CRC32_HAVE_ARMV8_CRC32)
      list(APPEND CIO_CRC32_DEFINITIONS CRC32_ARMV8_CRC32)
      set(CIO_CRC32_SIMD_FLAGS "-march=armv8-a+crc+crypto")
    endif()
  endif()
endif()

if(CIO_CRC32_DEFINITIONS)
  list(APPEND src crc32_simd.c)
  if(CIO_CRC32_SIMD_FLAGS)
    set_source_files_properties(crc32_simd.c PROPERTIES
      COMPILE_FLAGS "${CIO_CRC32_SIMD_FLAGS}")
  endif()
endif()

add_library(cio-crc32 STATIC ${src})
target_compile_definitions(cio-crc32 PRIVATE ${CIO_CRC32_DEFINITIONS})
