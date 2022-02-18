#!/bin/bash
#

mkl_meta_set "description" "name"      "librdkafka"
mkl_meta_set "description" "oneline"   "The Apache Kafka C/C++ library"
mkl_meta_set "description" "long"      "Full Apache Kafka protocol support, including producer and consumer"
mkl_meta_set "description" "copyright" "Copyright (c) 2012-2019 Magnus Edenhill"

# Enable generation of pkg-config .pc file
mkl_mkvar_set "" GEN_PKG_CONFIG y


mkl_require cxx
mkl_require lib
mkl_require pic
mkl_require atomics
mkl_require good_cflags
mkl_require socket
mkl_require zlib
mkl_require libzstd
mkl_require libssl
mkl_require libsasl2

# Generate version variables from rdkafka.h hex version define
# so we can use it as string version when generating a pkg-config file.

verdef=$(grep '^#define  *RD_KAFKA_VERSION  *0x' src/rdkafka.h | sed 's/^#define  *RD_KAFKA_VERSION  *\(0x[a-f0-9]*\)\.*$/\1/')
mkl_require parseversion hex2str "%d.%d.%d" "$verdef" RDKAFKA_VERSION_STR


mkl_toggle_option "Development" ENABLE_DEVEL "--enable-devel" "Enable development asserts, checks, etc" "n"
mkl_toggle_option "Development" ENABLE_VALGRIND "--enable-valgrind" "Enable in-code valgrind suppressions" "n"

mkl_toggle_option "Development" ENABLE_REFCNT_DEBUG "--enable-refcnt-debug" "Enable refcnt debugging" "n"

mkl_toggle_option "Feature" ENABLE_LZ4_EXT "--enable-lz4-ext" "Enable external LZ4 library support (builtin version 1.9.2)" "y"
mkl_toggle_option "Feature" ENABLE_LZ4_EXT "--enable-lz4" "Deprecated: alias for --enable-lz4-ext" "y"

mkl_toggle_option "Feature" ENABLE_REGEX_EXT "--enable-regex-ext" "Enable external (libc) regex (else use builtin)" "y"

# librdkafka with TSAN won't work with glibc C11 threads on Ubuntu 19.04.
# This option allows disabling libc-based C11 threads and instead
# use the builtin tinycthread alternative.
mkl_toggle_option "Feature" ENABLE_C11THREADS "--enable-c11threads" "Enable detection of C11 threads support in libc" "try"

mkl_toggle_option "Feature" ENABLE_SYSLOG "--enable-syslog" "Enable logging to syslog" "y"


function checks {

    # -lrt is needed on linux for clock_gettime: link it if it exists.
    mkl_lib_check "librt" "" cont CC "-lrt"

    # pthreads required (even if C11 threads available) for rwlocks.
    mkl_lib_check "libpthread" "" fail CC "-lpthread" \
                  "#include <pthread.h>"

    if [[ $ENABLE_C11THREADS != n ]]; then
        case "$ENABLE_C11THREADS" in
            y) local action=fail ;;
            try) local action=disable ;;
            *) mkl_err "mklove internal error: invalid value for ENABLE_C11THREADS: $ENABLE_C11THREADS"; exit 1 ;;
        esac
        # Use internal tinycthread if C11 threads not available.
        # Requires -lpthread on glibc c11 threads, thus the use of $LIBS.
        mkl_lib_check "c11threads" WITH_C11THREADS $action CC "$LIBS" \
                      "
#include <threads.h>


static int start_func (void *arg) {
   int iarg = *(int *)arg;
   return iarg;
}

void foo (void) {
    thrd_t thr;
    int arg = 1;
    if (thrd_create(&thr, start_func, (void *)&arg) != thrd_success) {
      ;
    }
}
"
    fi

    # Check if dlopen() is available
    mkl_lib_check "libdl" "WITH_LIBDL" disable CC "-ldl" \
"
#include <stdlib.h>
#include <dlfcn.h>
void foo (void) {
   void *h = dlopen(\"__bad_lib\", 0);
   void *p = dlsym(h, \"sym\");
   if (p)
     p = NULL;
   dlclose(h);
}"

    if [[ $WITH_LIBDL == "y" ]]; then
        mkl_allvar_set WITH_PLUGINS WITH_PLUGINS y
    fi

    # optional libs
    mkl_check "zlib"
    mkl_check "libssl"
    mkl_check "libsasl2"
    mkl_check "libzstd"

    if mkl_lib_check "libm" "" disable CC "-lm" \
                     "#include <math.h>"; then
        mkl_allvar_set WITH_HDRHISTOGRAM WITH_HDRHISTOGRAM y
    fi

    # Use builtin lz4 if linking statically or if --disable-lz4-ext is used.
    if [[ $MKL_SOURCE_DEPS_ONLY != y ]] && [[ $WITH_STATIC_LINKING != y ]] && [[ $ENABLE_LZ4_EXT == y ]]; then
        mkl_meta_set "liblz4" "static" "liblz4.a"
        mkl_lib_check "liblz4" "WITH_LZ4_EXT" disable CC "-llz4" \
                      "#include <lz4frame.h>"
    fi

    if [[ $ENABLE_SYSLOG == y ]]; then
        mkl_compile_check "syslog" "WITH_SYSLOG" disable CC "" \
                          '
#include <syslog.h>
void foo (void) {
    syslog(LOG_INFO, "test");
}'
    fi

    # rapidjson (>=1.1.0) is used in tests to verify statistics data, not used
    # by librdkafka itself.
    mkl_compile_check "rapidjson" "WITH_RAPIDJSON" disable CXX "" \
                      "#include <rapidjson/schema.h>"

    # Snappy support is built-in
    mkl_allvar_set WITH_SNAPPY WITH_SNAPPY y

    # Enable sockem (tests)
    mkl_allvar_set WITH_SOCKEM WITH_SOCKEM y

    if [[ "$WITH_SSL" == "y" ]]; then
        # SASL SCRAM requires base64 encoding from OpenSSL
        mkl_allvar_set WITH_SASL_SCRAM WITH_SASL_SCRAM y
        # SASL OAUTHBEARER's default unsecured JWS implementation
        # requires base64 encoding from OpenSSL
        mkl_allvar_set WITH_SASL_OAUTHBEARER WITH_SASL_OAUTHBEARER y
    fi

    # CRC32C: check for crc32 instruction support.
    #         This is also checked during runtime using cpuid.
    mkl_compile_check crc32chw WITH_CRC32C_HW disable CC "" \
                      "
#include <inttypes.h>
#include <stdio.h>
#define LONGx1 \"8192\"
#define LONGx2 \"16384\"
void foo (void) {
   const char *n = \"abcdefghijklmnopqrstuvwxyz0123456789\";
   uint64_t c0 = 0, c1 = 1, c2 = 2;
   uint64_t s;
   uint32_t eax = 1, ecx;
   __asm__(\"cpuid\"
           : \"=c\"(ecx)
           : \"a\"(eax)
           : \"%ebx\", \"%edx\");
   __asm__(\"crc32b\t\" \"(%1), %0\"
           : \"=r\"(c0)
           : \"r\"(n), \"0\"(c0));
   __asm__(\"crc32q\t\" \"(%3), %0\n\t\"
           \"crc32q\t\" LONGx1 \"(%3), %1\n\t\"
           \"crc32q\t\" LONGx2 \"(%3), %2\"
           : \"=r\"(c0), \"=r\"(c1), \"=r\"(c2)
           : \"r\"(n), \"0\"(c0), \"1\"(c1), \"2\"(c2));
  s = c0 + c1 + c2;
  printf(\"avoiding unused code removal by printing %d, %d, %d\n\", (int)s, (int)eax, (int)ecx);
}
"


    # Check for libc regex
    if [[ $ENABLE_REGEX_EXT == y ]]; then
        mkl_compile_check "regex" "HAVE_REGEX" disable CC "" \
"
#include <stddef.h>
#include <regex.h>
void foo (void) {
   regcomp(NULL, NULL, 0);
   regexec(NULL, NULL, 0, NULL, 0);
   regerror(0, NULL, NULL, 0);
   regfree(NULL);
}"
    fi

    # Older g++ (<=4.1?) gives invalid warnings for the C++ code.
    mkl_mkvar_append CXXFLAGS CXXFLAGS "-Wno-non-virtual-dtor"

    # Required on SunOS
    if [[ $MKL_DISTRO == "sunos" ]]; then
	mkl_mkvar_append CPPFLAGS CPPFLAGS "-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT -D__EXTENSIONS__"
	# Source defines _POSIX_C_SOURCE to 200809L for Solaris, and this is
	# incompatible on that platform with compilers < c99.
	mkl_mkvar_append CFLAGS CFLAGS "-std=c99"
    fi

    # Check if rand_r() is available
    mkl_compile_check "rand_r" "HAVE_RAND_R" disable CC "" \
"#include <stdlib.h>
void foo (void) {
   unsigned int seed = 0xbeaf;
   (void)rand_r(&seed);
}"

    # Check if strndup() is available (isn't on Solaris 10)
    mkl_compile_check "strndup" "HAVE_STRNDUP" disable CC "" \
"#include <string.h>
int foo (void) {
   return strndup(\"hi\", 2) ? 0 : 1;
}"

    # Check if strlcpy() is available
    mkl_compile_check "strlcpy" "HAVE_STRLCPY" disable CC "" \
"
#define _DARWIN_C_SOURCE
#include <string.h>
int foo (void) {
    char dest[4];
   return strlcpy(dest, \"something\", sizeof(dest));
}"

    # Check if strerror_r() is available.
    # The check for GNU vs XSI is done in rdposix.h since
    # we can't rely on all defines to be set here (_GNU_SOURCE).
    mkl_compile_check "strerror_r" "HAVE_STRERROR_R" disable CC "" \
"#include <string.h>
const char *foo (void) {
   static char buf[64];
   strerror_r(1, buf, sizeof(buf));
   return buf;
}"

    # Check if strcasestr() is available.
    mkl_compile_check "strcasestr" "HAVE_STRCASESTR" disable CC "" \
"
#define _GNU_SOURCE
#include <string.h>
char *foo (const char *needle) {
   return strcasestr(\"the hay\", needle);
}"


    # See if GNU's pthread_setname_np() is available, and in what form.
    mkl_compile_check "pthread_setname_gnu" "HAVE_PTHREAD_SETNAME_GNU" disable CC "-D_GNU_SOURCE -lpthread" \
'
#include <pthread.h>

void foo (void) {
  pthread_setname_np(pthread_self(), "abc");
}
' || \
    mkl_compile_check "pthread_setname_darwin" "HAVE_PTHREAD_SETNAME_DARWIN" disable CC "-D_DARWIN_C_SOURCE -lpthread" \
'
#include <pthread.h>

void foo (void) {
  pthread_setname_np("abc");
}
' || \
    mkl_compile_check "pthread_setname_freebsd" "HAVE_PTHREAD_SETNAME_FREEBSD" disable CC "-lpthread" \
'
#include <pthread.h>
#include <pthread_np.h>

void foo (void) {
  pthread_set_name_np(pthread_self(), "abc");
}
'

    # Figure out what tool to use for dumping public symbols.
    # We rely on configure.cc setting up $NM if it exists.
    if mkl_env_check "nm" "" cont "NM" ; then
	# nm by future mk var
	if [[ $MKL_DISTRO == "osx" || $MKL_DISTRO == "aix" ]]; then
	    mkl_mkvar_set SYMDUMPER SYMDUMPER '$(NM) -g'
	else
	    mkl_mkvar_set SYMDUMPER SYMDUMPER '$(NM) -D'
	fi
    else
	# Fake symdumper
	mkl_mkvar_set SYMDUMPER SYMDUMPER 'echo'
    fi

    # The linker-script generator (lds-gen.py) requires python3
    if [[ $WITH_LDS == y ]]; then
        if ! mkl_command_check python3 "HAVE_PYTHON" "disable" "python3 -V"; then
            mkl_err "disabling linker-script since python3 is not available"
            mkl_mkvar_set WITH_LDS WITH_LDS "n"
        fi
    fi

    if [[ "$ENABLE_VALGRIND" == "y" ]]; then
	mkl_compile_check valgrind WITH_VALGRIND fail CC "" \
			  "#include <valgrind/memcheck.h>"
    fi

    # getrusage() is used by the test framework
    mkl_compile_check "getrusage" "HAVE_GETRUSAGE" disable CC "" \
'
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>


void foo (void) {
  struct rusage ru;
  if (getrusage(RUSAGE_SELF, &ru) == -1)
    return;
  printf("ut %ld, st %ld, maxrss %ld, nvcsw %ld\n",
         (long int)ru.ru_utime.tv_usec,
         (long int)ru.ru_stime.tv_usec,
         (long int)ru.ru_maxrss,
         (long int)ru.ru_nvcsw);
}'

}

