
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS
# To compile with PKCS11: add "-lpkcs11-helper" to LDFLAGS

CFLAGS	?= -O2
WARNING_CFLAGS ?= -Wall -Wextra -Wformat=2 -Wno-format-nonliteral
WARNING_CXXFLAGS ?= -Wall -Wextra -Wformat=2 -Wno-format-nonliteral
LDFLAGS ?=

MBEDTLS_TEST_PATH:=../tests/src
MBEDTLS_TEST_OBJS:=$(patsubst %.c,%.o,$(wildcard ${MBEDTLS_TEST_PATH}/*.c ${MBEDTLS_TEST_PATH}/drivers/*.c))

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../tests/include -I../include -D_FILE_OFFSET_BITS=64
LOCAL_CXXFLAGS = $(WARNING_CXXFLAGS) -I../include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS = ${MBEDTLS_TEST_OBJS} 		\
		-L../library 			\
		-lmbedtls$(SHARED_SUFFIX)	\
		-lmbedx509$(SHARED_SUFFIX)	\
		-lmbedcrypto$(SHARED_SUFFIX)

ifeq ($(shell uname -s),Linux)
DLOPEN_LDFLAGS ?= -ldl
else
DLOPEN_LDFLAGS ?=
endif

include ../3rdparty/Makefile.inc
LOCAL_CFLAGS+=$(THIRDPARTY_INCLUDES)

ifndef SHARED
MBEDLIBS=../library/libmbedcrypto.a ../library/libmbedx509.a ../library/libmbedtls.a
else
MBEDLIBS=../library/libmbedcrypto.$(DLEXT) ../library/libmbedx509.$(DLEXT) ../library/libmbedtls.$(DLEXT)
endif
DEP=${MBEDLIBS} ${MBEDTLS_TEST_OBJS}

ifdef DEBUG
LOCAL_CFLAGS += -g3
endif

# if we're running on Windows, build for Windows
ifdef WINDOWS
WINDOWS_BUILD=1
endif

ifdef WINDOWS_BUILD
DLEXT=dll
EXEXT=.exe
LOCAL_LDFLAGS += -lws2_32
ifdef SHARED
SHARED_SUFFIX=.$(DLEXT)
endif
else
DLEXT ?= so
EXEXT=
SHARED_SUFFIX=
endif

# Zlib shared library extensions:
ifdef ZLIB
LOCAL_LDFLAGS += -lz
endif

# Only build the dlopen test in shared library builds, and not when building
# for Windows.
ifdef BUILD_DLOPEN
# Don't override the value
else ifdef WINDOWS_BUILD
BUILD_DLOPEN =
else ifdef SHARED
BUILD_DLOPEN = y
else
BUILD_DLOPEN =
endif

APPS = \
	aes/crypt_and_hash$(EXEXT) \
	hash/generic_sum$(EXEXT) \
	hash/hello$(EXEXT) \
	pkey/dh_client$(EXEXT) \
	pkey/dh_genprime$(EXEXT) \
	pkey/dh_server$(EXEXT) \
	pkey/ecdh_curve25519$(EXEXT) \
	pkey/ecdsa$(EXEXT) \
	pkey/gen_key$(EXEXT) \
	pkey/key_app$(EXEXT) \
	pkey/key_app_writer$(EXEXT) \
	pkey/mpi_demo$(EXEXT) \
	pkey/pk_decrypt$(EXEXT) \
	pkey/pk_encrypt$(EXEXT) \
	pkey/pk_sign$(EXEXT) \
	pkey/pk_verify$(EXEXT) \
	pkey/rsa_decrypt$(EXEXT) \
	pkey/rsa_encrypt$(EXEXT) \
	pkey/rsa_genkey$(EXEXT) \
	pkey/rsa_sign$(EXEXT) \
	pkey/rsa_sign_pss$(EXEXT) \
	pkey/rsa_verify$(EXEXT) \
	pkey/rsa_verify_pss$(EXEXT) \
	psa/crypto_examples$(EXEXT) \
	psa/key_ladder_demo$(EXEXT) \
	psa/psa_constant_names$(EXEXT) \
	random/gen_entropy$(EXEXT) \
	random/gen_random_ctr_drbg$(EXEXT) \
	random/gen_random_havege$(EXEXT) \
	ssl/dtls_client$(EXEXT) \
	ssl/dtls_server$(EXEXT) \
	ssl/mini_client$(EXEXT) \
	ssl/ssl_client1$(EXEXT) \
	ssl/ssl_client2$(EXEXT) \
	ssl/ssl_context_info$(EXEXT) \
	ssl/ssl_fork_server$(EXEXT) \
	ssl/ssl_mail_client$(EXEXT) \
	ssl/ssl_server$(EXEXT) \
	ssl/ssl_server2$(EXEXT) \
	test/benchmark$(EXEXT) \
	test/query_compile_time_config$(EXEXT) \
	test/selftest$(EXEXT) \
	test/udp_proxy$(EXEXT) \
	test/zeroize$(EXEXT) \
	util/pem2der$(EXEXT) \
	util/strerror$(EXEXT) \
	x509/cert_app$(EXEXT) \
	x509/cert_req$(EXEXT) \
	x509/cert_write$(EXEXT) \
	x509/crl_app$(EXEXT) \
	x509/load_roots$(EXEXT) \
	x509/req_app$(EXEXT) \
# End of APPS

ifdef PTHREAD
APPS +=	ssl/ssl_pthread_server$(EXEXT)
endif

ifdef BUILD_DLOPEN
APPS +=	test/dlopen
endif

ifdef TEST_CPP
APPS += test/cpp_dummy_build$(EXEXT)
endif

.SILENT:

.PHONY: all clean list fuzz

all: $(APPS)
ifndef WINDOWS
# APPS doesn't include the fuzzing programs, which aren't "normal"
# sample or test programs, and don't build with MSVC which is
# warning about fopen
all: fuzz
endif

fuzz: ${MBEDTLS_TEST_OBJS}
	$(MAKE) -C fuzz THIRDPARTY_INCLUDES=$(THIRDPARTY_INCLUDES)

$(MBEDLIBS):
	$(MAKE) -C ../library

${MBEDTLS_TEST_OBJS}:
	$(MAKE) -C ../tests mbedtls_test

aes/crypt_and_hash$(EXEXT): aes/crypt_and_hash.c $(DEP)
	echo "  CC    aes/crypt_and_hash.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) aes/crypt_and_hash.c $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

hash/hello$(EXEXT): hash/hello.c $(DEP)
	echo "  CC    hash/hello.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) hash/hello.c       $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

hash/generic_sum$(EXEXT): hash/generic_sum.c $(DEP)
	echo "  CC    hash/generic_sum.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) hash/generic_sum.c $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/dh_client$(EXEXT): pkey/dh_client.c $(DEP)
	echo "  CC    pkey/dh_client.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/dh_client.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/dh_genprime$(EXEXT): pkey/dh_genprime.c $(DEP)
	echo "  CC    pkey/dh_genprime.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/dh_genprime.c $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/dh_server$(EXEXT): pkey/dh_server.c $(DEP)
	echo "  CC    pkey/dh_server.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/dh_server.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/ecdh_curve25519$(EXEXT): pkey/ecdh_curve25519.c $(DEP)
	echo "  CC    pkey/ecdh_curve25519.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/ecdh_curve25519.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/ecdsa$(EXEXT): pkey/ecdsa.c $(DEP)
	echo "  CC    pkey/ecdsa.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/ecdsa.c       $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/gen_key$(EXEXT): pkey/gen_key.c $(DEP)
	echo "  CC    pkey/gen_key.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/gen_key.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/key_app$(EXEXT): pkey/key_app.c $(DEP)
	echo "  CC    pkey/key_app.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/key_app.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/key_app_writer$(EXEXT): pkey/key_app_writer.c $(DEP)
	echo "  CC    pkey/key_app_writer.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/key_app_writer.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/mpi_demo$(EXEXT): pkey/mpi_demo.c $(DEP)
	echo "  CC    pkey/mpi_demo.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/mpi_demo.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/pk_decrypt$(EXEXT): pkey/pk_decrypt.c $(DEP)
	echo "  CC    pkey/pk_decrypt.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/pk_decrypt.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/pk_encrypt$(EXEXT): pkey/pk_encrypt.c $(DEP)
	echo "  CC    pkey/pk_encrypt.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/pk_encrypt.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/pk_sign$(EXEXT): pkey/pk_sign.c $(DEP)
	echo "  CC    pkey/pk_sign.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/pk_sign.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/pk_verify$(EXEXT): pkey/pk_verify.c $(DEP)
	echo "  CC    pkey/pk_verify.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/pk_verify.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/rsa_genkey$(EXEXT): pkey/rsa_genkey.c $(DEP)
	echo "  CC    pkey/rsa_genkey.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/rsa_genkey.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/rsa_sign$(EXEXT): pkey/rsa_sign.c $(DEP)
	echo "  CC    pkey/rsa_sign.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/rsa_sign.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/rsa_verify$(EXEXT): pkey/rsa_verify.c $(DEP)
	echo "  CC    pkey/rsa_verify.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/rsa_verify.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/rsa_sign_pss$(EXEXT): pkey/rsa_sign_pss.c $(DEP)
	echo "  CC    pkey/rsa_sign_pss.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/rsa_sign_pss.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/rsa_verify_pss$(EXEXT): pkey/rsa_verify_pss.c $(DEP)
	echo "  CC    pkey/rsa_verify_pss.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/rsa_verify_pss.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/rsa_decrypt$(EXEXT): pkey/rsa_decrypt.c $(DEP)
	echo "  CC    pkey/rsa_decrypt.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/rsa_decrypt.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/rsa_encrypt$(EXEXT): pkey/rsa_encrypt.c $(DEP)
	echo "  CC    pkey/rsa_encrypt.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/rsa_encrypt.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

psa/key_ladder_demo$(EXEXT): psa/key_ladder_demo.c $(DEP)
	echo "  CC    psa/key_ladder_demo.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) psa/key_ladder_demo.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

psa/psa_constant_names$(EXEXT): psa/psa_constant_names.c psa/psa_constant_names_generated.c $(DEP)
	echo "  CC    psa/psa_constant_names.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) psa/psa_constant_names.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

random/gen_entropy$(EXEXT): random/gen_entropy.c $(DEP)
	echo "  CC    random/gen_entropy.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) random/gen_entropy.c $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

random/gen_random_havege$(EXEXT): random/gen_random_havege.c $(DEP)
	echo "  CC    random/gen_random_havege.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) random/gen_random_havege.c $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

random/gen_random_ctr_drbg$(EXEXT): random/gen_random_ctr_drbg.c $(DEP)
	echo "  CC    random/gen_random_ctr_drbg.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) random/gen_random_ctr_drbg.c $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/dtls_client$(EXEXT): ssl/dtls_client.c $(DEP)
	echo "  CC    ssl/dtls_client.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/dtls_client.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/dtls_server$(EXEXT): ssl/dtls_server.c $(DEP)
	echo "  CC    ssl/dtls_server.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/dtls_server.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_client1$(EXEXT): ssl/ssl_client1.c $(DEP)
	echo "  CC    ssl/ssl_client1.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_client1.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

SSL_TEST_OBJECTS = test/query_config.o ssl/ssl_test_lib.o
SSL_TEST_DEPS = $(SSL_TEST_OBJECTS) \
		test/query_config.h \
		ssl/ssl_test_lib.h \
		ssl/ssl_test_common_source.c \
		$(DEP)

ssl/ssl_test_lib.o: ssl/ssl_test_lib.c ssl/ssl_test_lib.h $(DEP)
	echo "  CC    ssl/ssl_test_lib.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -c ssl/ssl_test_lib.c -o $@

ssl/ssl_client2$(EXEXT): ssl/ssl_client2.c $(SSL_TEST_DEPS)
	echo "  CC    ssl/ssl_client2.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_client2.c $(SSL_TEST_OBJECTS) $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_server$(EXEXT): ssl/ssl_server.c $(DEP)
	echo "  CC    ssl/ssl_server.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_server.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_server2$(EXEXT): ssl/ssl_server2.c $(SSL_TEST_DEPS)
	echo "  CC    ssl/ssl_server2.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_server2.c $(SSL_TEST_OBJECTS) $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_context_info$(EXEXT): ssl/ssl_context_info.c test/query_config.o test/query_config.h $(DEP)
	echo "  CC    ssl/ssl_context_info.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_context_info.c test/query_config.o $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_fork_server$(EXEXT): ssl/ssl_fork_server.c $(DEP)
	echo "  CC    ssl/ssl_fork_server.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_fork_server.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_pthread_server$(EXEXT): ssl/ssl_pthread_server.c $(DEP)
	echo "  CC    ssl/ssl_pthread_server.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_pthread_server.c   $(LOCAL_LDFLAGS) -lpthread  $(LDFLAGS) -o $@

ssl/ssl_mail_client$(EXEXT): ssl/ssl_mail_client.c $(DEP)
	echo "  CC    ssl/ssl_mail_client.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_mail_client.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/mini_client$(EXEXT): ssl/mini_client.c $(DEP)
	echo "  CC    ssl/mini_client.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/mini_client.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/benchmark$(EXEXT): test/benchmark.c $(DEP)
	echo "  CC    test/benchmark.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/benchmark.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/cpp_dummy_build.cpp: test/generate_cpp_dummy_build.sh
	echo "  Gen   test/cpp_dummy_build.cpp"
	test/generate_cpp_dummy_build.sh

test/cpp_dummy_build$(EXEXT): test/cpp_dummy_build.cpp $(DEP)
	echo "  CXX   test/cpp_dummy_build.cpp"
	$(CXX) $(LOCAL_CXXFLAGS) $(CXXFLAGS) test/cpp_dummy_build.cpp   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ifdef BUILD_DLOPEN
test/dlopen$(EXEXT): test/dlopen.c $(DEP)
	echo "  CC    test/dlopen.c"
# Do not link any test objects (that would bring in a static dependency on
# libmbedcrypto at least). Do not link with libmbed* (that would defeat the
# purpose of testing dynamic loading).
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/dlopen.c $(LDFLAGS) $(DLOPEN_LDFLAGS) -o $@
endif

test/query_config.o: test/query_config.c test/query_config.h $(DEP)
	echo "  CC    test/query_config.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -c test/query_config.c -o $@

test/selftest$(EXEXT): test/selftest.c $(DEP)
	echo "  CC    test/selftest.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/selftest.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/udp_proxy$(EXEXT): test/udp_proxy.c $(DEP)
	echo "  CC    test/udp_proxy.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/udp_proxy.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/zeroize$(EXEXT): test/zeroize.c $(DEP)
	echo "  CC    test/zeroize.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/zeroize.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/query_compile_time_config$(EXEXT): test/query_compile_time_config.c test/query_config.o test/query_config.h $(DEP)
	echo "  CC    test/query_compile_time_config.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/query_compile_time_config.c test/query_config.o $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

util/pem2der$(EXEXT): util/pem2der.c $(DEP)
	echo "  CC    util/pem2der.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) util/pem2der.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

util/strerror$(EXEXT): util/strerror.c $(DEP)
	echo "  CC    util/strerror.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) util/strerror.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

x509/cert_app$(EXEXT): x509/cert_app.c $(DEP)
	echo "  CC    x509/cert_app.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) x509/cert_app.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

x509/cert_write$(EXEXT): x509/cert_write.c $(DEP)
	echo "  CC    x509/cert_write.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) x509/cert_write.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

x509/crl_app$(EXEXT): x509/crl_app.c $(DEP)
	echo "  CC    x509/crl_app.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) x509/crl_app.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

x509/cert_req$(EXEXT): x509/cert_req.c $(DEP)
	echo "  CC    x509/cert_req.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) x509/cert_req.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

x509/load_roots$(EXEXT): x509/load_roots.c $(DEP)
	echo "  CC    x509/load_roots.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) x509/load_roots.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

x509/req_app$(EXEXT): x509/req_app.c $(DEP)
	echo "  CC    x509/req_app.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) x509/req_app.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

psa/crypto_examples$(EXEXT): psa/crypto_examples.c $(DEP)
	echo "  CC    psa/crypto_examples.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) psa/crypto_examples.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

clean:
ifndef WINDOWS
	rm -f $(APPS)
	-rm -f ssl/ssl_pthread_server$(EXEXT)
	-rm -f test/cpp_dummy_build.cpp test/cpp_dummy_build$(EXEXT)
	-rm -f test/dlopen$(EXEXT)
else
	if exist *.o del /Q /F *.o
	if exist *.exe del /Q /F *.exe
	if exist test\cpp_dummy_build.cpp del /Q /F test\cpp_dummy_build.cpp
endif
	$(MAKE) -C fuzz clean

list:
	echo $(APPS)
