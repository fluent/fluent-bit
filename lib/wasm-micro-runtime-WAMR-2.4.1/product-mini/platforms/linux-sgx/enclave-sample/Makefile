# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_SSL ?= /opt/intel/sgxssl
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
SPEC_TEST ?= 0

# These variables are automatically set by CMakeLists.txt
WAMR_BUILD_SGX_IPFS = 0
WAMR_BUILD_LIB_RATS = 0
WAMR_BUILD_GLOBAL_HEAP_POOL = 0
WAMR_BUILD_GLOBAL_HEAP_SIZE = 10485760
WAMR_BUILD_STATIC_PGO = 0
WAMR_BUILD_LIBC_WASI = 1

VMLIB_BUILD_DIR ?= $(CURDIR)/../build
LIB_RATS_SRC ?= $(VMLIB_BUILD_DIR)/_deps/librats-build
LIB_RATS_INSTALL_DIR := $(VMLIB_BUILD_DIR)/librats/lib/librats
LIB_RATS_INCLUDE_DIR := $(VMLIB_BUILD_DIR)/librats/include

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Cpp_Files := App/App.cpp
App_Include_Paths := -IApp -I$(SGX_SDK)/include
ifeq ($(WAMR_BUILD_LIB_RATS), 1)
	App_Include_Paths += -I$(LIB_RATS_INCLUDE_DIR)
endif

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths) \
			   -DWASM_ENABLE_STATIC_PGO=$(WAMR_BUILD_STATIC_PGO) \
			   -DWASM_ENABLE_LIBC_WASI=$(WAMR_BUILD_LIBC_WASI)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
	App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

ifeq ($(SPEC_TEST), 1)
	App_C_Flags += -DWASM_ENABLE_SPEC_TEST=1
else
	App_C_Flags += -DWASM_ENABLE_SPEC_TEST=0
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) libvmlib_untrusted.a -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

ifeq ($(WAMR_BUILD_LIB_RATS), 1)
	App_Link_Flags += -L$(LIB_RATS_INSTALL_DIR) -L$(SGX_SSL)/lib64 -lrats_u -lsgx_dcap_ql -lsgx_dcap_quoteverify -lsgx_ukey_exchange -lsgx_usgxssl
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := iwasm

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

ifeq ($(WAMR_BUILD_SGX_IPFS), 1)
	Intel_Ipfs_Trusted_Flag = -lsgx_tprotected_fs
	App_Link_Flags += -lsgx_uprotected_fs
endif

Crypto_Library_Name := sgx_tcrypto

WAMR_ROOT := $(CURDIR)/../../../../

Enclave_Cpp_Files := Enclave/Enclave.cpp

Enclave_Include_Paths := -IEnclave -I$(WAMR_ROOT)/core/iwasm/include \
                         -I$(WAMR_ROOT)/core/shared/utils \
                         -I$(WAMR_ROOT)/core/shared/platform/linux-sgx \
                         -I$(SGX_SDK)/include \
                         -I$(SGX_SDK)/include/tlibc \
                         -I$(SGX_SDK)/include/stlport

ifeq ($(WAMR_BUILD_LIB_RATS), 1)
	Enclave_Include_Paths += -I$(LIB_RATS_INCLUDE_DIR) -I$(SGX_SSL)/include
endif

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden \
				   -fpie -fstack-protector $(Enclave_Include_Paths) \
				   -DWASM_GLOBAL_HEAP_SIZE=$(WAMR_BUILD_GLOBAL_HEAP_SIZE) \
				   -DWASM_ENABLE_GLOBAL_HEAP_POOL=$(WAMR_BUILD_GLOBAL_HEAP_POOL) \
				   -DWASM_ENABLE_LIB_RATS=$(WAMR_BUILD_LIB_RATS) \
				   -DWASM_ENABLE_STATIC_PGO=$(WAMR_BUILD_STATIC_PGO) \
				   -DWASM_ENABLE_LIBC_WASI=$(WAMR_BUILD_LIBC_WASI)
ifeq ($(SPEC_TEST), 1)
	Enclave_C_Flags += -DWASM_ENABLE_SPEC_TEST=1
else
	Enclave_C_Flags += -DWASM_ENABLE_SPEC_TEST=0
endif

ifeq ($(WAMR_BUILD_LIB_RATS), 1)
	Rats_Lib_Link_Dirs := -L$(LIB_RATS_INSTALL_DIR) -L$(LIB_RATS_INSTALL_DIR)/attesters -L$(LIB_RATS_INSTALL_DIR)/verifiers -L$(SGX_SSL)/lib64 -L$(VMLIB_BUILD_DIR)/external/libcbor/src/libcbor/lib -L$(LIB_RATS_INSTALL_DIR)/crypto_wrappers
	Rats_Lib_W_Link_libs := -lattester_nullattester -lattester_sgx_ecdsa -lattester_sgx_la \
						-lverifier_nullverifier -lverifier_sgx_la -lverifier_sgx_ecdsa_qve -lcbor \
						-lrats_lib -lsgx_tsgxssl -lcrypto_wrapper_nullcrypto -lcrypto_wrapper_openssl
	Rats_Lib_NW_Link_libs := -lsgx_dcap_tvl -lsgx_tsgxssl_crypto
endif

Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) ${Rats_Lib_Link_Dirs} \
	-Wl,--whole-archive -l$(Trts_Library_Name) ${Rats_Lib_W_Link_libs} $(Intel_Ipfs_Trusted_Flag) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_pthread -lsgx_tkey_exchange -l$(Crypto_Library_Name) -l$(Service_Library_Name) $(Rats_Lib_NW_Link_libs) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0

Enclave_Edl_Search_Path     =   --search-path ../Enclave \
								--search-path $(SGX_SDK)/include \
								--search-path $(WAMR_ROOT)/core/shared/platform/linux-sgx
ifeq ($(WAMR_BUILD_LIB_RATS), 1)
	Enclave_Edl_Search_Path	+=	--search-path $(LIB_RATS_INCLUDE_DIR)/librats/edl --search-path $(SGX_SSL)/include
endif


Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App_Name) $(Signed_Enclave_Name)
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########
librats:
ifeq ($(WAMR_BUILD_LIB_RATS), 1)
	@cd $(LIB_RATS_SRC) && make install
	@echo "librats build success"
endif

App/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl librats
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl $(Enclave_Edl_Search_Path)
	@echo "GEN  =>  $@"

App/Enclave_u.o: App/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

libvmlib_untrusted.a: $(VMLIB_BUILD_DIR)/libvmlib_untrusted.a
	@cp $< $@
	@echo "CP $@  <=  $<"

$(App_Name): App/Enclave_u.o $(App_Cpp_Objects) libvmlib_untrusted.a
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


######## Enclave Objects ########
Enclave/Enclave_t.c: $(SGX_EDGER8R) Enclave/Enclave.edl librats
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl $(Enclave_Edl_Search_Path)
	@echo "GEN  =>  $@"

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

libvmlib.a: $(VMLIB_BUILD_DIR)/libvmlib.a
	@cp $< $@
	@echo "CP $@  <=  $<"

$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects) libvmlib.a
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.* libvmlib.a libvmlib_untrusted.a
