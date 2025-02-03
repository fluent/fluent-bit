ifndef QCONFIG
QCONFIG=qconfig.mk
endif
include $(QCONFIG)

#where to install vsomeip:
#$(INSTALL_ROOT_$(OS)) is pointing to $QNX_TARGET
#by default, unless it was manually re-routed to
#a staging area by setting both INSTALL_ROOT_nto
#and USE_INSTALL_ROOT
VSOMEIP_INSTALL_ROOT ?= $(INSTALL_ROOT_$(OS))

#where to find the vsomeip external dependencies, such as Boost
VSOMEIP_EXTERNAL_DEPS_INSTALL ?= $(USE_ROOT_$(OS))

# Get version information from CMakeLists.txt
VSOMEIP_MAJOR_VERSION = $(word 3, $(shell bash -c "grep VSOMEIP_MAJOR_VERSION $(PROJECT_ROOT)/../CMakeLists.txt | head -1 | head -c-2"))
VSOMEIP_MINOR_VERSION = $(word 3, $(shell bash -c "grep VSOMEIP_MINOR_VERSION $(PROJECT_ROOT)/../CMakeLists.txt | head -1 | head -c-2"))
VSOMEIP_PATCH_VERSION = $(word 3, $(shell bash -c "grep VSOMEIP_PATCH_VERSION $(PROJECT_ROOT)/../CMakeLists.txt | head -1 | head -c-2"))

#choose Release or Debug
CMAKE_BUILD_TYPE ?= Release

#set the following to TRUE if you want to compile the vsomeip tests.
#If you do, make sure to set GTEST_ROOT to point to the google test library sources
GENERATE_TESTS ?= TRUE
TEST_IP_MASTER ?= XXX.XXX.XXX.XXX
TEST_IP_SLAVE ?= XXX.XXX.XXX.XXX

#set the following to FALSE if generating .pinfo files is causing problems
GENERATE_PINFO_FILES ?= TRUE

#override 'all' target to bypass the default QNX build system
ALL_DEPENDENCIES = vsomeip_all
.PHONY: vsomeip_all

FLAGS   += -g -D_QNX_SOURCE
LDFLAGS += -Wl,--build-id=md5 -lang-c++ -lsocket

INCVPATH+=$(USE_ROOT_INCLUDE)
EXTRA_INCVPATH = $(USE_ROOT_INCLUDE)/io-sock
LIBVPATH=$(QNX_TARGET)/usr/lib
EXTRA_LIBVPATH = $(USE_ROOT_LIB)/io-sock

CMAKE_ARGS = -DCMAKE_TOOLCHAIN_FILE=$(PROJECT_ROOT)/qnx.nto.toolchain.cmake \
             -DCMAKE_INSTALL_PREFIX=$(VSOMEIP_INSTALL_ROOT)/$(CPUVARDIR)/usr \
             -DCMAKE_CXX_STANDARD=17 \
             -DCMAKE_NO_SYSTEM_FROM_IMPORTED=TRUE \
             -DVSOMEIP_EXTERNAL_DEPS_INSTALL=$(VSOMEIP_EXTERNAL_DEPS_INSTALL) \
             -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) \
             -DCMAKE_MODULE_PATH=$(PROJECT_ROOT) \
             -DEXTRA_CMAKE_C_FLAGS="$(FLAGS)" \
             -DEXTRA_CMAKE_CXX_FLAGS="$(FLAGS)" \
             -DEXTRA_CMAKE_LINKER_FLAGS="$(LDFLAGS)" \
             -DINSTALL_INCLUDE_DIR=$(VSOMEIP_INSTALL_ROOT)/usr/include \
             -DCPUVARDIR=$(CPUVARDIR) \
             -DGCC_VER=${GCC_VER} \
             -DVSOMEIP_INSTALL_ROUTINGMANAGERD=ON \
             -DDISABLE_DLT=y

ifeq ($(GENERATE_TESTS), TRUE)
CMAKE_ARGS += -DENABLE_SIGNAL_HANDLING=1 \
              -DTEST_IP_MASTER=$(TEST_IP_MASTER) \
              -DTEST_IP_SLAVE=$(TEST_IP_SLAVE)
endif

MAKE_ARGS ?= -j $(firstword $(JLEVEL) 4)

define PINFO
endef
PINFO_STATE=Experimental
USEFILE=

include $(MKFILES_ROOT)/qtargets.mk

ifneq ($(wildcard $(foreach dir,$(LIBVPATH),$(dir)/libregex.so)),)
	LDFLAGS += -lregex
endif


ifndef NO_TARGET_OVERRIDE
vsomeip_all:
	@mkdir -p build
	@cd build && cmake $(CMAKE_ARGS) ../../../../../
	@cd build && make all $(MAKE_ARGS)
	@cd build && make build_tests $(MAKE_ARGS)

install: vsomeip_all
	@cd build && make install $(MAKE_ARGS)
	@cd build && make build_tests install $(MAKE_ARGS)

clean iclean spotless:
	@rm -fr build

endif

#everything down below deals with the generation of the PINFO
#information for shared objects that is used by the QNX build
#infrastructure to embed metadata in the .so files, for example
#data and time, version number, description, etc. Metadata can
#be retrieved on the target by typing 'use -i <path to vsomeip .so file>'.
#this is optional: setting GENERATE_PINFO_FILES to FALSE will disable
#the insertion of metadata in .so files.
ifeq ($(GENERATE_PINFO_FILES), TRUE)
#the following rules are called by the cmake generated makefiles,
#in order to generate the .pinfo files for the shared libraries
%.so.$(VSOMEIP_MAJOR_VERSION).$(VSOMEIP_MINOR_VERSION).$(VSOMEIP_PATCH_VERSION):
	$(ADD_PINFO)
	$(ADD_USAGE)

%vsomeipd:
	$(ADD_PINFO)
	$(ADD_USAGE)
endif
