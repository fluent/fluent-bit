APPLICATION = wamr-mini
# If no BOARD is defined in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../../../../RIOT

USEMODULE += ztimer64_msec
USEMODULE += ztimer_usec
USEMODULE += sema

WPEDANTIC := 0
WERROR := 0

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

ARCHIVES += $(BINDIR)/libwamr.a

#Load the usual RIOT make infrastructure

include $(RIOTBASE)/Makefile.include


WAMR_SOURCE = $(CURDIR)/../../..
WAMR_BUILD_DIR = $(BINDIR)/wamr

#less Wall TODO: get things fixed
CFLAGS :=  $(filter-out -pedantic, $(CFLAGS))
CFLAGS += -Wno-format
CFLAGS += -Wno-strict-prototypes
CFLAGS += -Wno-old-style-definition
CFLAGS += -Wno-cast-function-type

WAMR_CORE = $(WAMR_SOURCE)/core
IWASM_ROOT = $(WAMR_CORE)/iwasm
SHARED_LIB_ROOT = $(WAMR_CORE)/shared

IWASM_INCLUDES += ${IWASM_ROOT}/include \
                   ${SHARED_LIB_ROOT}/platform/include \
                   ${SHARED_LIB_ROOT}/platform/riot \


INCLUDES += $(addprefix -I,${IWASM_INCLUDES})



RIOT_INCLUDES = $(filter-out -%,$(subst -I,,$(INCLUDES)))

#WAMR_BUILD_TARGET is "X86_32" "AARCH64[sub]", "ARM[sub]",
#                     "THUMB[sub]", "MIPS" or "XTENSA"
#no msp430, no AVR support for now

#translate (CPU_ARCH) to Build Target
ifeq ($(CPU),native)
#$(CPU) is defined for every CPU
#Riot native is x86_32
	WAMR_BUILD_TARGET = X86_32
else ifeq ($(findstring arm,$(CPU_ARCH)),arm)
	WAMR_BUILD_TARGET = THUMB
else ifeq ($(CPU_ARCH),mips32r2)
	WAMR_BUILD_TARGET = MIPS
else ifeq ($(CPU_ARCH),xtensa)
	WAMR_BUILD_TARGET = XTENSA
endif

ifeq ($(QUIET), 0)
	CMAKEMAKEFLAGS += VERBOSE=1
endif


$(BINDIR)/libwamr.a: $(WAMR_BUILD_DIR)/libwamr.a
	cp $< $@

$(WAMR_BUILD_DIR)/libwamr.a: $(WAMR_BUILD_DIR)/Makefile
	$(MAKE) -C $(WAMR_BUILD_DIR) $(CMAKEMAKEFLAGS)

$(WAMR_BUILD_DIR)/Makefile: CMakeLists.txt
	cmake -B$(WAMR_BUILD_DIR) \
		"-DRIOT_INCLUDES=$(RIOT_INCLUDES)"\
		-DWAMR_ROOT_DIR=$(WAMR_SOURCE)\
		-DWAMR_BUILD_TARGET=$(WAMR_BUILD_TARGET)\
		-DCMAKE_SYSTEM_NAME=Generic \
		-DCMAKE_SYSTEM_PROCESSOR="$(MCPU)" \
		-DCMAKE_C_COMPILER=$(CC) \
		-DCMAKE_C_COMPILER_WORKS=TRUE \

print_build_target:
	@echo CPU_ARCH: $(CPU_ARCH)
	@echo CPU: $(CPU)
	@echo CFLAGS: $(CFLAGS)
	@echo WAMR_BUILD_TARGET: $(WAMR_BUILD_TARGET)
