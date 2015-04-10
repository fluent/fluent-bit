### detects the current OS and does some configuration

# detect linux
ifeq ($(shell uname),Linux)
include make/os.linux.mk

# detect freebsd
else ifeq ($(shell uname),FreeBSD)
include make/os.freebsd.mk

# detect windows
else ifeq ($(OS),Windows_NT)
include make/os.windows.mk

# detect os x (darwin)
else ifeq ($(shell uname),Darwin)
include make/os.darwin.mk

# detect error
else
$(error Unknown OS ($(shell uname)), please see make/os_detect.mk)
endif

# some twisting
DEFCONFIG?=generic.mk
DEFCONFIG:=$(addprefix make/default/,$(firstword $(DEFCONFIG)))

BUILD_RULES?=generic.mk
BUILD_RULES:=$(addprefix make/build.,$(firstword $(BUILD_RULES)))

ifneq ($(POST_BUILD),)
POST_BUILD:=$(addprefix make/post.,$(firstword $(POST_BUILD)))
endif

ifneq ($(INSTALL_RULES),)
INSTALL_RULES:=$(addprefix make/install.,$(firstword $(INSTALL_RULES)))
endif
