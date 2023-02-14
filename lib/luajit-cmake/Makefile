ifeq ($(MAKE),mingw32-make)
CMAKE_OPTIONS += -G"MinGW Makefiles"
endif

ifeq (${LUAJIT_DIR}, )
LUAJIT_DIR = $(shell pwd)/../LuaJIT
endif
CMAKE_OPTIONS += -DLUAJIT_DIR=${LUAJIT_DIR}

IOS_ARCH ?= armv7

.PHONY : all build install clean

# Basic
all: build
	cmake --build build --config Release

install: all
	cmake --install build

build:
	cmake -H. -Bbuild ${CMAKE_OPTIONS}

clean:
	@cmake -E remove_directory build

lua:
	cmake -H. -Bbuild -DLUA_DIR=$(shell pwd)/../lua
	cmake --build build --config Release

# Advance
iOS:
	cmake -H. -Bbuild ${CMAKE_OPTIONS} \
	-DCMAKE_TOOLCHAIN_FILE=$(shell pwd)/Utils/ios.toolchain.cmake \
	-DIOS_PLATFORM=OS -DIOS_ARCH=$(IOS_ARCH) -DLUAJIT_DISABLE_JIT=1 \
	-DASM_FLAGS="-arch ${IOS_ARCH} -isysroot ${shell xcrun --sdk iphoneos --show-sdk-path}"
	cmake --build build --config Release

Android:
	cmake -H. -Bbuild ${CMAKE_OPTIONS} \
	-DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK}/build/cmake/android.toolchain.cmake
	cmake --build build --config Release

Windows:
	cmake -H. -Bbuild ${CMAKE_OPTIONS} \
	-DCMAKE_TOOLCHAIN_FILE=${shell pwd}/Utils/windows.toolchain.cmake
	cmake --build build --config Release

