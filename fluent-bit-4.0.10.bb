# Fluent Bit - Yocto / Bitbake
# ============================
# The following Bitbake package the latest Fluent Bit stable release.

SUMMARY = "Fast Log processor and Forwarder"
DESCRIPTION = "Fluent Bit is a data collector, processor and  \
forwarder for Linux. It supports several input sources and \
backends (destinations) for your data. \
"

HOMEPAGE = "http://fluentbit.io"
BUGTRACKER = "https://github.com/fluent/fluent-bit/issues"

LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=2ee41112a44fe7014dce33e26468ba93"
SECTION = "net"

PR = "r0"
PV = "4.0.10"

SRCREV = "v${PV}"
SRC_URI = "git://github.com/fluent/fluent-bit.git;nobranch=1"

S = "${WORKDIR}/git"
DEPENDS = "zlib bison-native flex-native"
INSANE_SKIP_${PN}-dev += "dev-elf"

# Use CMake 'Unix Makefiles' generator
OECMAKE_GENERATOR ?= "Unix Makefiles"

# Fluent Bit build options
# ========================

# Host related setup
EXTRA_OECMAKE += "-DGNU_HOST=${HOST_SYS} "

# Disable LuaJIT and filter_lua support
EXTRA_OECMAKE += "-DFLB_LUAJIT=Off -DFLB_FILTER_LUA=Off "

# Disable Library and examples
EXTRA_OECMAKE += "-DFLB_SHARED_LIB=Off -DFLB_EXAMPLES=Off "

# Systemd support (optional)
DEPENDS += "systemd"
EXTRA_OECMAKE += "-DFLB_IN_SYSTEMD=On "

# Kafka Output plugin (disabled by default): note that when
# enabling Kafka output plugin, the backend library librdkafka
# requires 'openssl' as a dependency.
#
# DEPENDS += "openssl "
# EXTRA_OECMAKE += "-DFLB_OUT_KAFKA=On "

inherit cmake systemd

SYSTEMD_SERVICE_${PN} = "fluent-bit.service"
TARGET_CC_ARCH_append = " ${SELECTED_OPTIMIZATION}"
