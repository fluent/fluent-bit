SUMMARY = "Data Collector tool for Embedded Linux"
DESCRIPTION = "Fluent Bit is a data collector tool for Embedded Linux, \
it support different kind of inputs and built-in metrics.              \
"

HOMEPAGE = "http://fluentbit.io"
BUGTRACKER = "https://github.com/fluent/fluent-bit/issues"

LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=2ee41112a44fe7014dce33e26468ba93"
SECTION = "net"

SRC_URI = "git://github.com/fluent/fluent-bit.git"

PV = "0.14+git${SRCPV}"
SRCREV = "master"

S = "${WORKDIR}/git"
HOST_SYS_ARCH = "${HOST_ARCH}"
HOST_SYS_TRIPLE = "${HOST_SYS_ARCH}-unknown-linux"
EXTRA_OECMAKE = "-DGNU_HOST=${HOST_SYS_TRIPLE} -DFLB_WITHOUT_EXAMPLES=On -DFLB_LUAJIT=Off -DFLB_FILTER_LUA=Off"

inherit cmake
