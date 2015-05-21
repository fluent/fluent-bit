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

PR = "r0"
PV = "0.1.0"

S = "${WORKDIR}/git"
SRCREV = "master"
EXTRA_OECMAKE = "-DFLB_XBEE=1"

inherit cmake
