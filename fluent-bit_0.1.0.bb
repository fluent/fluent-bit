SUMMARY = "Data Collector tool for Embedded Linux"
DESCRIPTION = "Fluent Bit is a data collector tool for Embedded Linux, \
it support different kind of inputs and built-in metrics.              \
"

HOMEPAGE = "https://github.com/fluent/fluent-bit"
BUGTRACKER = "https://github.com/fluent/fluent-bit/issues"

LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=2ee41112a44fe7014dce33e26468ba93"

SECTION = "net"

# Temporal URL for demo purposes, no releases yet.
SRC_URI = "http://duda.io/fluent-bit-0.1.0.tar.gz"
SRC_URI[md5sum] = "76bb297884fd563fcdfc529d56d32051"
SRC_URI[sha256sum] = "f911129a33af84cef8276f080d6992ce6946b9c10f01d77f4efbddd3403b5be9"

EXTRA_OECMAKE = "-DFLB_XBEE=1"

inherit cmake

do_install_append() {
    install -d ${D}/usr/sbin/
    install -m 0755 ${WORKDIR}/fluent-bit-0.1.0/bin/fluent-bit ${D}/usr/sbin/
}
