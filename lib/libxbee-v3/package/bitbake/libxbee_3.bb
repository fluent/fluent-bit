MAINTAINER = "Ole Wolf <ole@naturloven.dk>"
HOMEPAGE = "https://code.google.com/p/libxbee/"
SUMMARY = "Library for Digi XBee radios running in API mode"
DESCRIPTION = "libxbee is a C/C++ library is to aid the use of Digi XBee radios running in API mode."
PROVIDES = "libxbee"
PR = "r0"

LICENSE = "LGPLv3"
LIC_FILES_CHKSUM = "file://COPYING;md5=d32239bcb673463ab874e80d47fae504"

SRC_URI = " \
	git://code.google.com/p/libxbee.libxbee-v3/;protocol=https \
"
SRCREV="${AUTOREV}"

S = "${WORKDIR}/git/"

FILES_${PN} += " \
	/usr/lib \
"

# Get the cross-compiler prefix.
CROSS_COMPILE = "$(echo $CC | sed -n -e "s/\([a-z\-]\+\)gcc .*/\1/p")"

EXTRA_OEMAKE += "SYS_ROOT=${D}/"

do_configure() {
	CROSS_COMPILE="${CROSS_COMPILE}" oe_runmake configure
}

do_compile() {
	unset CXXFLAGS
	CFLAGS="-fPIC" CROSS_COMPILE="${CROSS_COMPILE}" oe_runmake
}

do_install() {
	install -m 0755 -d -D ${D}/usr/lib
	install -m 0755 -d -D ${D}/usr/include
	install -m 0755 -d -D ${D}/usr/share/man/man3
	CROSS_COMPILE="${CROSS_COMPILE}" oe_runmake install
}
