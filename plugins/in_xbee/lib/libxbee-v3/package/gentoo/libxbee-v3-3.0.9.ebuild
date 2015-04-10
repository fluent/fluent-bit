# Copyright 1999-2013 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=4

inherit eutils git-2

DESCRIPTION="libxbee v3"
HOMEPAGE="https://code.google.com/p/libxbee/"
SRC_URI=""

EGIT_REPO_URI="https://code.google.com/p/libxbee.libxbee-v3/"
EGIT_COMMIT="v${PV}"

LICENSE=""
SLOT="0"
KEYWORDS="~amd64"
IUSE=""

DEPEND=""
RDEPEND="${DEPEND}"

src_prepare() {
    epatch "${FILESDIR}/skip-index.html.patch"
}

src_configure() {
    emake SYS_ROOT="${D}" configure
}

src_compile() {
    emake SYS_ROOT="${D}" all
}

src_install() {
	mkdir -p "${D}/usr/share/man/man3"
    emake SYS_ROOT="${D}" install
}
