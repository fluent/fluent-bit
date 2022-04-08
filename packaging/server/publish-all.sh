#!/bin/bash
set -eux

SOURCE_DIR=${SOURCE_DIR:-$HOME/apt}
APTLY_CONFIG=${APTLY_CONFIG:-/etc/aptly.conf}

if [ -z "$1" ]; then
    echo "Usage: ./publish_all  new_version"
    echo "                          |      "
    echo "                        -----    "
    echo "                        1.9.1    "
    echo
    exit 1
fi
VERSION="$1"

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "Missing source directory: $SOURCE_DIR"
fi

# Amazon Linux 2
echo "Publishing AmazonLinux 2"
find "$SOURCE_DIR/amazonlinux/" -iname "*-bit-$VERSION-*aarch64*.rpm" -exec cp -fv {} "/var/www/apt.fluentbit.io/amazonlinux/2/aarch64" \;
createrepo -dvp "/var/www/apt.fluentbit.io/amazonlinux/2/aarch64"

find "$SOURCE_DIR/amazonlinux/" -iname "*-bit-$VERSION-*x86_64*.rpm" -exec cp -fv {} "/var/www/apt.fluentbit.io/amazonlinux/2/x86_64" \;
createrepo -dvp "/var/www/apt.fluentbit.io/amazonlinux/2/x86_64"

# Centos 7
echo "Publishing Centos 7"
find "$SOURCE_DIR/centos/7/" -iname "*-bit-$VERSION-*aarch64*.rpm" -exec cp -fv {} "/var/www/apt.fluentbit.io/centos/7/aarch64" \;
createrepo -dvp "/var/www/apt.fluentbit.io/centos/7/aarch64"

find "$SOURCE_DIR/centos/7/" -iname "*-bit-$VERSION-*x86_64*.rpm" -exec cp -fv {} "/var/www/apt.fluentbit.io/centos/7/x86_64" \;
createrepo -dvp "/var/www/apt.fluentbit.io/centos/7/x86_64"

# Centos 8
echo "Publishing Centos 8"
find "$SOURCE_DIR/centos/8/" -iname "*-bit-$VERSION-*aarch64*.rpm" -exec cp -fv {} "/var/www/apt.fluentbit.io/centos/8/aarch64" \;
createrepo -dvp "/var/www/apt.fluentbit.io/centos/8/aarch64"

find "$SOURCE_DIR/centos/8/" -iname "*-bit-$VERSION-*x86_64*.rpm" -exec cp -fv {} "/var/www/apt.fluentbit.io/centos/8/x86_64" \;
createrepo -dvp "/var/www/apt.fluentbit.io/centos/8/x86_64"

# Debian 10 Buster
echo "Publishing Debian 10 Buster"
# Conflicts otherwise with existing
find "$SOURCE_DIR/debian/buster/" -iname "*-bit_$VERSION*.deb" -exec aptly -config="$APTLY_CONFIG" repo add flb-debian-buster {} \;
aptly -config="$APTLY_CONFIG" snapshot create "fluent-bit-debian-buster-${VERSION}" from repo flb-debian-buster
if ! aptly -config="$APTLY_CONFIG" publish switch -gpg-key="releases@fluentbit.io" buster filesystem:debian/buster: "fluent-bit-debian-buster-${VERSION}" ; then
    # Cleanup snapshot in case we want to retry later
    aptly -config="$APTLY_CONFIG" snapshot drop "fluent-bit-debian-buster-${VERSION}"
    exit 1
fi

# Debian 11 Bullseye - notice tweak in repo location
echo "Publishing Debian 11 Bullseye"
find "$SOURCE_DIR/debian/bullseye/" -iname "*-bit_$VERSION*.deb" -exec aptly -config="$APTLY_CONFIG" repo add flb-debian-bullseye {} \;
aptly -config="$APTLY_CONFIG" snapshot create "fluent-bit-debian-bullseye-${VERSION}" from repo flb-debian-bullseye
if ! aptly -config="$APTLY_CONFIG" publish switch -gpg-key="releases@fluentbit.io" bullseye filesystem:debian/bullseye:bullseye "fluent-bit-debian-bullseye-${VERSION}"; then
    # Cleanup snapshot in case we want to retry later
    aptly -config="$APTLY_CONFIG" snapshot drop "fluent-bit-debian-bullseye-${VERSION}"
    exit 1
fi

# Raspbian 10 Buster
echo "Publishing Raspbian 10 Buster"
find "$SOURCE_DIR/raspbian/buster/" -iname "*-bit_$VERSION*.deb" -exec aptly -config="$APTLY_CONFIG" repo add flb-raspbian-buster {} \;
aptly -config="$APTLY_CONFIG" snapshot create "fluent-bit-raspbian-buster-${VERSION}" from repo flb-raspbian-buster
if ! aptly -config="$APTLY_CONFIG" publish switch -gpg-key="releases@fluentbit.io" buster filesystem:raspbian/buster: "fluent-bit-raspbian-buster-${VERSION}" ; then
    # Cleanup snapshot in case we want to retry later
    aptly -config="$APTLY_CONFIG" snapshot drop "fluent-bit-raspbian-buster-${VERSION}"
    exit 1
fi

# Raspbian 11 Bullseye - notice tweak in repo location
echo "Publishing Raspbian 11 Bullseye"
find "$SOURCE_DIR/raspbian/bullseye/" -iname "*-bit_$VERSION*.deb" -exec aptly -config="$APTLY_CONFIG" repo add flb-raspbian-bullseye {} \;
aptly -config="$APTLY_CONFIG" snapshot create "fluent-bit-raspbian-bullseye-${VERSION}" from repo flb-raspbian-bullseye
if ! aptly -config="$APTLY_CONFIG" publish switch -gpg-key="releases@fluentbit.io" bullseye filesystem:raspbian/bullseye:bullseye "fluent-bit-raspbian-bullseye-${VERSION}" ; then
    # Cleanup snapshot in case we want to retry later
    aptly -config="$APTLY_CONFIG" snapshot drop "fluent-bit-raspbian-bullseye-${VERSION}"
    exit 1
fi

# Ubuntu 16.04 Xenial
echo "Publishing Ubuntu 16.04 Xenial"
find "$SOURCE_DIR/ubuntu/xenial/" -iname "*-bit_$VERSION*.deb" -exec aptly -config="$APTLY_CONFIG" repo add flb-ubuntu-xenial {} \;
aptly -config="$APTLY_CONFIG" snapshot create "fluent-bit-ubuntu-xenial-${VERSION}" from repo flb-ubuntu-xenial
if ! aptly -config="$APTLY_CONFIG" publish switch -gpg-key="releases@fluentbit.io" xenial filesystem:ubuntu/xenial: "fluent-bit-ubuntu-xenial-${VERSION}" ; then
    # Cleanup snapshot in case we want to retry later
    aptly -config="$APTLY_CONFIG" snapshot drop "fluent-bit-ubuntu-xenial-${VERSION}"
    exit 1
fi

# Ubuntu 18.04 Bionic
echo "Publishing Ubuntu 18.04 Bionic"
find "$SOURCE_DIR/ubuntu/bionic/" -iname "*-bit_$VERSION*.deb" -exec aptly -config="$APTLY_CONFIG" repo add flb-ubuntu-bionic {} \;
aptly -config="$APTLY_CONFIG" snapshot create "fluent-bit-ubuntu-bionic-${VERSION}" from repo flb-ubuntu-bionic
if ! aptly -config="$APTLY_CONFIG" publish switch -gpg-key="releases@fluentbit.io" bionic filesystem:ubuntu/bionic: "fluent-bit-ubuntu-bionic-${VERSION}" ; then
    # Cleanup snapshot in case we want to retry later
    aptly -config="$APTLY_CONFIG" snapshot drop "fluent-bit-ubuntu-bionic-${VERSION}"
    exit 1
fi

# Ubuntu 20.04 Focal
echo "Publishing Ubuntu 20.04 Focal"
find "$SOURCE_DIR/ubuntu/focal/" -iname "*-bit_$VERSION*.deb" -exec aptly -config="$APTLY_CONFIG" repo add flb-ubuntu-focal {} \;
aptly -config="$APTLY_CONFIG" snapshot create "fluent-bit-ubuntu-focal-${VERSION}" from repo flb-ubuntu-focal
if ! aptly -config="$APTLY_CONFIG" publish switch -gpg-key="releases@fluentbit.io" -gpg-key="releases@fluentbit.io" focal filesystem:ubuntu/focal: "fluent-bit-ubuntu-focal-${VERSION}"; then
    # Cleanup snapshot in case we want to retry later
    aptly -config="$APTLY_CONFIG" snapshot drop "fluent-bit-ubuntu-focal-${VERSION}"
    exit 1
fi

# Sign YUM repo meta-data
find "/var/www/apt.fluentbit.io" -name repomd.xml -exec gpg --detach-sign --armor --yes -u "releases@fluentbit.io" {} \;