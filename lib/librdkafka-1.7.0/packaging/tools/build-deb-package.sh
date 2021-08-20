#!/bin/bash
#
# Build librdkafka Debian package on a bare-bone Debian host, such as ubuntu:16.04 (docker).
#
# Usage (from top-level librdkafka dir):
#   docker run -it -v $PWD:/v ubuntu:16.04 /v/packaging/tools/build-deb-package.sh 1.0.0 master
#

set -exu

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <package-version> <librdkafka-branch-or-tag>"
    exit 1
fi

export VERSION=$1
LRK_BRANCH=$2

apt-get update

# Install debian packaging tools and librdkafka build dependencies
apt-get install -y git-buildpackage debhelper \
        zlib1g-dev libssl-dev libsasl2-dev liblz4-dev


# Clone the librdkafka git repo to a new location to avoid messing
# up the librdkafka working directory.


BUILD_DIR=$(mktemp -d)

pushd $BUILD_DIR

git clone /v librdkafka

pushd librdkafka

export DEBEMAIL="librdkafka packaging <rdkafka@edenhill.se>"
git config user.email "rdkafka@edenhill.se"
git config user.name "librdkafka packaging"

DEB_BRANCH=origin/confluent-debian
TMP_BRANCH=tmp-debian
git checkout -b $TMP_BRANCH $LRK_BRANCH
git merge --no-edit $DEB_BRANCH

dch --newversion ${VERSION/-/\~}-1 "Release version $VERSION" --urgency low && dch --release --distribution unstable ""

git commit -a -m "Tag Debian release $VERSION."

make archive
mkdir -p ../tarballs || true
mv librdkafka-${VERSION}.tar.gz ../tarballs/librdkafka_${VERSION}.orig.tar.gz

gbp buildpackage -us -uc --git-debian-branch=$TMP_BRANCH \
    --git-upstream-tree=$LRK_BRANCH \
    --git-verbose \
    --git-builder="debuild --set-envvar=VERSION=$VERSION --set-envvar=SKIP_TESTS=y -i -I"


popd # librdkafka

popd # $BUILD_DIR

