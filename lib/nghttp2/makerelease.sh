#!/bin/sh -e

TAG=$1
PREV_TAG=$2

git checkout refs/tags/$TAG
git log --pretty=fuller --date=short refs/tags/$PREV_TAG..HEAD > ChangeLog

git submodule update --init

autoreconf -i
./configure --with-mruby && \
    make dist-bzip2 && make dist-gzip && make dist-xz || echo "error"

rm -f checksums.txt

VERSION=`echo -n $TAG | sed -E 's|^v([0-9]+\.[0-9]+\.[0-9]+)(-DEV)?$|\1|'`
for f in nghttp2-$VERSION.tar.bz2 nghttp2-$VERSION.tar.gz nghttp2-$VERSION.tar.xz; do
    sha256sum $f >> checksums.txt
    gpg --armor --detach-sign $f
done

make distclean
