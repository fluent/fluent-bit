#!/bin/bash

. common.sh

url="https://dlcdn.apache.org/kafka/3.0.0/kafka_2.13-3.0.0.tgz"
sha256="a82728166bbccf406009747a25e1fe52dbcb4d575e4a7a8616429b5818cd02d1"

outdir="$1"

[ -z $outdir ] && die "usage: $0 OUTDIR"
[ -d $outdir ] && die "$outdir already exists"

mkdir -p $outdir
cd $outdir
outdir=$(pwd)
cd -
rmdir $outdir
tmpdir=$(mktemp -d)
cd $tmpdir
curl -L $url | tee kafka.tgz | sha256sum -c <(echo "$sha256 -")
tar xf kafka.tgz
mv kafka_* $outdir
rm -rf $tmpdir
find $outdir/config -type f -name '*.properties' | xargs sed -e "s@=/tmp@=$outdir/tmp@" -i 
