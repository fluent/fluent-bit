Format: 3.0 (quilt)
Source: librdkafka
Binary: librdkafka1, librdkafka-dev, librdkafka1-dbg
Architecture: any
Version: 0.9.1-1pre1
Maintainer: Confluent Inc. <cloud-support@confluent.io>
Homepage: https://github.com/confluentinc/librdkafka
Standards-Version: 3.9.6
Vcs-Browser: https://github.com/confluentinc/librdkafka/tree/master
Vcs-Git: git://github.com/confluentinc/librdkafka.git -b master
Build-Depends: debhelper (>= 9), zlib1g-dev, libssl-dev, libsasl2-dev, python3
Package-List:
 librdkafka-dev deb libdevel optional arch=any
 librdkafka1 deb libs optional arch=any
 librdkafka1-dbg deb debug extra arch=any
Original-Maintainer: Faidon Liambotis <paravoid@debian.org>
