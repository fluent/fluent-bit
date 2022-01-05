FROM arm64v8/amazonlinux:2

COPY --from=multiarch/qemu-user-static:x86_64-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

RUN yum -y update && \
    yum install -y rpm-build curl ca-certificates gcc gcc-c++ cmake make bash \
                   wget unzip systemd-devel wget flex bison \
                   cyrus-sasl-lib cyrus-sasl-devel openssl openss-libs openssl-devel \
                   cmake3

ARG FLB_PREFIX
ARG FLB_VERSION
ARG FLB_SRC

ENV FLB_PREFIX=$FLB_PREFIX
ENV FLB_VERSION=$FLB_VERSION
ENV FLB_SRC=$FLB_SRC

ENV FLB_TARBALL http://github.com/fluent/fluent-bit/archive/$FLB_PREFIX$FLB_VERSION.zip
COPY sources/$FLB_SRC /

WORKDIR /tmp
RUN if [ "x$FLB_SRC" = "x" ] ; then wget -O "/tmp/fluent-bit-${FLB_VERSION}.zip" ${FLB_TARBALL} && unzip "fluent-bit-$FLB_VERSION.zip" ; else tar zxfv "/$FLB_SRC" ; fi

WORKDIR /tmp/fluent-bit-$FLB_VERSION/build/
# Unused
ARG CFLAGS

ARG CMAKE_INSTALL_PREFIX=/opt/td-agent-bit/
ARG CMAKE_INSTALL_SYSCONFDIR=/etc/
ARG FLB_TD=On
ARG FLB_RELEASE=On
ARG FLB_TRACE=On
ARG FLB_SQLDB=On
ARG FLB_HTTP_SERVER=On
ARG FLB_OUT_KAFKA=On
ARG FLB_OUT_PGSQL=On

RUN cmake -DCMAKE_INSTALL_PREFIX=$CMAKE_INSTALL_PREFIX \
          -DCMAKE_INSTALL_SYSCONFDIR=$CMAKE_INSTALL_SYSCONFDIR \
          -DFLB_RELEASE=$FLB_RELEASE \
          -DFLB_TRACE=$FLB_TRACE \
          -DFLB_TD=$FLB_TD \
          -DFLB_SQLDB=$FLB_SQLDB \
          -DFLB_HTTP_SERVER=$FLB_HTTP_SERVER \
          -DFLB_OUT_KAFKA=$FLB_OUT_KAFKA \
          -DFLB_OUT_PGSQL=$FLB_OUT_PGSQL \
          ../

WORKDIR "/tmp/fluent-bit-${FLB_VERSION}/build/"
VOLUME [ "/output" ]
CMD make -j 4 && cpack3 -G RPM && cp *.rpm /output/
