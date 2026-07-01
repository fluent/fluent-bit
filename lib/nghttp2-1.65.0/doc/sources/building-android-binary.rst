Building Android binary
=======================

In this article, we briefly describe how to build Android binary using
`Android NDK <https://developer.android.com/ndk>`_ cross-compiler on
Debian Linux.

The easiest way to build android binary is use Dockerfile.android.
See Dockerfile.android for more details.  If you cannot use
Dockerfile.android for whatever reason, continue to read the rest of
this article.

We offer ``android-config`` script to make the build easier.  To make
the script work, NDK directory must be set to ``NDK`` environment
variable.  NDK directory is the directory where NDK is unpacked:

.. code-block:: text

    $ unzip android-ndk-$NDK_VERSION-linux.zip
    $ cd android-ndk-$NDK_VERSION
    $ export NDK=$PWD

The dependent libraries, such as OpenSSL, libev, and c-ares should be
built with the same NDK toolchain and installed under
``$NDK/usr/local``.  We recommend to build these libraries as static
library to make the deployment easier.  libxml2 support is currently
disabled.

Although zlib comes with Android NDK, it seems not to be a part of
public API, so we have to built it for our own.  That also provides us
proper .pc file as a bonus.

Before running ``android-config``, ``NDK`` environment variable must
be set to point to the correct path.

You need to set ``NGHTTP2`` environment variable to the absolute path
to the source directory of nghttp2.

To configure OpenSSL, use the following script:

.. code-block:: sh

    #!/bin/sh

    . $NGHTTP2/android-env

    export ANDROID_NDK_HOME=$NDK
    export PATH=$TOOLCHAIN/bin:$PATH

    ./Configure no-shared --prefix=$PREFIX android-arm64

And run the following script to build and install without
documentation:

.. code-block:: sh

    #!/bin/sh

    . $NGHTTP2/android-env

    export PATH=$TOOLCHAIN/bin:$PATH

    make install_sw

To configure libev, use the following script:

.. code-block:: sh

    #!/bin/sh

    . $NGHTTP2/android-env

    ./configure \
        --host=$TARGET \
        --build=`dpkg-architecture -qDEB_BUILD_GNU_TYPE` \
        --prefix=$PREFIX \
        --disable-shared \
        --enable-static \
        CPPFLAGS=-I$PREFIX/include \
        LDFLAGS=-L$PREFIX/lib

And run ``make install`` to build and install.

To configure c-ares, use the following script:

.. code-block:: sh

    #!/bin/sh -e

    . $NGHTTP2/android-env

    ./configure \
        --host=$TARGET \
        --build=`dpkg-architecture -qDEB_BUILD_GNU_TYPE` \
        --prefix=$PREFIX \
        --disable-shared

And run ``make install`` to build and install.

To configure zlib, use the following script:

.. code-block:: sh

    #!/bin/sh -e

    . $NGHTTP2/android-env

    export HOST=$TARGET

    ./configure \
        --prefix=$PREFIX \
        --libdir=$PREFIX/lib \
        --includedir=$PREFIX/include \
        --static

And run ``make install`` to build and install.

After prerequisite libraries are prepared, run ``android-config`` and
then ``make`` to compile nghttp2 source files.

If all went well, application binaries, such as nghttpx, are created
under src directory.  Strip debugging information from the binary
using the following command:

.. code-block:: text

    $ $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip src/nghttpx
