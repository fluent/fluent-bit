SUBDIRS = src test

DOC_FILES = \
		README.md \
		LICENSE \
		NOTICE \
		msgpack_vc8.vcproj \
		msgpack_vc8.sln \
		msgpack_vc.postbuild.bat

EXTRA_DIST = \
		$(DOC_FILES) CMakeLists.txt test/CMakeLists.txt

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = msgpack.pc

doxygen:
	./preprocess clean
	cd src && $(MAKE) doxygen
	./preprocess

