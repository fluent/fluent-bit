prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=@CMAKE_INSTALL_PREFIX@
libdir=@CMAKE_INSTALL_PREFIX@/@ONIGMO_INSTALL_LIBDIR@
includedir=@ONIGMO_INSTALL_INCLUDEDIR@
datarootdir=@ONIGMO_INSTALL_DATADIR@
datadir=@ONIGMO_INSTALL_DATADIR@

Name: onigmo
Description: Regular expression library
Version: @PACKAGE_VERSION@
Requires:
Libs: -L${libdir} -lonigmo
Cflags: -I${includedir}
