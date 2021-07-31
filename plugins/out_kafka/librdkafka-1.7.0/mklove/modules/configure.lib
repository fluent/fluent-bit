#!/bin/bash
#
# Module for building shared libraries
# Sets:
#  WITH_GNULD | WITH_OSXLD
#  WITH_LDS  - linker script support
mkl_require pic

function checks {

    mkl_mkvar_append LIB_LDFLAGS LIB_LDFLAGS '-shared'

    # Check what arguments to pass to CC or LD for shared libraries
    mkl_meta_set gnulib name "GNU-compatible linker options"
    mkl_meta_set osxlib name "OSX linker options"

    if mkl_compile_check gnulib WITH_GNULD cont CC \
	"-shared -Wl,-soname,mkltest.0" "" ; then
	# GNU linker
	mkl_mkvar_append LIB_LDFLAGS LIB_LDFLAGS '-Wl,-soname,$(LIBFILENAME)'

    elif mkl_compile_check osxlib WITH_OSXLD cont CC \
	"-dynamiclib -Wl,-install_name,/tmp/mkltest.so.0" ; then
	# OSX linker
        mkl_mkvar_append LIB_LDFLAGS LIB_LDFLAGS '-dynamiclib -Wl,-install_name,$(DESTDIR)$(libdir)/$(LIBFILENAME)'
    fi

    # Check what argument is needed for passing linker script.
    local ldsfile=$(mktemp _mkltmpXXXXXX)
    echo "{
 global:
  *;
};
" > $ldsfile

    mkl_meta_set ldsflagvs name "GNU linker-script ld flag"
    mkl_meta_set ldsflagm name "Solaris linker-script ld flag"
    if mkl_compile_check ldsflagvs "" cont CC \
	"-shared -Wl,--version-script=$ldsfile"; then
	mkl_mkvar_set ldsflagvs LDFLAG_LINKERSCRIPT "-Wl,--version-script="
	mkl_mkvar_set lib_lds WITH_LDS y
    elif mkl_compile_check ldsflagm ""  ignore CC \
	"-shared -Wl,-M$ldsfile"; then
	mkl_mkvar_set ldsflagm LDFLAG_LINKERSCRIPT "-Wl,-M"
	mkl_mkvar_set lib_lds WITH_LDS y
    fi

    rm -f "$ldsfile"
}
