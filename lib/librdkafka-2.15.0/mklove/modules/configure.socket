#!/bin/bash
#
# Provides proper compiler flags for socket support, e.g. socket(3).

function checks {

    local src="
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
void foo (void) {
   int s = socket(0, 0, 0);
   close(s);
}"
    if ! mkl_compile_check socket "" cont CC "" "$src"; then
	if mkl_compile_check --ldflags="-lsocket -lnsl" socket_nsl "" fail CC "" "$src"; then
	    mkl_mkvar_append socket_nsl LIBS "-lsocket -lnsl"
	fi
    fi
}
