/*
	libxbee - a C/C++ library to aid the use of Digi's XBee wireless modules
	          running in API mode.

	Copyright (C) 2009 onwards  Attie Grande (attie@attie.co.uk)

	libxbee is free software: you can redistribute it and/or modify it
	under the terms of the GNU Lesser General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	libxbee is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>

#include "internal.h"

#define __XBEE_XSYS_LOAD_C
#if defined(__MACH__) /* ------- */
#include "xsys_darwin.c"
#elif defined(__GNUC__) /* ----- */
#include "xsys_linux.c"
#elif defined(_WIN32) /* ------- */
#include "xsys_win32.c"
#else /* ----------------------- */
#error Unsupported OS
#endif /* ---------------------- */
#undef __XBEE_XSYS_LOAD_C
