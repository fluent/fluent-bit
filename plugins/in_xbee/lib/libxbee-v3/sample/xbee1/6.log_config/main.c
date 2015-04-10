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
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with libxbee. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xbee.h>

int main(int argc, char *argv[]) {
	struct xbee *xbee;
	xbee_err ret;
	int level;

	if ((ret = xbee_setup(&xbee, "xbee1", "/dev/ttyUSB0", 57600)) != XBEE_ENONE) {
		printf("ret: %d (%s)\n", ret, xbee_errorToStr(ret));
		return ret;
	}

	if ((ret = xbee_logLevelGet(xbee, &level)) != XBEE_ENONE) {
		printf("xbee_logLevelGet() returned: %d\n", ret);
		return ret;
	}
	printf("libxbee log level is currently: %d\n", level);
	printf("\nDon't forget you can set the log level via the environment, for example:\n\tXBEE_LOG_LEVEL=100 %s\n\n", argv[0]);

	xbee_log(xbee, 50, "Test Message 1...");

	printf("setting libxbee log level to: 100\n");
	if ((ret = xbee_logLevelSet(xbee, 100)) != XBEE_ENONE) {
		printf("xbee_logLevelSet() returned: %d\n", ret);
		return ret;
	}

	xbee_log(xbee, 50, "Test Message 2...");

	xbee_shutdown(xbee);

	return 0;
}
