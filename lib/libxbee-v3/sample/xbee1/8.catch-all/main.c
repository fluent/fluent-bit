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

void specificCB(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	if ((*pkt)->dataLen > 0) {
		if ((*pkt)->data[0] == '@') {
			xbee_conCallbackSet(con, NULL, NULL);
			printf("*** DISABLED CALLBACK... ***\n");
		}
		printf("rx: [%s]\n", (*pkt)->data);
	}
	printf("tx: %d\n", xbee_conTx(con, NULL, "Hello\r\n"));
}

void catchallCB(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	xbee_err ret;
	struct xbee_con *newCon;
	
	printf("Got packet from new node!\n");
	if ((*pkt)->address.addr16_enabled) {
		printf("    16-bit (0x%02X%02X)\n", (*pkt)->address.addr16[0], (*pkt)->address.addr16[1]);
	}
	if ((*pkt)->address.addr64_enabled) {
		printf("    64-bit (0x%02X%02X%02X%02X 0x%02X%02X%02X%02X)\n", (*pkt)->address.addr64[0], (*pkt)->address.addr64[1],
		                                                               (*pkt)->address.addr64[2], (*pkt)->address.addr64[3],
		                                                               (*pkt)->address.addr64[4], (*pkt)->address.addr64[5],
		                                                               (*pkt)->address.addr64[6], (*pkt)->address.addr64[7]);
	}
	if ((*pkt)->address.endpoints_enabled) {
		printf("    Endpoints (local: 0x%02X, remote: 0x%02X)\n", (*pkt)->address.endpoint_local,
		                                                          (*pkt)->address.endpoint_remote);
	}
	
	/* you should really hold on to the returned newCon somehow, but for the sample it is just let loose! */
	if ((ret = xbee_conNew(xbee, &newCon, (*pkt)->conType, &(*pkt)->address)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conNew() returned: %d (%s)", ret, xbee_errorToStr(ret));
		return;
	}

	if ((ret = xbee_conCallbackSet(newCon, specificCB, NULL)) != XBEE_ENONE) {
		xbee_conEnd(newCon);
		xbee_log(xbee, -1, "xbee_conCallbackSet() returned: %d", ret);
		return;
	}
	
	specificCB(xbee, newCon, pkt, data);
}

int main(void) {
	void *d;
	struct xbee *xbee;
	struct xbee_con *con;
	struct xbee_conAddress address;
	struct xbee_conSettings settings;
	xbee_err ret;

	if ((ret = xbee_setup(&xbee, "xbee1", "/dev/ttyUSB0", 57600)) != XBEE_ENONE) {
		printf("ret: %d (%s)\n", ret, xbee_errorToStr(ret));
		return ret;
	}

	memset(&address, 0, sizeof(address));
	address.addr64_enabled = 1;
	address.addr64[0] = 0x00;
	address.addr64[1] = 0x00;
	address.addr64[2] = 0x00;
	address.addr64[3] = 0x00;
	address.addr64[4] = 0x00;
	address.addr64[5] = 0x00;
	address.addr64[6] = 0xFF;
	address.addr64[7] = 0xFF;
	if ((ret = xbee_conNew(xbee, &con, "64-bit Data", &address)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conNew() returned: %d (%s)", ret, xbee_errorToStr(ret));
		return ret;
	}

	xbee_conSettings(con, NULL, &settings);
	settings.catchAll = 1;
	xbee_conSettings(con, &settings, NULL);

	if ((ret = xbee_conCallbackSet(con, catchallCB, NULL)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conCallbackSet() returned: %d", ret);
		return ret;
	}

	printf("Ready!... waiting for 30 secs\n");
	
	usleep(30000000);

	if ((ret = xbee_conEnd(con)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conEnd() returned: %d", ret);
		return ret;
	}

	xbee_shutdown(xbee);

	return 0;
}
