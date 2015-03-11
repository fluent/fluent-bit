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

/*
	Because it's very hard to predict what port the other end will be using (though it _is_ possible for them to choose)
	this sample will listen for incomming messages from a given IP address. Each port on the remote system will get it's
	own connection.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xbee.h>

void myCB(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	struct xbee_con *newCon = NULL;
	xbee_err ret;
	if ((*pkt)->dataLen > 0) {
		printf("rx: [%s]\n", (*pkt)->data);
	}

	/* just try to create a new connection! this will fail if it already exists */
	if ((ret = xbee_conNew(xbee, &newCon, (*pkt)->conType, &((*pkt)->address))) == XBEE_ENONE) {
		con = newCon;
		if ((ret = xbee_conCallbackSet(con, myCB, NULL)) != XBEE_ENONE) {
			xbee_log(xbee, -1, "xbee_conCallbackSet() returned: %d", ret);
		}
	} else if (ret != XBEE_EEXISTS) {
		xbee_log(xbee, -1, "xbee_conNew() returned: %d (%s)", ret, xbee_errorToStr(ret));
		return;
	}

	/* either respond to the connection that the message came in on, or the one we just made */
	printf("tx: %d\n", xbee_conTx(con, NULL, "Hello\r\n"));
}

int main(void) {
	void *d;
	struct xbee *xbee;
	struct xbee_con *con;
	struct xbee_conAddress address;
	xbee_err ret;

	if ((ret = xbee_setup(&xbee, "xbee6b", "/dev/ttyUSB1", 57600)) != XBEE_ENONE) {
		printf("ret: %d (%s)\n", ret, xbee_errorToStr(ret));
		return ret;
	}

	memset(&address, 0, sizeof(address));
	address.addr64_enabled = 1;
	address.addr64[0] = 192;
	address.addr64[1] = 168;
	address.addr64[2] = 0;
	address.addr64[3] = 251;
	if ((ret = xbee_conNew(xbee, &con, "Data", &address)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conNew() returned: %d (%s)", ret, xbee_errorToStr(ret));
		return ret;
	}

	if ((ret = xbee_conCallbackSet(con, myCB, NULL)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conCallbackSet() returned: %d", ret);
		return ret;
	}

	printf("Waiting for 30 seconds...\n");
	usleep(30000000);

	if ((ret = xbee_conEnd(con)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conEnd() returned: %d", ret);
		return ret;
	}

	xbee_shutdown(xbee);

	return 0;
}
