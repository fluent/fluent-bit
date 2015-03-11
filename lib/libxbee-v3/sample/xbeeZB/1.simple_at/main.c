/*
	libxbee - a C library to aid the use of Digi's XBee wireless modules
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
	This sample has been designed to give you a very basic introduction to
	libxbee. The sample will start libxbee, create a connection to the local
	XBee module, and then request its Node Identifier before shutting down.

	For this example, your XBee should be configured with AO=0
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xbee.h>

/* this is the callback function...
   it will be executed once for each packet that is recieved on an associated connection */
void myCB(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	if ((*pkt)->dataLen == 0) {
		printf("too short...\n");
		return;
	}
	printf("rx: [%s]\n", ((*pkt)->data));
}

int main(void) {
	void *d;
	struct xbee *xbee;
	struct xbee_con *con;
	unsigned char txRet;
	xbee_err ret;

	/* setup libxbee, using the USB to Serial adapter '/dev/ttyUSB0' at 57600 baud */
	if ((ret = xbee_setup(&xbee, "xbeeZB", "/dev/ttyUSB1", 57600)) != XBEE_ENONE) {
		printf("ret: %d (%s)\n", ret, xbee_errorToStr(ret));
		return ret;
	}

	/* create a new AT connection to the local XBee */
	if ((ret = xbee_conNew(xbee, &con, "Local AT", NULL)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conNew() returned: %d (%s)", ret, xbee_errorToStr(ret));
		return ret;
	}

	/* configure a callback for the connection
	   this function is called every time a packet for this connection is recieved */
	if ((ret = xbee_conCallbackSet(con, myCB, NULL)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conCallbackSet() returned: %d", ret);
		return ret;
	}

	/* send the AT command 'NI' (request the Node Identifier)
	   when the response is recieved, the packet will be directed to the callback function */
	ret = xbee_conTx(con, &txRet, "NI");
	/* print out the return value
	   if this is non-zero, then check 'enum xbee_errors' in xbee.h for its meaning
	   alternatively look at the xbee_errorToStr() function */
	printf("tx: %d\n", ret);
	if (ret) {
		/* if ret was non-zero, then some error occured
		   if ret == XBEE_ETX then it is possible that txRet is now -17 / XBEE_ETIMEOUT
		   alternatively, txRet will contain the status code returned by the XBee */
		printf("txRet: %d\n", txRet);
	} else {
		/* give the callback a chance to run */
		usleep(1000000);
	}

	/* shutdown the connection */
	if ((ret = xbee_conEnd(con)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conEnd() returned: %d", ret);
		return ret;
	}

	/* shutdown libxbee */
	xbee_shutdown(xbee);

	return 0;
}
