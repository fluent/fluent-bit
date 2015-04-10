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

int main(void) {
	void *d;
	struct xbee *xbee;
	struct xbee_con *con;
	struct xbee_pkt *pkt;
	struct xbee_conAddress address;
	unsigned char txRet;
	int i;
	xbee_err ret;

	if ((ret = xbee_setup(&xbee, "xbee2", "/dev/ttyUSB1", 57600)) != XBEE_ENONE) {
		printf("ret: %d (%s)\n", ret, xbee_errorToStr(ret));
		return ret;
	}

	memset(&address, 0, sizeof(address));
	address.addr64_enabled = 1;
	address.addr64[0] = 0x00;
	address.addr64[1] = 0x13;
	address.addr64[2] = 0xA2;
	address.addr64[3] = 0x00;
	address.addr64[4] = 0x40;
	address.addr64[5] = 0x2D;
	address.addr64[6] = 0x60;
	address.addr64[7] = 0x7B;
	if ((ret = xbee_conNew(xbee, &con, "Remote AT", &address)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conNew() returned: %d (%s)", ret, xbee_errorToStr(ret));
		return ret;
	}
	
	for (i = 0; i < 60 * 4; i++) {
		unsigned int value;
		if ((ret = xbee_conTx(con, NULL, "IS")) != XBEE_ENONE) break;
		if ((ret = xbee_conRx(con, &pkt, NULL)) != XBEE_ENONE) break;
		
		if ((ret = xbee_pktDigitalGet(pkt, 3, 0, &value)) != XBEE_ENONE) {
			printf("xbee_pktDigitalGet(channel=3): ret %d\n", ret);
		} else {
			printf("D3: %d\n", value);
		}
		
		xbee_pktFree(pkt);
		usleep(250000);
	}
	if (ret != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conTx() or xbee_conRx() returned: %d", ret);
		return ret;
	}
	
	if ((ret = xbee_conEnd(con)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conEnd() returned: %d", ret);
		return ret;
	}

	xbee_shutdown(xbee);

	return 0;
}
