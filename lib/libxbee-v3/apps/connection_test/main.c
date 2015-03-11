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
	this application can be used to test the reliability of a given connection
	stats including transmissions, failures and a percentage success rate will
	be printed to the terminal

	a 'slow' count indicates that the packet did actually arrive, but after a
	tx status packet who indicated that there would be 'no response'...
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <semaphore.h>

#include <xbee.h>

sem_t sync_sem;
long long rx_counter;
long long tx_counter;
long long slow_counter;

void myCB(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	if ((*pkt)->dataLen < 1) return;
	if ((*pkt)->atCommand[0] == 'N' && (*pkt)->atCommand[1] == 'I') rx_counter++;
	sem_post(&sync_sem);
}

int main(int argc, char *argv[]) {
	xbee_err ret;
	
	struct xbee *xbee;
	struct xbee_conAddress addr;
	struct xbee_con *con;
	
	/* setup libxbee */
	if ((ret = xbee_setup(&xbee, "xbee1", "/dev/ttyUSB0", 57600)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_setup() returned: %d (%s)", ret, xbee_errorToStr(ret));
		exit(1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.addr64_enabled = 1;
	addr.addr64[0] = 0x00;
	addr.addr64[1] = 0x13;
	addr.addr64[2] = 0xA2;
	addr.addr64[3] = 0x00;
	addr.addr64[4] = 0x40;
	addr.addr64[5] = 0x3C;
	addr.addr64[6] = 0xB2;
	addr.addr64[7] = 0x6D;
	//if ((ret = xbee_conNew(xbee, &con, "Remote AT", &addr)) != XBEE_ENONE) {
	if ((ret = xbee_conNew(xbee, &con, "Local AT", NULL)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conNew() returned: %d (%s)", ret, xbee_errorToStr(ret));
		exit(1);
	}
	
	sem_init(&sync_sem, 0, 0);
	rx_counter = 0;
	tx_counter = 0;
	slow_counter = 0;

	if ((ret = xbee_conCallbackSet(con, myCB, NULL)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conNew() returned: %d (%s)", ret, xbee_errorToStr(ret));
		exit(1);
	}

	for (;;) {
		long long t_rx_counter;
		char retVal;
		struct timespec to;
		double succ_rate;
		long long fails;

		succ_rate = rx_counter;
		succ_rate /= tx_counter;
		succ_rate *= 100;

		fails = tx_counter - rx_counter;

		printf("\rtx: %lld   rx: %lld   slow: %lld   fail: %lld   rate: %1.3f%%", tx_counter, rx_counter, slow_counter, fails, succ_rate);
		fflush(stdout);

		tx_counter++;
		t_rx_counter = -1;
		if ((ret = xbee_conTx(con, &retVal, "NI")) != XBEE_ENONE) {
			t_rx_counter = rx_counter;
			printf("\n");
			xbee_log(xbee, -1, "xbee_conTx() returned; %d (%s) - 0x%02X", ret, xbee_errorToStr(ret), retVal);
			/* with XBee1, 0x04 indicates 'no response' - this may need to be changed for other xbee modules */
			if (retVal != 4) continue;
		}

		clock_gettime(CLOCK_REALTIME, &to);
		to.tv_sec += 2;
		if (sem_timedwait(&sync_sem, &to) != 0) continue;

		if (t_rx_counter == -1) continue;

		if (rx_counter != t_rx_counter) {
			slow_counter++;
			xbee_log(xbee, -1, "xbee_conTx() just a slow respose...\n");
		}
	}
	
	return 0;
}
