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
#include <ctype.h>
#include <semaphore.h>
#include <errno.h>
#include <time.h>

#include <xbee.h>

sem_t ndComplete;

void nodeCB(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	int i;

	if (strncasecmp((*pkt)->atCommand, "ND", 2)) return;
	if ((*pkt)->dataLen == 0) {
		printf("Scan complete!\n");
		sem_post(&ndComplete);
		return;
	}

	if ((*pkt)->dataLen < 11) {
		printf("Received small packet...\n");
		return;
	}

	/*                     v   v       v   v   v   v      v   v   v   v       */
	printf("Node: %-20s  0x%02X%02X  0x%02X%02X%02X%02X 0x%02X%02X%02X%02X\n",
	       &((*pkt)->data[11]),

	       (*pkt)->data[0],
	       (*pkt)->data[1],

	       (*pkt)->data[2],
	       (*pkt)->data[3],
	       (*pkt)->data[4],
	       (*pkt)->data[5],
	       (*pkt)->data[6],
	       (*pkt)->data[7],
	       (*pkt)->data[8],
	       (*pkt)->data[9]);
}

int main(void) {
	void *d;
	struct xbee *xbee;
	struct xbee_con *con;
	xbee_err ret;
	unsigned char txRet;
	struct timespec to;

	if (sem_init(&ndComplete, 0, 0) != 0) {
		printf("sem_init() returned an error: %d - %s\n", errno, strerror(errno));
		return -1;
	}
	
	if ((ret = xbee_setup(&xbee, "xbee1", "/dev/ttyUSB0", 57600)) != XBEE_ENONE) {
		printf("ret: %d (%s)\n", ret, xbee_errorToStr(ret));
		return ret;
	}

	if ((ret = xbee_conNew(xbee, &con, "Local AT", NULL)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conNew() returned: %d (%s)", ret, xbee_errorToStr(ret));
		return ret;
	}

	if ((ret = xbee_conCallbackSet(con, nodeCB, NULL)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conCallbackSet() returned: %d", ret);
		return ret;
	}

	if ((ret = xbee_conTx(con, &txRet, "ND")) != XBEE_ENONE && ret != XBEE_ETIMEOUT) {
		xbee_log(xbee, -1, "xbee_conTx() returned: %d-%d", ret, txRet);
		return ret;
	}

	printf("ND Sent!... waiting for completion\n");

	clock_gettime(CLOCK_REALTIME, &to);
	to.tv_sec  += 30;
	if (sem_timedwait(&ndComplete, &to) != 0) {
		if (errno == ETIMEDOUT) {
			printf("Timeout while waiting for ND command to complete...\n");
		} else {
			printf("Error calling sem_timedwait()... sleeping for 30 seconds instead\n");
			usleep(30000000);
		}
	}

	if ((ret = xbee_conEnd(con)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conEnd() returned: %d", ret);
		return ret;
	}

	xbee_shutdown(xbee);

	return 0;
}
