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

#include <time.h>
#include <semaphore.h>

sem_t sem;

void myCB(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	if ((*pkt)->dataLen == 0) {
		printf("too short...\n");
		return;
	}
	printf("rx: [%s]\n", (*pkt)->data);
	sem_post(&sem);
}

int main(void) {
	void *d;
	struct xbee *xbee;
	struct xbee_con *con;
	unsigned char txRet;
	xbee_err ret;
	int i, o, t;

	sem_init(&sem, 0, 0);

	if ((ret = xbee_setup(&xbee, "xbee1", "/dev/ttyUSB0", 57600)) != XBEE_ENONE) {
		printf("ret: %d (%s)\n", ret, xbee_errorToStr(ret));
		return ret;
	}

	if ((ret = xbee_conNew(xbee, &con, "Local AT", NULL)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conNew() returned: %d (%s)", ret, xbee_errorToStr(ret));
		return ret;
	}

	if ((ret = xbee_conCallbackSet(con, myCB, NULL)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conCallbackSet() returned: %d", ret);
		return ret;
	}
	
	o = 0;
	t = 0;

	for (i = 0; i < 1000; i++) {
		ret = xbee_conTx(con, &txRet, "NI");
		printf("tx: %d\n", ret);
		if (ret) {
			printf("txRet: %d\n", txRet);
			usleep(1000000);
		} else {
			struct timespec to;
			clock_gettime(CLOCK_REALTIME, &to);
			to.tv_sec++;
			if (sem_timedwait(&sem, &to) == 0) {
				o++;
				usleep(10000);
			} else {
				printf("             TIMEOUT!\n");
				usleep(250000);
				t++;
			}
		}
	}

	printf("%d / %d / %d - success/timeout/total - success rate (%2.1f%%) / timeout rate (%2.1f%%)\n",
		o, t, i, (double)((double)o/(double)i)*100.0, (double)((double)t/(double)i)*100.0);
	
	if ((ret = xbee_conEnd(con)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conEnd() returned: %d", ret);
		return ret;
	}

	xbee_shutdown(xbee);

	return 0;
}
