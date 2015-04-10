#include <stdio.h>
#include <stdlib.h>
#include <xbee.h>
#include <string.h>

#define PKT_SIZE 94

xbee_err sendPacket(struct xbee *xbee, struct xbee_con *con, int seq, int pktLen, unsigned char *retVal) {
	static unsigned char *x = NULL;
	static int xLen = 0;
	int i;

	if (pktLen + 6 > xLen || x == NULL) {
		void *p;
		if ((p = realloc(x, pktLen + 6)) == NULL) {
			if (x != NULL && xLen > 0) {
				xbee_log(xbee, -10, "failed to (re)allocate x to %d bytes... using %d bytes instead.", pktLen, xLen);
				pktLen = xLen;
			} else {
				return xbee_conTx(con, retVal, "NMEM");
			}
		} else {
			x = p;
			xLen = pktLen + 6;
		}
	}
	x[0] = (seq >> 24) & 0xFF;
	x[1] = (seq >> 16) & 0xFF;
	x[2] = (seq >>  8) & 0xFF;
	x[3] = (seq      ) & 0xFF;
	x[4] = (pktLen >> 8) & 0xFF;
	x[5] = (pktLen     ) & 0xFF;
	for (i = 6; i < pktLen + 6; i++) {
		x[i] = i;
	}

	xbee_log(xbee, -10, "Tx #%d (%d bytes)", seq, xLen);
	return xbee_connTx(con, retVal, x, xLen);
}

/* send back the next seq */
void callback(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	xbee_err ret;
	unsigned char retVal;
	int seq;
	int pktLen;

	ret = XBEE_ENONE;

	if ((*pkt)->dataLen < 4) {
		xbee_log(xbee, -10, "SHRT - short packet...");
	} else if (!strncmp((*pkt)->data, "SHRT", 4)) {
		xbee_log(xbee, -10, "Rx SHRT...");
	} else if (!strncmp((*pkt)->data, "XLEN", 4)) {
		xbee_log(xbee, -10, "Rx XLEN...");
	} else if (!strncmp((*pkt)->data, "DONE", 4)) {
		xbee_log(xbee, -10, "Rx DONE!");
		*data = NULL;
	} else if ((*pkt)->dataLen > 6) {

		seq  = ((*pkt)->data[0] << 24) & 0xFF000000;
		seq |= ((*pkt)->data[1] << 16) & 0xFF0000;
		seq |= ((*pkt)->data[2] <<  8) & 0xFF00;
		seq |= ((*pkt)->data[3]      ) & 0xFF;

		pktLen  = (((*pkt)->data[4]) << 8) & 0xFF00;
		pktLen |= (((*pkt)->data[5])     ) & 0xFF;

		if (pktLen < 6 || pktLen != (*pkt)->dataLen - 6) {
			xbee_log(xbee, -10, "XLEN - packet length mismatch...");
		} else {
			ret = sendPacket(xbee, con, seq + 1, pktLen, &retVal);
		}
	}

	if (ret != XBEE_ENONE) {
		xbee_log(xbee, -1, "ret = %d      retVal = %d", ret, retVal);
	}
}

int main(int argc, char *argv[]) {
	xbee_err ret;
	struct xbee *xbee;

	struct xbee_conAddress addr;
	struct xbee_con *con;

	if ((ret = xbee_setup(&xbee, "xbee1", "/dev/ttyUSB0", 57600)) != XBEE_ENONE) {
		fprintf(stderr, "failed to setup libxbee...\n");
		return 1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.addr64_enabled = 1;
	addr.addr64[0] = 0x00;
	addr.addr64[1] = 0x13;
	addr.addr64[2] = 0xA2;
	addr.addr64[3] = 0x00;
	addr.addr64[4] = 0x40;
	addr.addr64[5] = 0x08;
	addr.addr64[6] = 0x18;
	addr.addr64[7] = 0x26;

	if ((ret = xbee_conNew(xbee, &con, "64-bit Data", &addr)) != XBEE_ENONE) {
		fprintf(stderr, "failed to setup a connection...\n");
		return 2;
	}

	if ((ret = xbee_conDataSet(con, xbee, NULL)) != XBEE_ENONE) {
		fprintf(stderr, "failed to setup connection data...\n");
		return 3;
	}

	if ((ret = xbee_conCallbackSet(con, callback, NULL)) != XBEE_ENONE) {
		fprintf(stderr, "failed to setup connection callback...\n");
		return 4;
	}

	/* trigger it! */
	if ((ret = sendPacket(xbee, con, 0, PKT_SIZE, NULL)) != XBEE_ENONE) {
		fprintf(stderr, "failed triggering the cascade...\n");
		return 5;
	}

	for (;;) {
		void *p;
		if ((ret = xbee_conDataGet(con, &p)) != XBEE_ENONE) {
			fprintf(stderr, "failed to get connection's data...\n");
			return 5;
		}
		if (p == NULL) break;
		usleep(25000);
	}

	xbee_conEnd(con);
	xbee_shutdown(xbee);

	sleep(5);

	fprintf(stderr, "test complete!\n");
	
	return 0;
}
