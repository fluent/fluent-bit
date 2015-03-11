#include <stdio.h>
#include <stdlib.h>
#include <xbee.h>
#include <string.h>

#define PACKET_COUNT 10000

/* just echo it back */
void callback(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	xbee_err ret;
	unsigned char retVal;
	int seq;
	int pktLen;

	if ((*pkt)->dataLen < 6) {
		xbee_log(xbee, -10, "SHRT - short packet...");
		ret = xbee_conTx(con, &retVal, "SHRT");
	} else {

		seq  = ((*pkt)->data[0] << 24) & 0xFF000000;
		seq |= ((*pkt)->data[1] << 16) & 0xFF0000;
		seq |= ((*pkt)->data[2] <<  8) & 0xFF00;
		seq |= ((*pkt)->data[3]      ) & 0xFF;

		pktLen  = (((*pkt)->data[4]) << 8) & 0xFF00;
		pktLen |= (((*pkt)->data[5])     ) & 0xFF;

		if (pktLen < 6 || pktLen != (*pkt)->dataLen - 6) {
			xbee_log(xbee, -10, "XLEN - packet length mismatch... (rx'd %d / expected %d bytes)", (*pkt)->dataLen - 6, pktLen);
			ret = xbee_conTx(con, &retVal, "XLEN");
		} else if (seq >= PACKET_COUNT) {
			xbee_log(xbee, -10, "DONE - test complete!");
			ret = xbee_conTx(con, &retVal, "DONE");
			*data = NULL;
		} else {
			xbee_log(xbee, -10, "Tx #%d", seq);
			ret = xbee_connTx(con, &retVal, (*pkt)->data, (*pkt)->dataLen);
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

  if ((ret = xbee_setup(&xbee, "xbee1", "/dev/ttyUSB1", 57600)) != XBEE_ENONE) {
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
	addr.addr64[5] = 0x4B;
	addr.addr64[6] = 0x75;
	addr.addr64[7] = 0xDE;

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

