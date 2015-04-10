#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xbee.h>

#define TEST_DURATION 10

volatile int rx_bytes = 0;

unsigned char payload[100];

void cb(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	xbee_connTx(con, NULL, payload, sizeof(payload));
}

void counter_cb(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	if (pkt) rx_bytes += (*pkt)->dataLen;
	xbee_conTx(con, NULL, "v");
	printf("\r%d", rx_bytes);
	fflush(stdout);
}

struct xbee_con *setup_xbee(const char *tty, struct xbee_conAddress *addr) {
	struct xbee *xbee;
	struct xbee_con *con;
	xbee_err ret;

	if ((ret = xbee_setup(&xbee, "xbee1", tty, 57600)) != XBEE_ENONE) {
		printf("ret: %d (%s)\n", ret, xbee_errorToStr(ret));
		return NULL;
	}
	
	if ((ret = xbee_conNew(xbee, &con, "64-bit Data", addr)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conNew() returned: %d (%s)", ret, xbee_errorToStr(ret));
		return NULL;
	}

	if ((ret = xbee_conDataSet(con, xbee, NULL)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conDataSet() returned: %d", ret);
		return NULL;
	}

	return con;
}

int main(int argc, char *argv[]) {
	struct xbee_con *con1, *con2;
	struct xbee_conAddress address;
	xbee_err ret;
	int i;
	int tot_rx_bytes;
	void *p;

	memset(&address, 0, sizeof(address));
	address.addr64_enabled = 1;
	address.addr64[0] = 0x00;
	address.addr64[1] = 0x13;
	address.addr64[2] = 0xA2;
	address.addr64[3] = 0x00;
	address.addr64[4] = 0x40;
	address.addr64[5] = 0x08;
	address.addr64[6] = 0x18;
	address.addr64[7] = 0x26;
	if ((con1 = setup_xbee("/dev/ttyUSB0", &address)) == NULL) {
		fprintf(stderr, "setup_xbee() failed...\n");
		return 1;
	}

	memset(&address, 0, sizeof(address));
	address.addr64_enabled = 1;
	address.addr64[0] = 0x00;
	address.addr64[1] = 0x13;
	address.addr64[2] = 0xA2;
	address.addr64[3] = 0x00;
	address.addr64[4] = 0x40;
	address.addr64[5] = 0x4B;
	address.addr64[6] = 0x75;
	address.addr64[7] = 0xDE;
	if ((con2 = setup_xbee("/dev/ttyUSB2", &address)) == NULL) {
		fprintf(stderr, "setup_xbee() failed...\n");
		return 1;
	}

	if ((ret = xbee_conCallbackSet(con1, cb, NULL)) != XBEE_ENONE) {
		fprintf(stderr, "xbee_conCallbackSet() returned: %d", ret);
		return ret;
	}
	if ((ret = xbee_conCallbackSet(con2, counter_cb, NULL)) != XBEE_ENONE) {
		fprintf(stderr, "xbee_conCallbackSet() returned: %d", ret);
		return ret;
	}

	for (i = 0; i < sizeof(payload); i++) {
		payload[i] = i & 0xFF;
	}

	rx_bytes = 0;

	counter_cb(NULL, con2, NULL, NULL);

	sleep(TEST_DURATION);

	tot_rx_bytes = rx_bytes;
	
	xbee_conDataGet(con1, &p);
	xbee_conEnd(con1);
	xbee_shutdown(p);

	xbee_conDataGet(con2, &p);
	xbee_conEnd(con2);
	xbee_shutdown(p);

	printf("\n");

	sleep(1);

	printf("Total bytes transferred in one direction in %d seconds: %d\n", TEST_DURATION, tot_rx_bytes);
	printf("~%.2f kb/sec\n", ((float)(tot_rx_bytes * 8) / (float)TEST_DURATION) / 1024.0);

	return 0;
}
