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
	this application will create a pseudo terminal so that you may talk
	directly to a device connected to a remote XBee
	
	this application has been used to successfully program an arduino over
	an XBee link, using both direct mode ('xbee1') and network client mode.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <linux/limits.h>

#include <xbee.h>

/* ########################################################################## */

#define MAX_RETRIES 10
//#define INVERT_RESET

#ifndef INVERT_RESET
#  define RESET_STEP1 0x04
#  define RESET_STEP2 0x05
#else
#  define RESET_STEP1 0x05
#  define RESET_STEP2 0x04
#endif

/* ########################################################################## */

struct remoteInfo {
	struct xbee_con *conAT, *conData;
	int ptfd;
	char ptn[PATH_MAX];
};

/* ########################################################################## */

void usage(char *argv0) {
	printf("usage:\n"
	       "  %s <nodeIdentifier>\n"
				 "  %s 0x<16bitAddress>\n"
				 "  %s 0x<64bitAddress>\n",
				 argv0, argv0, argv0);
	exit(1);
}

void xbee_error(xbee_err err) {
	printf("xbee_setup(): %d - %s\n", err, xbee_errorToStr(err));
	exit(1);
}

/* ########################################################################## */

int parseAddress(int argc, char *argv[], struct xbee *xbee, struct remoteInfo *info) {
	xbee_err ret;
	
	info->conAT = NULL;
	info->conData = NULL;
	
	if (!strncasecmp(argv[1], "0x", 2)) {
		long long rawAddr;
		struct xbee_conAddress addr;
		int items;
		memset(&addr, 0, sizeof(addr));
		if (sscanf(&(argv[1][2]), "%llx", &rawAddr) != 1) {
			fprintf(stderr, "error parsing address...\n");
			usage(argv[0]);
			exit(1);
		}
		if (rawAddr < 0xFFFF) {
			printf("16-bit address: 0x%04X\n", (short)rawAddr);
			addr.addr16_enabled = 1;
			addr.addr16[0] = (rawAddr >> 8) & 0xFF;
			addr.addr16[1] = rawAddr & 0xFF;
			if ((ret = xbee_conNew(xbee, &info->conAT, "Remote AT", &addr)) != XBEE_ENONE) {
				xbee_error(ret);
				exit(1);
			}
			if ((ret = xbee_conNew(xbee, &info->conData, "16-bit Data", &addr)) != XBEE_ENONE) {
				xbee_error(ret);
				exit(1);
			}
		} else if (rawAddr == 0xFFFF) {
			fprintf(stderr, "you may not use a broadcast address...\n");
			exit(1);
		} else {
			printf("64-bit address: 0x%016llX\n", rawAddr);
			addr.addr64_enabled = 1;
			addr.addr64[0] = (rawAddr >> 56) & 0xFF;
			addr.addr64[1] = (rawAddr >> 48) & 0xFF;
			addr.addr64[2] = (rawAddr >> 40) & 0xFF;
			addr.addr64[3] = (rawAddr >> 32) & 0xFF;
			addr.addr64[4] = (rawAddr >> 24) & 0xFF;
			addr.addr64[5] = (rawAddr >> 16) & 0xFF;
			addr.addr64[6] = (rawAddr >> 8) & 0xFF;
			addr.addr64[7] = rawAddr & 0xFF;
			if ((ret = xbee_conNew(xbee, &info->conAT, "Remote AT", &addr)) != XBEE_ENONE) {
				xbee_error(ret);
				exit(1);
			}
			if ((ret = xbee_conNew(xbee, &info->conData, "64-bit Data", &addr)) != XBEE_ENONE) {
				xbee_error(ret);
				exit(1);
			}
		}
	} else {
		char *NI;
		NI = argv[1];
		printf("ni: %s\n", NI);
		fprintf(stderr, "this functionality is not yet supported...\n");
		usage(argv[0]);
		exit(1);
	}
	
	if (info->conData) {
		xbee_conDataSet(info->conData, info, NULL);
	}
	
	return 0;
}

/* ########################################################################## */

void openPt(struct remoteInfo *remote) {
	int ptfd2;

	/* create/open a Pseudo Terminal */
	if ((remote->ptfd = posix_openpt(O_RDWR | O_NOCTTY)) == -1) {
		perror("posix_openpt()");
		exit(1);
	}
	if (grantpt(remote->ptfd)) {
		perror("grantpt()");
		exit(1);
	}
	if (unlockpt(remote->ptfd)) {
		perror("unlockpt()");
		exit(1);
	}

	if (ptsname_r(remote->ptfd, remote->ptn, sizeof(remote->ptn)) != 0) {
		perror("ptsname_r()");
		exit(1);
	}
	
	/* unblock it... by opening and closing it */
	if ((ptfd2 = open(remote->ptn, O_RDWR)) == -1) {
		perror("open(ptfd)");
		exit(1);
	}
	close(ptfd2);
}

/* ########################################################################## */

int getSx(struct xbee_con *con, char *command, int *addr) {
	xbee_err ret;
	struct xbee_pkt *pkt;
	
	if ((ret = xbee_conTx(con, NULL, command)) != XBEE_ENONE) {
		printf("xbee_conTx(\"%s\"): failed %d\n", command, ret);
		return 1;
	}
	if ((ret = xbee_conRx(con, &pkt, NULL)) != XBEE_ENONE) {
		printf("xbee_conRx() - \"%s\": failed %d\n", command, ret);
		return 2;
	}
	if (strncasecmp(command, pkt->atCommand, 2) || pkt->dataLen != 4) {
		printf("AT command \"%s\" returned invalid data...\n", command);
		xbee_pktFree(pkt);
		return 3;
	}
	*addr  = (pkt->data[0] << 24) & 0xFF000000;
	*addr |= (pkt->data[1] << 16) & 0xFF0000;
	*addr |= (pkt->data[2] << 8 ) & 0xFF00;
	*addr |= (pkt->data[3]      ) & 0xFF;
	xbee_pktFree(pkt);
}

int setDx(struct xbee_con *con, char *command, int *addr) {
	xbee_err ret;
	
	if ((ret = xbee_conTx(con, NULL, "%s%c%c%c%c", command, (*addr >> 24) & 0xFF,
	                                                  (*addr >> 16) & 0xFF,
	                                                  (*addr >> 8 ) & 0xFF,
	                                                  (*addr      ) & 0xFF)) != XBEE_ENONE) {
		printf("xbee_conTx(\"%s\"): failed %d\n", command, ret);
		return 1;
	}
}

int configureRemoteXBee(struct xbee_con *conLAT, struct xbee_con *conAT) {
	int myAddrH, myAddrL;
	xbee_err ret;
	
	/* get my address */
	if (getSx(conLAT, "SH", &myAddrH) != 0) return 1;
	if (getSx(conLAT, "SL", &myAddrL) != 0) return 1;
	
	/* set their address */
	if (setDx(conAT,  "DH", &myAddrH) != 0) return 2;
	if (setDx(conAT,  "DL", &myAddrL) != 0) return 2;
	
	/* turn off API mode at their end */
	if ((ret = xbee_conTx(conAT, NULL, "AP%c", 0)) != XBEE_ENONE) return 3;
	
	return 0;
}

/* ########################################################################## */

void relayCallback(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	int t;
	int written;
	struct remoteInfo *remote = *data;
	
	for (written = 0; written < (*pkt)->dataLen; written += t) {
		if ((t = write(remote->ptfd, &((*pkt)->data[written]), (*pkt)->dataLen - written)) == -1) {
			perror("write()");
			exit(1);
		}
	}
}

/* ########################################################################## */

int main(int argc, char *argv[]) {
	xbee_err ret;
	
	struct xbee *xbee;
	struct xbee_con *conLAT;
	struct remoteInfo remote;
	
	/* check that we have details on the remote XBee */
	if (argc != 2) {
		usage(argv[0]);
		exit(1);
	}
	
	/* get a Pseudo Terminal */
	openPt(&remote);
	
	/* setup libxbee */
	if ((ret = xbee_setup(&xbee, "xbee1", "/dev/ttyUSB0", 57600)) != XBEE_ENONE) {
	/* or you can use the network! */
	//if ((ret = xbee_setup(&xbee, "net", "127.0.0.1", 27015)) != XBEE_ENONE) {
		xbee_error(ret);
		exit(1);
	}
	
	/* get the remote connections */
	remote.conAT = remote.conData = NULL;
	if (parseAddress(argc, argv, xbee, &remote)) exit(1);
	if (!remote.conAT || !remote.conData) {
		fprintf(stderr, "the connection wasn't initialized...\n");
		exit(1);
	}
	
	/* get the local connection (used to configure the remote XBee) */
	if ((ret = xbee_conNew(xbee, &conLAT, "Local AT", NULL)) != XBEE_ENONE) {
		xbee_error(ret);
		exit(1);
	}
	
	/* configure the remote XBee to talk with us! */
	if (configureRemoteXBee(conLAT, remote.conAT)) exit(1);
	
	/* we are now done with the Local AT connection */
	xbee_conEnd(conLAT);
	
	for (;;) {
		int i;
		unsigned char buf[64];
		
		for (;;) {
			int fl;
			int bufLen;
			int bufGot;
			
			printf("- PT closed! - please use '%s'\n", remote.ptn);
			
			/* disable blocking */
			if ((fl = fcntl(remote.ptfd, F_GETFL)) == -1) {
				perror("fcntl(F_GETFL)");
				exit(1);
			}
			if (fcntl(remote.ptfd, F_SETFL, fl | O_NONBLOCK) == -1) {
				perror("fcntl(F_SETFL, O_NONBLOCK)");
				exit(1);
			}
			
			/* wait for data */
			while ((bufLen = read(remote.ptfd, buf, sizeof(buf))) == -1) {
				if (errno == EAGAIN) {
					break;
				}
				if (errno != EIO) {
					perror("read()");
					exit(1);
				}
				usleep(50000);
			}
			
			/* enable blocking */
			if (fcntl(remote.ptfd, F_SETFL, fl) == -1) {
				perror("fcntl(F_SETFL, !O_NONBLOCK)");
				exit(1);
			}
			
			printf("# PT opened!\n");
			
			/* flick the reset line */
			if (xbee_conTx(remote.conAT, NULL, "D3%c", RESET_STEP1) != XBEE_ENONE) {
				printf("failed to send reset...\n");
			} else {
				usleep(5000);
				if (xbee_conTx(remote.conAT, NULL, "D3%c", RESET_STEP2) != XBEE_ENONE) {
					printf("failed to complete reset...\n");
				}
			}
			
			/* relay information! */
			xbee_conPurge(remote.conData);
			xbee_conCallbackSet(remote.conData, relayCallback, NULL);
			bufLen = 0;
			while (bufLen > 0 || (bufLen = read(remote.ptfd, buf, sizeof(buf))) > 0) {
				unsigned char txRet;
				int retries = MAX_RETRIES;
				while (retries--) {
					if (xbee_connTx(remote.conData, &txRet, buf, bufLen) == XBEE_ENONE) break;
				}
				if (!retries) {
					printf("data lost! (tx: %d bytes)\n", bufLen);
				}
				bufLen = 0;
			}
			xbee_conCallbackSet(remote.conData, NULL, NULL);
		}
	}
	
	return 0;
}
