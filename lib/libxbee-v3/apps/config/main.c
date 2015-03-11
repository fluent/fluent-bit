#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include <xbee.h>

const char * const skip[] = {"AC", "AI", "AS", "CA", "CK", "CN", "DA", "DB", "DN", "EA",
                             "EC", "ED", "FP", "FR", "HV", "IS", "ND", "RE", "SH", "SL",
                             "VL", "VR", "WR"};
const char achars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char bchars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/* ########################################################################## */

void usage(char *argv0) {
	fprintf(stderr, "usage:\n"
	                "  --save, -s              - save the config (from XBee)\n"
	                "  --load, -l              - load the config (to XBee)\n"
                  "  --file, -f [filename]   - use the file (else stdin/stdout)\n"
                  "  --write, -w             - write the changes (ATWR) after load\n"
	                "e.g:\n"
                  "  %s -sf ./myxbee.cfg\n"
                  "  %s -lwf ./myxbee.cfg\n",
                  argv0, argv0);
  exit(1);
}

/* ########################################################################## */

void config_save(FILE *f, struct xbee_con *con) {
	int a,b,s,l,q;
	int i;
	
	xbee_err ret;
	unsigned char retVal;
	struct xbee_pkt *pkt;
	unsigned char cmd[3];
	
	l = sizeof(skip) / sizeof(*skip);
	fprintf(stderr, "Skipping %d special commands:", l);
	for (i = 0; i < l; i++) {
		if (!(i % 10)) fprintf(stderr,"\n  ");
		fprintf(stderr, "%s%s", (i % 10 ? ", " : ""), skip[i]);
	}
	fprintf(stderr, "\n");
	
	i = 0;
	for (a = 0; achars[a]; a++) {
		for (b = 0; bchars[b]; b++) {
			for (s = 0; s < l; s++) {
				if (!skip[s]) continue;
				if (skip[s][0] == '\0') continue;
				if (skip[s][1] == '\0') continue;
				if (achars[a] == skip[s][0] && bchars[b] == skip[s][1]) break;
			}
			if (s != l) continue;
			if ((ret = xbee_conPurge(con)) != XBEE_ENONE) {
				fprintf(stderr, "xbee_conPurge(): %d - %s\n", ret, xbee_errorToStr(ret));
				exit(1);
			}
			cmd[0] = achars[a];
			cmd[1] = bchars[b];
			cmd[2] = '\0';
			if ((ret = xbee_conTx(con, &retVal, "%c%c", achars[a], bchars[b])) != XBEE_ENONE && ret != XBEE_ETX) {
				fprintf(stderr, "xbee_conTx(): %d - %s\n", ret, xbee_errorToStr(ret));
				exit(1);
			}
			if (retVal != 0) continue;
			if ((ret = xbee_conRx(con, &pkt, NULL)) != XBEE_ENONE) {
				fprintf(stderr, "xbee_conRx(): %d - %s\n", ret, xbee_errorToStr(ret));
				exit(1);
			}
			if (pkt->status != 0) {
				fprintf(stderr, "xbee_conRx(): AT command returned error - %d\n", pkt->status);
				exit(1);
			}
			if (strncasecmp(pkt->atCommand, cmd, 2)) {
				fprintf(stderr, "xbee_conRx(): AT command response mis-match\n");
				exit(1);
			}
			if (pkt->dataLen > 0) {
				fprintf(stderr, "\r%c%c...", achars[a], bchars[b]);
				fflush(stderr);
				fprintf(f, "%c%c =", achars[a], bchars[b]);
				for (q = 0; q < pkt->dataLen; q++) {
					fprintf(f, " 0x%02X", pkt->data[q]);
				}
				fprintf(f, "\n");
				i++;
			}
			xbee_pktFree(pkt);
		}
	}
	
	printf("\rTotal: %d\n", i);
}

void config_load(FILE *f, struct xbee_con *con, int write) {
	char *buf;
	int bufLen;
	char *p, *q;
	int a, b;
	unsigned char val;
	
	xbee_err ret;
	struct xbee_pkt *pkt;
	unsigned char retVal;
	struct xbee_conSettings settings;
	
	if (xbee_conSettings(con, NULL, &settings) != XBEE_ENONE) return;
	settings.queueChanges = 1;
	if (xbee_conSettings(con, &settings, NULL) != XBEE_ENONE) return;
	
	buf = NULL;
	bufLen = 0;
	
	while (!feof(f)) {
		if (getline(&buf, &bufLen, f) == -1) {
			if (feof(f)) break;
			fprintf(stderr, "\ngetline(): unknown error...\n");
			exit(1);
		}
		
		if (buf[0] == '#') continue;
		
		for (a = 0; achars[a]; a++) {
			if (achars[a] == buf[0]) break;
		}
		if (!achars[a]) goto skip;
		
		for (b = 0; bchars[b]; b++) {
			if (bchars[b] == buf[1]) break;
		}
		if (!bchars[b]) goto skip;
		
		p = &(buf[2]);
		q = strchr(p, '=');
		*q = '\0';
		q++;
		
		while (*q != '\0' && *q != '\n') {
			while (*q == ' ') { q++; }
			if (sscanf(q, "0x%02hhX", &val) != 1) {
				fprintf(stderr, "\nInvalid parameters for %c%c\n", buf[0], buf[1]);
				exit(1);
			}
			q += 4;
			*p = val;
			if (p != &(buf[2]) || val != 0) p++;
		}
		if (p == &(buf[2])) p++;
		
		fprintf(stderr, "\r%c%c...", buf[0], buf[1]);
		fflush(stderr);
		if ((ret = xbee_conPurge(con)) != XBEE_ENONE) {
			fprintf(stderr, "\nxbee_conPurge(): %d - %s\n", ret, xbee_errorToStr(ret));
			exit(1);
		}
		if ((ret = xbee_connTx(con, &retVal, buf, p - buf + 1)) != XBEE_ENONE && ret != XBEE_ETX) {
			fprintf(stderr, "\nxbee_conTx(): %d - %s\n", ret, xbee_errorToStr(ret));
			exit(1);
		}
		if (retVal != 0) {
			fprintf(stderr, "\nError sending command: %c%c - %hhd\n", buf[0], buf[1], retVal);
			//exit(1);
		}
		continue;
		
skip:
		fprintf(stderr, "\nSkipping invalid command: %c%c\n", buf[0], buf[1]);
	}
	
	if (buf) free(buf);
	
	if (xbee_conSettings(con, NULL, &settings) != XBEE_ENONE) return;
	settings.queueChanges = 0;
	if (xbee_conSettings(con, &settings, NULL) != XBEE_ENONE) return;
	
	xbee_conTx(con, NULL, "AC");
	if (write) xbee_conTx(con, NULL, "WR");
}

/* ########################################################################## */

int main(int argc, char *argv[]) {
	int mode = -1;
	char *filename = NULL;
	FILE *f = NULL;
	int write = 0;
	
	xbee_err ret;
	struct xbee *xbee;
	struct xbee_con *con;
	
	int i;
	char *t;
	
	for (i = 1; i < argc; i++) {
		
		if (argv[i][0] == '-' && argv[i][1] == '-') {
			t = &(argv[i][2]);
			if (!strcmp(t, "save")) {
				mode = 1;
			} else if (!strcmp(t, "load")) {
				mode = 2;
			} else if (!strcmp(t, "write")) {
				write = 1;
			} else if (!strcmp(t, "file")) {
				if (++i >= argc) usage(argv[0]);
				filename = argv[i];
			}
			continue;
		}
		if (argv[i][0] == '-') {
			int o;
			for (o = 1; o >= 0 && argv[i][o]; o++) {
				switch (argv[i][o]) {
					case 's': mode = 1;  break;
					case 'l': mode = 2;  break;
					case 'w': write = 1; break;
          case 'f':
						if (argv[i][o+1] != '\0') usage(argv[0]);
						if (++i >= argc) usage(argv[0]);
						filename = argv[i];
						o = -2;
						break;
				}
			}
			continue;
		}
		usage(argv[0]);
	}
	if (mode == -1) usage(argv[0]);
	
	if (mode == 1) {
		if (!filename) {
			f = stdout;
		} else {
			f = fopen(filename, "w");
		}
	} else if (mode == 2) {
		if (!filename) {
			f = stdin;
		} else {
			f = fopen(filename, "r");
		}
	} else {
		usage(argv[0]);
	}
	
	if (!f) {
		perror("fopen()");
		exit(1);
	}
	
	if ((ret = xbee_setup(&xbee, "xbee1", "/dev/ttyUSB0", 57600)) != XBEE_ENONE) {
		fprintf(stderr, "xbee_setup(): %d - %s\n", ret, xbee_errorToStr(ret));
		exit(1);
	}
	
	if ((ret = xbee_conNew(xbee, &con, "Local AT", NULL)) != XBEE_ENONE) {
		fprintf(stderr, "xbee_conNew(): %d - %s\n", ret, xbee_errorToStr(ret));
		exit(1);
	}
	
	if (mode == 1) {
		config_save(f, con);
	} else {
		config_load(f, con, write);
	}

	fprintf(stderr, "complete!\n");
}
