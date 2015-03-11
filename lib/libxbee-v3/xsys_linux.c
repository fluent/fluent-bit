#ifndef __XBEE_XSYS_LOAD_C
#error This source should be included by xsys.c only
#endif /* __XBEE_XSYS_LOAD_C */

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
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

int xsys_serialSetup(struct xbee_serialInfo *info) {
	struct termios tc;
	speed_t chosenbaud;
	
	if (!info) return XBEE_EMISSINGPARAM;
	
	switch (info->baudrate) {
#ifdef B134
		case 134:    chosenbaud = B134;    break;
#endif
#ifdef B150
		case 150:    chosenbaud = B150;    break;
#endif
#ifdef B200
		case 200:    chosenbaud = B200;    break;
#endif
#ifdef B300
		case 300:    chosenbaud = B300;    break;
#endif
#ifdef B600
		case 600:    chosenbaud = B600;    break;
#endif
		case 1200:   chosenbaud = B1200;   break;
#ifdef B1800
		case 1800:   chosenbaud = B1800;   break;
#endif
		case 2400:   chosenbaud = B2400;   break;
		case 4800:   chosenbaud = B4800;   break;
		case 9600:   chosenbaud = B9600;   break;
		case 19200:  chosenbaud = B19200;  break;
		case 38400:  chosenbaud = B38400;  break;
		case 57600:  chosenbaud = B57600;  break;
		case 115200: chosenbaud = B115200; break;
#ifdef B230400
		case 230400: chosenbaud = B230400; break;
#endif
#ifdef B460800
		case 460800: chosenbaud = B460800; break;
#endif
#ifdef B500000
		case 500000: chosenbaud = B500000; break;
#endif
#ifdef B576000
		case 576000: chosenbaud = B576000; break;
#endif
#ifdef B921600
		case 921600: chosenbaud = B921600; break;
#endif
		default:
#ifdef XBEE_ALLOW_ARB_BAUD
			chosenbaud = info->baudrate;
#else
			return XBEE_EINVAL;
#endif
	}
	
	if ((info->dev.fd = open(info->device, O_RDWR | O_NOCTTY | O_SYNC)) == -1) {
		perror("open()");
		return XBEE_EIO;
	}

	if (flock(info->dev.fd, LOCK_EX | LOCK_NB) == -1) {
		perror("flock()");
		return XBEE_EINUSE;
	}

	if ((info->dev.f = fdopen(info->dev.fd, "r+")) == NULL) {
		perror("fdopen()");
		return XBEE_EIO;
	}
	
	setvbuf(info->dev.f, NULL, _IONBF, BUFSIZ);
	fflush(info->dev.f);
	
	if (tcgetattr(info->dev.fd, &tc)) {
		perror("tcgetattr()");
		return XBEE_ESETUP;
	}
	
	/* input flags */
	tc.c_iflag &= ~ IGNBRK;           /* enable ignoring break */
	tc.c_iflag &= ~(IGNPAR | PARMRK); /* disable parity checks */
	tc.c_iflag &= ~ INPCK;            /* disable parity checking */
	tc.c_iflag &= ~ ISTRIP;           /* disable stripping 8th bit */
	tc.c_iflag &= ~(INLCR | ICRNL);   /* disable translating NL <-> CR */
	tc.c_iflag &= ~ IGNCR;            /* disable ignoring CR */
	tc.c_iflag &= ~(IXON | IXOFF);    /* disable XON/XOFF flow control */
	/* output flags */
	tc.c_oflag &= ~ OPOST;            /* disable output processing */
	tc.c_oflag &= ~(ONLCR | OCRNL);   /* disable translating NL <-> CR */
#ifdef linux
	/* not for FreeBSD */
	tc.c_oflag &= ~ OFILL;            /* disable fill characters */
#endif /* linux */
	/* control flags */
	tc.c_cflag |=   CLOCAL;           /* prevent changing ownership */
	tc.c_cflag |=   CREAD;            /* enable reciever */
	tc.c_cflag &= ~ PARENB;           /* disable parity */
	if (info->baudrate >= 115200) {
		tc.c_cflag |=   CSTOPB;         /* enable 2 stop bits for the high baudrate */
	} else {
		tc.c_cflag &= ~ CSTOPB;         /* disable 2 stop bits */
	}
	tc.c_cflag &= ~ CSIZE;            /* remove size flag... */
	tc.c_cflag |=   CS8;              /* ...enable 8 bit characters */
	tc.c_cflag |=   HUPCL;            /* enable lower control lines on close - hang up */
#ifdef XBEE_NO_RTSCTS
	tc.c_cflag &= ~ CRTSCTS;          /* disable hardware CTS/RTS flow control */
#else
	tc.c_cflag |=   CRTSCTS;          /* enable hardware CTS/RTS flow control */
#endif
	/* local flags */
	tc.c_lflag &= ~ ISIG;             /* disable generating signals */
	tc.c_lflag &= ~ ICANON;           /* disable canonical mode - line by line */
	tc.c_lflag &= ~ ECHO;             /* disable echoing characters */
	tc.c_lflag &= ~ ECHONL;           /* ??? */
	tc.c_lflag &= ~ NOFLSH;           /* disable flushing on SIGINT */
	tc.c_lflag &= ~ IEXTEN;           /* disable input processing */

	/* control characters */
	memset(tc.c_cc,0,sizeof(tc.c_cc));
	
	/* set i/o baud rate */
	if (cfsetspeed(&tc, chosenbaud)) {
		perror("cfsetspeed()");
		return XBEE_ESETUP;
	}
	
	if (tcsetattr(info->dev.fd, TCSAFLUSH, &tc)) {
		perror("tcsetattr()");
		return XBEE_ESETUP;
	}
	
	/* enable input & output transmission */
#ifdef linux
/* for Linux */
	if (tcflow(info->dev.fd, TCOON | TCION)) {
#else
/* for FreeBSD */
	if (tcflow(info->dev.fd, TCOON)) {
#endif
		perror("tcflow()");
		return XBEE_ESETUP;
	}
	
	/* purge buffer */
	{
		int flags;
		char buf[1024];
		int n;
		flags = fcntl(info->dev.fd, F_GETFL, 0) & ~O_NONBLOCK;
		fcntl(info->dev.fd, F_SETFL, flags | O_NONBLOCK); /* disable blocking */
		if ((fcntl(info->dev.fd, F_GETFL, 0) & O_NONBLOCK) == 0) {
			fprintf(stderr, "unable to disable blocking...\n");
			return XBEE_ESETUP;
		}
		do {
			usleep(5000); /* 5ms */
			n = read(info->dev.fd, buf, sizeof(buf));
		} while (n > 0);
		fcntl(info->dev.fd, F_SETFL, flags); /* enable blocking */
		if (fcntl(info->dev.fd, F_GETFL, 0) & O_NONBLOCK) {
			fprintf(stderr, "unable to enable blocking...\n");
			return XBEE_ESETUP;
		}
	}
	
#ifndef linux
/* for FreeBSD */
	usleep(250000); /* it seems that the serial port takes a while to get going... */
#endif
	
	return XBEE_ENONE;
}

int xsys_serialShutdown(struct xbee_serialInfo *info) {
	if (!info) return XBEE_EMISSINGPARAM;
	if (info->dev.f) fclose(info->dev.f);
	info->dev.f = NULL;
	if (info->dev.fd) close(info->dev.fd);
	info->dev.fd = -1;
	return XBEE_ENONE;
}

int xsys_serialRead(struct xbee_serialInfo *info, int len, unsigned char *dest) {
	fd_set fds;
	int ret, retv;
	struct timeval to;
	int pos;
	
	if (!info || !dest) return XBEE_EMISSINGPARAM;
	if (info->dev.fd == -1 || !info->dev.f || len == 0) return XBEE_EINVAL;
	
	for (pos = 0; pos < len; pos += ret) {
		FD_ZERO(&fds);
		FD_SET(info->dev.fd, &fds);
		
		/* allow waiting for up-to 2 seconds */
		memset(&to, 0, sizeof(to));
		to.tv_sec = 2;
		if ((retv = select(info->dev.fd + 1, &fds, NULL, NULL, &to)) == -1) {
			if (errno == EINTR) return XBEE_ESELECTINTERRUPTED;
			return XBEE_ESELECT;
		} else if (retv == 0) {
			return XBEE_ETIMEOUT;
		}
		ret = 0;
		while ((retv = fread(&(dest[pos + ret]), 1, len - ret - pos, info->dev.f)) > 0) {
			ret += retv;
		}
		if (retv >= 0 && ret > 0) continue;
		if (feof(info->dev.f)) {
#ifndef linux
/* for FreeBSD */
			usleep(10000);
			continue;
#else
			return XBEE_EEOF;
#endif /* !linux */
		}
		if (ferror(info->dev.f)) {
			perror("fread()");
			return XBEE_EIO;
		}
	}
	
	return XBEE_ENONE;
}

/* ######################################################################### */

int xsys_serialWrite(struct xbee_serialInfo *info, int len, unsigned char *src) {
	int pos;
	int ret;
	
	if (!info || !src) return XBEE_EMISSINGPARAM;
	if (info->dev.fd == -1 || !info->dev.f || len == 0) return XBEE_EINVAL;
	
	for (pos = 0; pos < len; pos += ret) {
		if ((ret = fwrite(&(src[pos]), 1, len - pos, info->dev.f)) > 0) continue;
		if (ferror(info->dev.f)) {
			perror("fwrite()");
			return XBEE_EIO;
		}
	}
	
	return XBEE_ENONE;
}
