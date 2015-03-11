#ifndef __XBEE_H
#define __XBEE_H

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

#ifndef EXPORT
#define EXPORT
#define XBEE_EXPORT_DEFINED
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdarg.h>

#ifdef _WIN32
#ifndef ETIMEDOUT
/* only define this if it hasn't been given already...
   xsys_win32_winpthreads.h will provide it, as do some more
   recent versions of VS */
#define ETIMEDOUT           110
#endif

#define CLOCK_REALTIME      0

#if !defined(WIN_PTHREADS) && !defined(XBEE_NODEF_TIMESPEC)
/* i still hate windows */
struct timespec {
  time_t  tv_sec;    /* seconds */
  long    tv_nsec;   /* nanoseconds */
};
#endif /* !WIN_PTHREADS && !XBEE_NODEF_TIMESPEC */

#else /* !_WIN32 */

#include <sys/time.h>

#endif /* _WIN32 */

/* ######################################################################### */

/* structs that won't be defined in user-space */
struct xbee;
struct xbee_con;


/* ######################################################################### */
/* tasty structs 'n stuff */

/* these must increment away from 'awake' */
enum xbee_conSleepStates {
	CON_AWAKE  = 0,
	CON_SNOOZE = 1,
	CON_SLEEP  = 2,
};

struct xbee_conAddress {
	unsigned char broadcast; /* if set, this address just sent us a broadcast message */

	unsigned char addr16_enabled;
	unsigned char addr16[2];
	
	unsigned char addr64_enabled;
	unsigned char addr64[8];
	
	unsigned char endpoints_enabled;
	unsigned char endpoint_local;
	unsigned char endpoint_remote;
	
	unsigned char profile_enabled;
	unsigned short profile_id;
	
	unsigned char cluster_enabled;
	unsigned short cluster_id;
};

struct xbee_conInfo {
	int countRx;
	int countTx;
	
	time_t lastRxTime;
};

struct xbee_conSettings {
	/* libxbee options: */
	unsigned char noBlock          : 1;
	unsigned char catchAll         : 1;
	unsigned char noWaitForAck     : 1;
	
	/* generic options: */
	unsigned char queueChanges     : 1; /* for AT connections */
	unsigned char disableAck       : 1; /* specific options for XBee 1 / causes use of FrameID 0x00 for others */
	unsigned char broadcast        : 1; /* used to tranmit on the broadcast PAN, for address broadcast, use the appropriate address */
	
	/* XBee 2 / ZNet options: */
	unsigned char multicast        : 1;
	
	/* XBee ZigBee options: */
	unsigned char disableRetries   : 1;
	unsigned char enableEncryption : 1;
	unsigned char extendTimeout    : 1;
	
	/* XBee 5 options: */
	unsigned char noRoute          : 1;

	/* other */
	unsigned char broadcastRadius;
};

/* ######################################################################### */

struct xbee_pkt {
	struct xbee *xbee;
	struct xbee_con *con;
	const char *conType;

	unsigned char status;
	unsigned char options;
	unsigned char rssi; /* print as "RSSI: -%d\n" - only valid for XBee 1 */
	unsigned char frameId;

	struct timespec timestamp;

	struct xbee_conAddress address;
	
	unsigned char atCommand[2];
	
	struct xbee_ll_head *dataItems;
	
	int dataLen;
	unsigned char data[1];
};

/* ######################################################################### */

enum xbee_errors {
	XBEE_ENONE                 =  0,
	XBEE_EUNKNOWN              = -1,
	
	XBEE_ENOMEM                = -2,
	
	XBEE_ESELECT               = -3,
	XBEE_ESELECTINTERRUPTED    = -4,
	
	XBEE_EEOF                  = -5,
	XBEE_EIO                   = -6,
	
	XBEE_ESEMAPHORE            = -7,
	XBEE_EMUTEX                = -8,
	XBEE_ETHREAD               = -9,
	XBEE_ELINKEDLIST           = -10,
	
	XBEE_ESETUP                = -11,
	XBEE_EMISSINGPARAM         = -12,
	XBEE_EINVAL                = -13,
	XBEE_ERANGE                = -14,
	XBEE_ELENGTH               = -15,
	
	XBEE_EFAILED               = -18,
	XBEE_ETIMEOUT              = -17,
	XBEE_EWOULDBLOCK           = -16,
	XBEE_EINUSE                = -19,
	XBEE_EEXISTS               = -20,
	XBEE_ENOTEXISTS            = -21,
	XBEE_ENOFREEFRAMEID        = -22,
	
	XBEE_ESTALE                = -23,
	XBEE_ENOTIMPLEMENTED       = -24,
	
	XBEE_ETX                   = -25,
	
	XBEE_EREMOTE               = -26,
	
	XBEE_ESLEEPING             = -27,
	XBEE_ECATCHALL             = -28,
	
	XBEE_ESHUTDOWN             = -29,
};
typedef enum xbee_errors xbee_err;

/* ######################################################################### */
/* ######################################################################### */
/* --- ver.c --- */
EXPORT extern const char libxbee_revision[];
EXPORT extern const char libxbee_commit[];
EXPORT extern const char libxbee_committer[];
EXPORT extern const char libxbee_buildtime[];


/* ######################################################################### */
/* --- xbee.c --- */
typedef void (*xbee_t_eofCallback)(struct xbee *xbee, void *rxInfo);

EXPORT void xbee_freeMemory(void *ptr); /* <-- this is for STUPID windows */
EXPORT xbee_err xbee_validate(struct xbee *xbee);
EXPORT xbee_err xbee_setup(struct xbee **retXbee, const char *mode, ...);
EXPORT xbee_err xbee_vsetup(struct xbee **retXbee, const char *mode, va_list ap);
EXPORT xbee_err xbee_attachEOFCallback(struct xbee *xbee, xbee_t_eofCallback eofCallback);
EXPORT xbee_err xbee_shutdown(struct xbee *xbee);

EXPORT xbee_err xbee_dataSet(struct xbee *xbee, void *newData, void **oldData);
EXPORT xbee_err xbee_dataGet(struct xbee *xbee, void **curData);

/* ######################################################################### */
/* --- mode.c --- */
EXPORT xbee_err xbee_modeGetList(char ***retList);
EXPORT xbee_err xbee_modeGet(struct xbee *xbee, const char **mode);


/* ######################################################################### */
/* --- conn.c --- */
typedef void(*xbee_t_conCallback)(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data);

EXPORT xbee_err xbee_conGetTypes(struct xbee *xbee, char ***retList);
/* - */
EXPORT xbee_err xbee_conNew(struct xbee *xbee, struct xbee_con **retCon, const char *type, struct xbee_conAddress *address);
EXPORT xbee_err xbee_conValidate(struct xbee_con *con);
EXPORT xbee_err xbee_conGetXBee(struct xbee_con *con, struct xbee **xbee);
/* - */
EXPORT xbee_err xbee_conTx(struct xbee_con *con, unsigned char *retVal, const char *format, ...);
EXPORT xbee_err xbee_convTx(struct xbee_con *con, unsigned char *retVal, const char *format, va_list args);
EXPORT xbee_err xbee_connTx(struct xbee_con *con, unsigned char *retVal, const unsigned char *buf, int len);
EXPORT xbee_err xbee_conxTx(struct xbee_con *con, unsigned char *retVal, unsigned char *frameId, const char *format, ...);
EXPORT xbee_err xbee_convxTx(struct xbee_con *con, unsigned char *retVal, unsigned char *frameId, const char *format, va_list args);
EXPORT xbee_err xbee_connxTx(struct xbee_con *con, unsigned char *retVal, unsigned char *frameId, const unsigned char *buf, int len);
/* - */
EXPORT xbee_err xbee_conRx(struct xbee_con *con, struct xbee_pkt **retPkt, int *remainingPackets);
EXPORT xbee_err xbee_conRxWait(struct xbee_con *con, struct xbee_pkt **retPkt, int *remainingPackets);
/* - */
EXPORT xbee_err xbee_conPurge(struct xbee_con *con);
/* - */
EXPORT xbee_err xbee_conSleepSet(struct xbee_con *con, enum xbee_conSleepStates state);
EXPORT xbee_err xbee_conSleepGet(struct xbee_con *con, enum xbee_conSleepStates *state);
/* - */
EXPORT xbee_err xbee_conDataSet(struct xbee_con *con, void *newData, void **oldData);
EXPORT xbee_err xbee_conDataGet(struct xbee_con *con, void **curData);
/* - */
EXPORT xbee_err xbee_conTypeGet(struct xbee_con *con, char **type);
/* - */
EXPORT xbee_err xbee_conInfoGet(struct xbee_con *con, struct xbee_conInfo *info);
/* - */
EXPORT xbee_err xbee_conCallbackSet(struct xbee_con *con, xbee_t_conCallback newCallback, xbee_t_conCallback *oldCallback);
EXPORT xbee_err xbee_conCallbackGet(struct xbee_con *con, xbee_t_conCallback *curCallback);
/* - */
EXPORT xbee_err xbee_conSettings(struct xbee_con *con, struct xbee_conSettings *newSettings, struct xbee_conSettings *oldSettings);
/* - */
EXPORT xbee_err xbee_conEnd(struct xbee_con *con);


/* ######################################################################### */
/* --- pkt.c --- */
EXPORT xbee_err xbee_pktFree(struct xbee_pkt *pkt);
EXPORT xbee_err xbee_pktValidate(struct xbee_pkt *pkt);
EXPORT xbee_err xbee_pktDataGet(struct xbee_pkt *pkt, const char *key, int id, int index, void **retData);
EXPORT xbee_err xbee_pktAnalogGet(struct xbee_pkt *pkt, int channel, int index, int *retVal);
EXPORT xbee_err xbee_pktDigitalGet(struct xbee_pkt *pkt, int channel, int index, int *retVal);


/* ######################################################################### */
/* --- net.c --- */
EXPORT xbee_err xbee_netStart(struct xbee *xbee, int port, int(*clientFilter)(struct xbee *xbee, const char *remoteHost));
EXPORT xbee_err xbee_netvStart(struct xbee *xbee, int fd, int(*clientFilter)(struct xbee *xbee, const char *remoteHost));
EXPORT xbee_err xbee_netStop(struct xbee *xbee);


/* ######################################################################### */
/* --- log.c --- */
EXPORT xbee_err xbee_logTargetSet(struct xbee *xbee, FILE *f);
EXPORT xbee_err xbee_logTargetGet(struct xbee *xbee, FILE **f);
EXPORT xbee_err xbee_logLevelSet(struct xbee *xbee, int level);
EXPORT xbee_err xbee_logLevelGet(struct xbee *xbee, int *level);

#ifndef __XBEE_INTERNAL_H
EXPORT xbee_err _xbee_logDev(const char *file, int line, const char *function, struct xbee *xbee, int minLevel, const char *format, ...);
#define xbee_log(...) _xbee_logDev(__FILE__,__LINE__,__FUNCTION__,__VA_ARGS__)
#endif


/* ########################################################################## */
/* --- error.c --- */
EXPORT const char *xbee_errorToStr(xbee_err error);


/* ######################################################################### */

#ifdef __cplusplus

} /* extern "C" */

#endif /* __cplusplus */

#ifdef XBEE_EXPORT_DEFINED
#undef EXPORT
#undef XBEE_EXPORT_DEFINED
#endif

#endif /* __XBEE_H */
