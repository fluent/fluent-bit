#ifndef __XBEE_MODE_H
#define __XBEE_MODE_H

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

struct xbee_modeDataHandlerRx {
	unsigned char identifier;
	xbee_err (*func)(struct xbee *xbee,
	                 void *arg,
	                 unsigned char identifier,
	     /* IN */    struct xbee_tbuf *buf,
	     /* OUT */   struct xbee_frameInfo *frameInfo,
	     /* OUT */   struct xbee_conAddress *address,
	     /* OUT */   struct xbee_pkt **pkt);
	xbee_err (*funcPost)(struct xbee *xbee,
	                     struct xbee_con *con,
	                     struct xbee_pkt *pkt);
	unsigned char needsFree;
};

struct xbee_modeDataHandlerTx {
	unsigned char identifier;
	xbee_err (*func)(struct xbee *xbee,
	                 struct xbee_con *con,
	                 void *arg,
	                 unsigned char identifier,
	     /* IN */    unsigned char frameId,
	     /* IN */    struct xbee_conAddress *address,
	     /* IN */    struct xbee_conSettings *settings,
	     /* IN */    const unsigned char *buf,
	     /* IN */    int len,
	     /* OUT */   struct xbee_sbuf **oBuf);
	unsigned char needsFree;
};

struct xbee_modeConType {
	char *name;
	struct xbee_modeDataHandlerRx *rxHandler;
	struct xbee_modeDataHandlerTx *txHandler;
	void (*init)(struct xbee_modeConType *conType);

	/* this function will be called to prepare the address structure (after libxbee has had a go...) */
	xbee_err (*addressPrep)(struct xbee_conAddress *addr);
	/* this function should compare the given addresses
	   if the addresses are a perfect match, matchRating should be set to 255
	   if the addresses have nothing in common, matchRating should be set to 0 */
	xbee_err (*addressCmp)(struct xbee_conAddress *addr1, struct xbee_conAddress *addr2, unsigned char *matchRating);
	
	int nameNeedsFree;
	
	struct xbee_ll_head *conList;
	
	unsigned char internal     : 1;
	unsigned char allowFrameId : 1;
	unsigned char useTimeout   : 1;
	struct timespec timeout;
	
	unsigned char save_addr16;
	unsigned char save_addr64;
	
	
#define ADDR_EP_NOTALLOW    0x01
#define ADDR_EP_REQUIRED    0x02
#define ADDR_64_NOTALLOW    0x04
#define ADDR_16_NOTALLOW    0x08
#define ADDR_64_REQUIRED    0x10
#define ADDR_16_REQUIRED    0x20
#define ADDR_16OR64         0x40
#define ADDR_16XOR64        0x80

#define ADDR_NONE           (ADDR_16_NOTALLOW | ADDR_64_NOTALLOW | ADDR_EP_NOTALLOW)

#define ADDR_16_ONLY        (ADDR_16_REQUIRED | ADDR_64_NOTALLOW | ADDR_EP_NOTALLOW)
#define ADDR_64_ONLY        (ADDR_16_NOTALLOW | ADDR_64_REQUIRED | ADDR_EP_NOTALLOW)
#define ADDR_EP_ONLY        (ADDR_16_NOTALLOW | ADDR_64_NOTALLOW | ADDR_EP_REQUIRED)

#define ADDR_64_16OPT_EP    (ADDR_64_REQUIRED | ADDR_EP_REQUIRED)
#define ADDR_64_16OPT_NOEP  (ADDR_64_REQUIRED | ADDR_EP_NOTALLOW)
#define ADDR_64_16OPT_EPOPT (ADDR_64_REQUIRED)

#define ADDR_16OR64_NOEP    (ADDR_16OR64 | ADDR_EP_NOTALLOW)
#define ADDR_16OR64_EP      (ADDR_16OR64 | ADDR_EP_REQUIRED)
#define ADDR_16XOR64_NOEP   (ADDR_16XOR64 | ADDR_EP_NOTALLOW)
#define ADDR_16XOR64_EP     (ADDR_16XOR64 | ADDR_EP_REQUIRED)
	/* 0b........
	     -------1  - endpoints not allowed
	     ------1-  - endpoints required
	     -----1--  - 64-bit not allowed
	     ----1---  - 16-bit not allowed
	     ---1----  - 64-bit address required
	     --1-----  - 16-bit address required
	     -1------  - 16 or 64-bit address required (OR)
	     1-------  - 16 or 64-bit address required (XOR) */
	unsigned char addressRules;
};

struct xbee_modeSupport {
	xbee_err (* const conNew)(struct xbee *xbee, struct xbee_interface *iface, struct xbee_modeConType *conType, struct xbee_conAddress *address, int *conIdentifier);
	xbee_err (* const conValidate)(struct xbee_con *con);
	xbee_err (* const conSleepSet)(struct xbee_con *con, enum xbee_conSleepStates state);
	xbee_err (* const conSleepGet)(struct xbee_con *con);
	xbee_err (* const conSettings)(struct xbee_con *con, struct xbee_conSettings *newSettings);
	xbee_err (* const conEnd)(struct xbee_con *con);
};

struct xbee_mode {
	const char * const name;
	
	const struct xbee_modeConType ** const conTypes;
	
	xbee_err (* const init)(struct xbee *xbee, va_list ap);
	xbee_err (* const prepare)(struct xbee *xbee);
	xbee_err (* const shutdown)(struct xbee *xbee);
	
	xbee_err (* const rx_io)(struct xbee *xbee, void *arg, struct xbee_tbuf **buf); /* retrieves raw buffers from the I/O device */
	xbee_err (* const tx_io)(struct xbee *xbee, void *arg, struct xbee_sbuf *buf); /* transmits raw buffers to the I/O device */
	
	xbee_err (* const thread)(struct xbee *xbee, int *restart, void *arg);
	
	struct xbee_modeSupport support;
};

xbee_err xbee_modeRetrieve(const char *name, const struct xbee_mode **retMode);

xbee_err xbee_modeImport(struct xbee_modeConType **retConTypes, const struct xbee_mode *mode);
xbee_err xbee_modeAddConType(struct xbee_modeConType **extConTypes, const struct xbee_modeConType *newConType);
xbee_err xbee_modeCleanup(struct xbee_modeConType *conTypes);

xbee_err xbee_modeLocateConType(struct xbee_modeConType *conTypes, int allowInternal, const char *name, const unsigned char *rxId, const unsigned char *txId, struct xbee_modeConType **retType);

/* list of potential modes... basically a list of subdirectories in './modes/' */
extern const struct xbee_mode mode_xbee1;
extern const struct xbee_mode mode_xbee2;
extern const struct xbee_mode mode_xbee3;
extern const struct xbee_mode mode_xbee5;
extern const struct xbee_mode mode_xbee6b;
extern const struct xbee_mode mode_xbeeZB;
extern const struct xbee_mode mode_net;
extern const struct xbee_mode mode_debug;

#endif /* __XBEE_MODE_H */
