#ifndef __XBEE_PKT_H
#define __XBEE_PKT_H

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

#define PKT_DATAKEY_MAXLEN 32
struct pkt_dataKey {
	char name[PKT_DATAKEY_MAXLEN]; /* eg: 'analog' */
	int id; /* eg: (channel) 3 */
	struct xbee_ll_head *items; /* this contains a list of data, which CAN be raw data cast to a void*, eg: 524 */
	void (*freeCallback)(void*); /* can only be assigned once for each key */
};

/* ########################################################################## */

extern struct xbee_ll_head *pktList;

xbee_err xbee_pktAlloc(struct xbee_pkt **nPkt, struct xbee_pkt *oPkt, int dataLen);

xbee_err xbee_pktLink(struct xbee_con *con, struct xbee_pkt *pkt);
xbee_err xbee_pktUnlink(struct xbee_con *con, struct xbee_pkt *pkt);
xbee_err _xbee_pktUnlink(struct xbee_con *con, struct xbee_pkt *pkt, int needsLLLock);

xbee_err xbee_pktDataKeyAdd(struct xbee_pkt *pkt, const char *key, int id, struct pkt_dataKey **retKey, void (*freeCallback)(void*));
xbee_err xbee_pktDataKeyGet(struct xbee_pkt *pkt, const char *key, int id, struct pkt_dataKey **retKey);

xbee_err xbee_pktDataAdd(struct xbee_pkt *pkt, const char *key, int id, void *data, void (*freeCallback)(void*));

xbee_err xbee_pktAnalogAdd(struct xbee_pkt *pkt, int channel, long value);
xbee_err xbee_pktDigitalAdd(struct xbee_pkt *pkt, int channel, long value);

#endif /* __XBEE_PKT_H */
