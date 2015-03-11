#ifndef __XBEE_CONN_H
#define __XBEE_CONN_H

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

extern struct xbee_ll_head *conList;

struct xbee_con {
	struct xbee *xbee;
	struct xbee_ll_head *pktList;
	struct xbee_modeConType *conType;
	
	int ending;
	int conIdentifier;
	
	struct xbee_interface *iface;
	
	void *userData;
	struct xbee_netClientInfo *netClient;
	
	xbee_t_conCallback callback;
	struct xbee_threadInfo *callbackThread;
	xsys_sem callbackSem;
	
	xsys_mutex txMutex;
	unsigned char frameId;
	
	enum xbee_conSleepStates sleepState;
	struct xbee_conAddress address;
	struct xbee_conInfo info;
	struct xbee_conSettings settings;
};

xbee_err xbee_conAlloc(struct xbee_con **nCon);
xbee_err xbee_conFree(struct xbee_con *con);

xbee_err xbee_conWake(struct xbee_con *con);

xbee_err _xbee_conNew(struct xbee *xbee, struct xbee_interface *iface, int allowInternal, struct xbee_con **retCon, const char *type, struct xbee_conAddress *address);

xbee_err xbee_conLink(struct xbee *xbee, struct xbee_modeConType *conType, struct xbee_conAddress *address, struct xbee_con *con);
xbee_err xbee_conUnlink(struct xbee_con *con);

xbee_err xbee_conLogAddress(struct xbee *xbee, int minLogLevel, struct xbee_conAddress *address);

xbee_err xbee_conAddressPrepDefault(struct xbee_conAddress *addr);
xbee_err xbee_conAddressCmpDefault(struct xbee_conAddress *addr1, struct xbee_conAddress *addr2, unsigned char *matchRating);

xbee_err xbee_conLocate(struct xbee_ll_head *conList, struct xbee_conAddress *address, struct xbee_con **retCon, enum xbee_conSleepStates alertLevel);
xbee_err _xbee_conLocate(struct xbee_ll_head *conList, struct xbee_conAddress *address, unsigned char *retRating, struct xbee_con **retCon, enum xbee_conSleepStates alertLevel, int needsLLLock);

xbee_err xbee_conLinkPacket(struct xbee_con *con, struct xbee_pkt *pkt);
xbee_err xbee_conCallbackProd(struct xbee_con *con);

#endif /* __XBEE_CONN_H */
