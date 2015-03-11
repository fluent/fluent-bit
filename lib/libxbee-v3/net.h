#ifndef __XBEE_NET_H
#define __XBEE_NET_H

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

extern struct xbee_ll_head *netDeadClientList;

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

struct xbee_netClientInfo {
	int fd;
	int die;
	
	int started;
	
	struct xbee *xbee;
	char addr[INET_ADDRSTRLEN];
	int port;
	
	struct xbee_threadInfo *rxThread;
	struct xbee_threadInfo *rxHandlerThread;
	struct xbee_threadInfo *txThread;
	
	struct xbee_ll_head *conList;
	
	struct xbee_con *bc_status;
	
	struct xbee_interface iface;
	struct xbee_frameBlock *fBlock;
	
	size_t txBufSize;
	struct xbee_buf *txBuf;
};

struct xbee_netInfo {
	int fd;
	
	struct xbee_threadInfo *serverThread;
	
	struct xbee_netClientInfo *newClient;
	int(*clientFilter)(struct xbee *xbee, const char *remoteHost);
	struct xbee_ll_head *clientList;
};

#ifndef XBEE_NO_NET_SERVER

xbee_err xbee_netClientAlloc(struct xbee *xbee, struct xbee_netClientInfo **info);
xbee_err xbee_netClientFree(struct xbee_netClientInfo *info);

xbee_err xbee_netClientStartup(struct xbee *xbee, struct xbee_netClientInfo *client);

#else /* XBEE_NO_NET_SERVER */

struct xbee_netClientInfo;

#endif /* XBEE_NO_NET_SERVER */

xbee_err xbee_netClientShutdown(struct xbee_netClientInfo *client);

#endif /* __XBEE_NET_H */
