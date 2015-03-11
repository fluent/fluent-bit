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

#include "internal.h"
#include "xbee_int.h"
#include "net.h"

struct xbee_ll_head *netDeadClientList = NULL;

#ifdef XBEE_NO_NET_SERVER

EXPORT xbee_err xbee_netStart(struct xbee *xbee, int port, int(*clientFilter)(struct xbee *xbee, const char *remoteHost)) {
	return XBEE_ENOTIMPLEMENTED;
}

EXPORT xbee_err xbee_netvStart(struct xbee *xbee, int fd, int(*clientFilter)(struct xbee *xbee, const char *remoteHost)) {
	return XBEE_ENOTIMPLEMENTED;
}

EXPORT xbee_err xbee_netStop(struct xbee *xbee) {
	return XBEE_ENOTIMPLEMENTED;
}

xbee_err xbee_netClientShutdown(struct xbee_netClientInfo *client) {
	return XBEE_ENONE;
}

#else /* XBEE_NO_NET_SERVER */

#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#ifndef linux
/* for FreeBSD */
#include <netinet/in.h>
#endif /* !linux */

#include "rx.h"
#include "tx.h"
#include "frame.h"
#include "conn.h"
#include "net_io.h"
#include "net_handlers.h"
#include "net_callbacks.h"
#include "mode.h"
#include "log.h"
#include "ll.h"
#include "thread.h"

/* ######################################################################### */

xbee_err xbee_netClientAlloc(struct xbee *xbee, struct xbee_netClientInfo **info) {
	xbee_err ret;
	struct xbee_netClientInfo *iInfo;
	
	if (!info) return XBEE_EMISSINGPARAM;
	
	if ((iInfo = malloc(sizeof(*iInfo))) == NULL) return XBEE_ENOMEM;
	*info = iInfo;
	memset(iInfo, 0, sizeof(*iInfo));

	ret = XBEE_ENONE;
	
	iInfo->conList = xbee_ll_alloc();
	
	if ((ret = xbee_rxAlloc(&iInfo->iface.rx)) != XBEE_ENONE) goto die;
	if ((ret = xbee_txAlloc(&iInfo->iface.tx)) != XBEE_ENONE) goto die;
	if ((ret = xbee_frameBlockAlloc(&iInfo->fBlock)) != XBEE_ENONE) goto die;
	
	iInfo->xbee = xbee;
	
	iInfo->iface.rx->handlerArg = iInfo;
	iInfo->iface.rx->ioArg = iInfo;
	iInfo->iface.rx->ioFunc = xbee_netRx;
	iInfo->iface.rx->fBlock = iInfo->fBlock;
	
	iInfo->iface.tx->ioArg = iInfo;
	iInfo->iface.tx->ioFunc = xbee_netTx;
	
	goto done;
die:
	*info = NULL;
	xbee_netClientFree(iInfo);
done:
	return ret;
}

xbee_err xbee_netClientFree(struct xbee_netClientInfo *info) {
	if (!info) return XBEE_EINVAL;
	
	if (info->iface.conTypes) xbee_modeCleanup(info->iface.conTypes);
	xbee_frameBlockFree(info->fBlock);
	xbee_txFree(info->iface.tx);
	xbee_rxFree(info->iface.rx);
	xbee_ll_free(info->conList, (void(*)(void*))xbee_conEnd);
	
	free(info);
	return XBEE_ENONE;
}

/* ######################################################################### */

xbee_err xbee_netConNew(struct xbee *xbee, struct xbee_netClientInfo *client, char *type, unsigned char endpoint, xbee_t_conCallback callback) {
	xbee_err ret;
	struct xbee_conAddress address;
	struct xbee_con *con;
	
	if (!xbee || !client || !type || !callback) return XBEE_EMISSINGPARAM;
	
	memset(&address, 0, sizeof(address));
	address.endpoints_enabled = 1;
	address.endpoint_local = endpoint;
	address.endpoint_remote = endpoint;
	
	if ((ret = _xbee_conNew(xbee, &client->iface, 1, &con, type, &address)) != XBEE_ENONE) return ret;
	if (!con) return XBEE_EUNKNOWN;
	con->netClient = client;
	
	if (callback == xbee_net_start) {
		client->bc_status = con;
	}
	
	xbee_conDataSet(con, client, NULL);
	xbee_conCallbackSet(con, callback, NULL);
	
	return XBEE_ENONE;
}

xbee_err xbee_netClientSetupBackchannel(struct xbee *xbee, struct xbee_netClientInfo *client) {
	xbee_err ret;
	int endpoint;

	if (!xbee || !client) return XBEE_EMISSINGPARAM;
	
	for (endpoint = 0; xbee_netServerCallbacks[endpoint].callback; endpoint++) {
		if ((ret = xbee_netConNew(xbee, client, "Backchannel", endpoint, xbee_netServerCallbacks[endpoint].callback)) != XBEE_ENONE) return ret;
	}
	
	/* 'frontchannel' connections are added later... by the developer... you know, with xbee_conNew()... */
	
	return ret;
}

/* ######################################################################### */

xbee_err xbee_netClientStartup(struct xbee *xbee, struct xbee_netClientInfo *client) {
	xbee_err ret;
	
	if (!xbee || !client) return XBEE_EMISSINGPARAM;
	
	ret = XBEE_ENONE;
	
	if ((ret = xbee_netClientSetupBackchannel(xbee, client)) != XBEE_ENONE) return ret;
	
	if ((ret = xbee_threadStart(xbee, &client->rxThread, 150000, 0, xbee_rx, client->iface.rx)) != XBEE_ENONE) {
		xbee_log(1, "failed to start xbee_rx() thread for client from %s:%d", client->addr, client->port);
		ret = XBEE_ETHREAD;
		goto die;
	}
	if ((ret = xbee_threadStart(xbee, &client->rxHandlerThread, 150000, 0, xbee_rxHandler, client->iface.rx)) != XBEE_ENONE) {
		xbee_log(1, "failed to start xbee_rx() thread for client from %s:%d", client->addr, client->port);
		ret = XBEE_ETHREAD;
		goto die;
	}
	if ((ret = xbee_threadStart(xbee, &client->txThread, 150000, 0, xbee_tx, client->iface.tx)) != XBEE_ENONE) {
		xbee_log(1, "failed to start xbee_tx() thread for client from %s:%d", client->addr, client->port);
		ret = XBEE_ETHREAD;
		goto die;
	}
	return XBEE_ENONE;
die:
	if (client->txThread) {
		xbee_threadKillJoin(xbee, client->txThread, NULL);
		client->txThread = NULL;
	}
	if (client->rxHandlerThread) {
		xbee_threadKillJoin(xbee, client->rxHandlerThread, NULL);
		client->rxHandlerThread = NULL;
	}
	if (client->rxThread) {
		xbee_threadKillJoin(xbee, client->rxThread, NULL);
		client->rxThread = NULL;
	}
	return ret;
}

xbee_err xbee_netClientShutdown(struct xbee_netClientInfo *client) {
	if (!client) return XBEE_EMISSINGPARAM;
	if (!client->xbee) return XBEE_EINVAL;

	if (client->rxThread) {
		xbee_threadKillJoin(client->xbee, client->rxThread, NULL);
		client->rxThread = NULL;
	}
	if (client->rxHandlerThread) {
		xbee_threadKillJoin(client->xbee, client->rxHandlerThread, NULL);
		client->rxHandlerThread = NULL;
	}
	if (client->txThread) {
		xbee_threadKillJoin(client->xbee, client->txThread, NULL);
		client->txThread = NULL;
	}
	
	if (client->fd != -1) {
		shutdown(client->fd, SHUT_RDWR);
		xsys_close(client->fd);
	}
	
	xbee_netClientFree(client);
	
	return XBEE_ENONE;
}

/* ######################################################################### */

xbee_err xbee_netServerThread(struct xbee *xbee, int *restart, void *arg) {
	xbee_err ret;
	struct sockaddr_in addrinfo;
	socklen_t addrlen;
	char addr[INET_ADDRSTRLEN];
	int port;
	unsigned int i, o, u;
	
	struct xbee_netInfo *info;
	struct xbee_netClientInfo *client;
	struct xbee_netClientInfo *deadClient;
	
	struct xbee_modeConType newConType;
	struct xbee_modeDataHandlerRx *rx;
	struct xbee_modeDataHandlerTx *tx;
	
	if (!xbee->netInfo || arg != xbee->netInfo) {
		*restart = 0;
		return XBEE_EINVAL;
	}
	
	client = NULL;
	while (xbee->netInfo) {
		ret = XBEE_ENONE;
		info = xbee->netInfo;
		
		while (xbee_ll_ext_head(netDeadClientList, (void**)&deadClient) == XBEE_ENONE && deadClient != NULL) {
			xbee_netClientShutdown(deadClient);
		}
		
		xbee_ll_count_items(info->clientList, &u);
		xbee_log(4, "active clients: %u", u);
		
		if (!client) {
			if ((ret = xbee_netClientAlloc(xbee, &info->newClient)) != XBEE_ENONE) return ret;
			client = info->newClient;
			client->xbee = xbee;
		}
		
		addrlen = sizeof(addrinfo);
		if ((client->fd = accept(info->fd, (struct sockaddr*)&addrinfo, &addrlen)) < 0) {
			ret = XBEE_EIO;
			if (errno == EINVAL) {
				/* it appears we aren't listening yet... or have stopped listening. let's sleep for 5ms and try again */
				usleep(5000);
				continue;
			}
			break;
		}
		
		if (!xbee->netInfo) {
			shutdown(client->fd, SHUT_RDWR);
			close(client->fd);
			break;
		}
		
		memset(addr, 0, sizeof(addr));
		if (inet_ntop(AF_INET, (const void*)&addrinfo.sin_addr, addr, sizeof(addr)) == NULL) {
			shutdown(client->fd, SHUT_RDWR);
			close(client->fd);
			ret = XBEE_EIO;
			break;
		}
		port = ntohs(addrinfo.sin_port);
		
		if (info->clientFilter) {
			if (info->clientFilter(xbee, addr) != 0) {
				shutdown(client->fd, SHUT_RDWR);
				close(client->fd);
				xbee_log(1, "*** connection from %s:%d was blocked ***", addr, port);
				continue;
			}
		}
		
		memcpy(client->addr, addr, sizeof(client->addr));
		client->port = port;
		
		client->iface.conTypes = NULL;
		if ((ret = xbee_modeImport(&client->iface.conTypes, &xbee_netServerMode)) != XBEE_ENONE) {
			shutdown(client->fd, SHUT_RDWR);
			close(client->fd);
			xbee_log(10, "failed to accept client... xbee_modeImport() returned %d", ret);
			continue;
		}
		
		rx = NULL;
		tx = NULL;
		for (i = 0, o = -1; xbee->iface.conTypes[i].name; i++) {
			struct xbee_modeConType *conType;
			
			/* this order of conTypes HAS to match up with the order in net_callbacks.c xbee_net_conGetTypes() */
			if (xbee->iface.conTypes[i].internal) continue;
			conType = &xbee->iface.conTypes[i];
			o++;
			
			memset(&newConType, 0, sizeof(newConType));
			
			/* YES - THIS IS BACKWARDS... think about it */
			if (conType->rxHandler) {
				if ((tx = malloc(sizeof(*tx))) == NULL) { ret = XBEE_ENOMEM; break; } /* !!! */
				memset(tx, 0, sizeof(*tx));
				
				tx->identifier = o;
				tx->func = xbee_netServer_fc_tx_func;
				tx->needsFree = 1;
				
				newConType.txHandler = tx;
			}
			
			/* YES - THIS IS BACKWARDS... think about it */
			if (conType->txHandler) {
				if ((rx = malloc(sizeof(*rx))) == NULL) { ret = XBEE_ENOMEM; break; } /* !!! */
				memset(rx, 0, sizeof(*rx));
				
				rx->identifier = o;
				rx->func = xbee_netServer_fc_rx_func;
				rx->needsFree = 1;
				
				newConType.rxHandler = rx;
			}
			
			newConType.name = conType->name;
			
			if ((ret = xbee_modeAddConType(&client->iface.conTypes, &newConType)) != XBEE_ENONE) {
				if (rx) free(rx);
				rx = NULL;
				if (tx) free(tx);
				tx = NULL;
				continue;
			}
			
			rx = NULL;
			tx = NULL;
		}
		if (rx) free(rx);
		if (tx) free(tx);
		if (ret != XBEE_ENONE) {
			xbee_modeCleanup(client->iface.conTypes);
			shutdown(client->fd, SHUT_RDWR);
			close(client->fd);
			xbee_log(10, "failed to import all connection types... returned %d", ret);
			continue;
		}
		
		client->iface.rx->conTypes = &client->iface.conTypes;
		
		if ((ret = xbee_netClientStartup(xbee, client)) != XBEE_ENONE) {
			xbee_modeCleanup(client->iface.conTypes);
			shutdown(client->fd, SHUT_RDWR);
			close(client->fd);
			xbee_log(10, "failed to accept client... xbee_netClientStartup() returned %d", ret);
			continue;
		}
		
		xbee_log(10, "accepted connection from %s:%d", addr, port);
		
		xbee_ll_add_tail(info->clientList, client);
		info->newClient = NULL;
		client = NULL;
	}
	
	if (xbee->netInfo) xbee->netInfo->newClient = NULL;
	if (client) {	
		xbee_netClientFree(client);
	}
	
	return ret;
}

/* ######################################################################### */

EXPORT xbee_err xbee_netStart(struct xbee *xbee, int port, int(*clientFilter)(struct xbee *xbee, const char *remoteHost)) {
	xbee_err ret;
	int fd;
	int i;
  struct sockaddr_in addrinfo;
	
	if (!xbee) return XBEE_EMISSINGPARAM;
	if (xbee->netInfo != NULL) return XBEE_EINVAL;
	if (port <= 0 || port >= 65535) return XBEE_EINVAL;
	
	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) return XBEE_EIO;
	
	i = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) == -1) {
		xsys_close(fd);
		return XBEE_EIO;
	}
	
	memset(&addrinfo, 0, sizeof(addrinfo));
	addrinfo.sin_family = AF_INET;
	addrinfo.sin_port = htons(port);
	addrinfo.sin_addr.s_addr = INADDR_ANY;
	
	if (bind(fd, (const struct sockaddr*)&addrinfo, sizeof(addrinfo)) == -1) {
		xsys_close(fd);
		return XBEE_EIO;
	}
	
	if ((ret = xbee_netvStart(xbee, fd, clientFilter)) != XBEE_ENONE) {
		xsys_close(fd);
	}
	
	return ret;
}

EXPORT xbee_err xbee_netvStart(struct xbee *xbee, int fd, int(*clientFilter)(struct xbee *xbee, const char *remoteHost)) {
	xbee_err ret;
	struct xbee_netInfo *info;
	
	if (!xbee) return XBEE_EMISSINGPARAM;
	if (fd < 0 || xbee->netInfo != NULL) return XBEE_EINVAL;
	
	ret = XBEE_ENONE;
	
	if ((info = malloc(sizeof(*info))) == NULL) return XBEE_ENOMEM;
	memset(info, 0, sizeof(*info));
	
	if ((info->clientList = xbee_ll_alloc()) == NULL) {
		free(info);
		return XBEE_ENOMEM;
	}
	
	info->fd = fd;
	info->clientFilter = clientFilter;
	
	xbee->netInfo = info;
	
	if ((ret = xbee_threadStart(xbee, &info->serverThread, 150000, 0, xbee_netServerThread, info)) == XBEE_ENONE) {
		if (listen(fd, 512) == -1) return XBEE_EIO;
	}
	
	return ret;
}

/* ######################################################################### */

EXPORT xbee_err xbee_netStop(struct xbee *xbee) {
	struct xbee_netInfo *info;
	struct xbee_netClientInfo *deadClient;
	
	if (!xbee) return XBEE_EMISSINGPARAM;
	if (!xbee->netInfo) return XBEE_EINVAL;
	
	info = xbee->netInfo;
	xbee->netInfo = NULL;
	
	/* closing the listening fd, will cause the accept() in the serverThread to return an error.
	   once that returns, the while() loop will break, and the thread will die - no need for threadKillRelease() */
	xbee_threadStopRelease(xbee, info->serverThread);
	shutdown(info->fd, SHUT_RDWR);
	xsys_close(info->fd);
	
	xbee_ll_free(info->clientList, (void(*)(void*))xbee_netClientShutdown);
	
	while (xbee_ll_ext_head(netDeadClientList, (void**)&deadClient) == XBEE_ENONE && deadClient != NULL) {
		xbee_netClientShutdown(deadClient);
	}
	
	free(info);

	return XBEE_ENONE;
}

#endif /* XBEE_NO_NET_SERVER */
