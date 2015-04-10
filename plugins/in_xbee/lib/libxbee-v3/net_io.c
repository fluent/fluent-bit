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

/* this file is used by the network client... so is not masked out by XBEE_NO_NET_SERVER */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "internal.h"
#include "xbee_int.h"
#include "mode.h"
#include "net.h"
#include "net_io.h"
#include "thread.h"
#include "ll.h"

/* for the dual-purpose-ness */
#include "modes/net/mode.h"

/* ######################################################################### */

xbee_err xbee_netRx(struct xbee *xbee, void *arg, struct xbee_tbuf **buf) {
	char c;
	char length[2];
	int pos, len, ret;
	struct xbee_tbuf *iBuf;
	int fd;
	
	if (!xbee || !buf) return XBEE_EMISSINGPARAM;
	
	if (arg) {
		/* this is on the server end */
		struct xbee_netClientInfo *info;
		info = arg;
		if (xbee != info->xbee) return XBEE_EINVAL;
		fd = info->fd;
	} else {
		/* this is on the client end */
		struct xbee_modeData *info;
		info = xbee->modeData;
		fd = info->netInfo.fd;
	}
	
	while (1) {
		do {
			if ((ret = recv(fd, &c, 1, MSG_NOSIGNAL)) < 0) return XBEE_EIO;
			if (ret == 0) goto eof;
		} while (c != 0x7E);
		
		for (len = 2, pos = 0; pos < len; pos += ret) {
			ret = recv(fd, &(length[pos]), len - pos, MSG_NOSIGNAL);
			if (ret > 0) continue;
			if (ret == 0) goto eof;
			return XBEE_EIO;
		}
		
		len = (((length[0] << 8) & 0xFF00) | (length[1] & 0xFF)) + 1;
		if ((iBuf = malloc(sizeof(*iBuf) + len)) == NULL) return XBEE_ENOMEM;
		xbee_ll_add_tail(needsFree, iBuf);
		
		iBuf->len = len;

		memset(&iBuf->ts, 0, sizeof(iBuf->ts));
		
		for (pos = 0; pos < iBuf->len; pos += ret) {
			ret = recv(fd, &(iBuf->data[pos]), iBuf->len - pos, MSG_NOSIGNAL);
			if (ret > 0) continue;
			xbee_ll_ext_item(needsFree, iBuf);
			free(iBuf);
			if (ret == 0) goto eof;
			return XBEE_EIO;
		}
		break;
	}
	
	/* needs free is handled for us by xbee_rxHandler(), we just need to register it */
	*buf = iBuf;
	
	return XBEE_ENONE;
eof:
	if (arg) {
		struct xbee_netClientInfo *info;
		struct xbee_netClientInfo *deadClient;
		struct xbee_con *con;
		info = arg;
		
		/* tidy up any dead clients - not including us */
		while (xbee_ll_ext_head(netDeadClientList, (void**)&deadClient) == XBEE_ENONE && deadClient != NULL) {
			xbee_netClientShutdown(deadClient);
		}

		/* xbee_netRx() is responsible for free()ing memory and killing off client threads on the server
		   to do this, we need to add ourselves to the netDeadClientList, and remove ourselves from the clientList
		   the server thread will then cleanup any clients on the next accept() */
		xbee_ll_add_tail(netDeadClientList, arg);
		xbee_ll_ext_item(xbee->netInfo->clientList, arg);
		
		/* kill the other threads */
		/* excluding the rx thread... thats us! */
		if (info->rxHandlerThread) {
			xbee_threadKillJoin(info->xbee, info->rxHandlerThread, NULL);
			info->rxHandlerThread = NULL;
		}
		if (info->txThread) {
			xbee_threadKillJoin(info->xbee, info->txThread, NULL);
			info->txThread = NULL;
		}

		/* close up the socket */
		shutdown(info->fd, SHUT_RDWR);
		xsys_close(info->fd);
		info->fd = -1; /* <-- mark it closed */

		/* end all of our connections */
		for (con = NULL; xbee_ll_ext_head(info->conList, (void **)&con) == XBEE_ENONE && con; ) {
			xbee_conEnd(con);
		}
		
		/* this leaves us with a call to xbee_threadKillJoin() and xbee_netClientFree() left! */
	}
	return XBEE_EEOF;
}

xbee_err xbee_netTx(struct xbee *xbee, void *arg, struct xbee_sbuf *buf) {
	int pos, ret;
	int fd;
	size_t txSize;
	size_t memSize;
	struct xbee_buf *iBuf;

	size_t *txBufSize;
	struct xbee_buf **txBuf;
	
	if (!xbee || !buf) return XBEE_EMISSINGPARAM;
	
	if (arg) {
		/* this is on the server end */
		struct xbee_netClientInfo *info;
		info = arg;
		if (xbee != info->xbee) return XBEE_EINVAL;
		fd = info->fd;

		txBufSize = &info->txBufSize;
		txBuf = &info->txBuf;
	} else {
		/* this is on the client end */
		struct xbee_modeData *info;
		info = xbee->modeData;
		fd = info->netInfo.fd;

		txBufSize = &info->netInfo.txBufSize;
		txBuf = &info->netInfo.txBuf;
	}
	
	txSize = 3 + buf->len;
	memSize = txSize + sizeof(*iBuf);
	
	iBuf = *txBuf;
	if (!iBuf || *txBufSize < memSize) {
		void *p;
		
		/* make sure we save this buffer... */
		xbee_ll_lock(needsFree);
		if ((p = realloc(iBuf, memSize)) == NULL) {
			xbee_ll_unlock(needsFree);
			return XBEE_ENOMEM;
		}
		if (iBuf) _xbee_ll_ext_item(needsFree, iBuf, 0);
		_xbee_ll_add_tail(needsFree, p, 0);
		xbee_ll_unlock(needsFree);
		iBuf = p;
		
		*txBuf = iBuf;
		*txBufSize = memSize;
	}
	
	iBuf->len = txSize;
	iBuf->data[0] = 0x7E;
	iBuf->data[1] = ((buf->len - 1) >> 8) & 0xFF;
	iBuf->data[2] = ((buf->len - 1)     ) & 0xFF;
	memcpy(&(iBuf->data[3]), buf->data, buf->len);
	
	for (pos = 0; pos < iBuf->len; pos += ret) {
		ret = send(fd, iBuf->data, iBuf->len - pos, MSG_NOSIGNAL);
		if (ret >= 0) continue;
		return XBEE_EIO;
	}
	
	return XBEE_ENONE;
}
