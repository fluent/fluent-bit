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
#include <string.h>

#include "internal.h"
#include "rx.h"
#include "xbee_int.h"
#include "mode.h"
#include "frame.h"
#include "conn.h"
#include "log.h"
#include "ll.h"

xbee_err xbee_rxAlloc(struct xbee_rxInfo **nInfo) {
	static char logColor = 1;
	size_t memSize;
	struct xbee_rxInfo *info;
	
	if (!nInfo) return XBEE_EMISSINGPARAM;
	
	memSize = sizeof(*info);
	
	if (!(info = malloc(memSize))) return XBEE_ENOMEM;
	
	memset(info, 0, memSize);
	info->bufList = xbee_ll_alloc();
	xsys_sem_init(&info->sem);
	
	/* give it a log color */
	info->logColor = logColor;
	if (logColor++ > 7) logColor = 7;
	
	*nInfo = info;
	
	return XBEE_ENONE;
}

xbee_err xbee_rxFree(struct xbee_rxInfo *info) {
	if (!info) return XBEE_EMISSINGPARAM;
	
	xbee_ll_free(info->bufList, (void(*)(void*))xbee_pktFree);
	xsys_sem_destroy(&info->sem);
	free(info);
	
	return XBEE_ENONE;
}

/* ######################################################################### */

xbee_err xbee_rx(struct xbee *xbee, int *restart, void *arg) {
	xbee_err ret;
	struct xbee_rxInfo *info;
	struct xbee_tbuf *buf;
	
	info = arg;
	if (!info->bufList || !info->ioFunc) {
		*restart = 0;
		return XBEE_EINVAL;
	}
	
	while (!xbee->die) {
		buf = NULL;
		if ((ret = info->ioFunc(xbee, info->ioArg, &buf)) != XBEE_ENONE) {
			if (ret == XBEE_EEOF) {
				*restart = 0;
				if (info->eofCallback) info->eofCallback(xbee, info);
				return XBEE_EEOF;
			} else if (ret == XBEE_ESHUTDOWN && xbee->die) {
				break;
			}
			xbee_log(1, "rx() returned %d (%s)... retrying in 10 ms", ret, xbee_errorToStr(ret));
			usleep(10000); /* 10 ms */
			continue;
		}
		
#ifdef XBEE_LOG_RX
		{
			/* format: tx[0x0000000000000000] */
#ifdef XBEE_LOG_NO_COLOR
			char label[23]; /* enough space for a 64-bit pointer */
			snprintf(label, sizeof(label), "Rx[%p]", info);
#else
			char label[42]; /* enough space for a 64-bit pointer and ANSI color codes */
			snprintf(label, sizeof(label), "Rx[%c[%dm%p%c[0m]", 27, 30 + info->logColor, info,  27);
#endif
			xbee_logData(25, label, buf->data, buf->len);
		}
#endif /* XBEE_LOG_RX */
		
		if (xbee_ll_add_tail(info->bufList, buf) != XBEE_ENONE) return XBEE_ELINKEDLIST;
		buf = NULL;
		if (xsys_sem_post(&info->sem) != 0) return XBEE_ESEMAPHORE;
	}
	
	return XBEE_ESHUTDOWN;
}

/* ######################################################################### */

xbee_err xbee_rxHandler(struct xbee *xbee, int *restart, void *arg) {
	xbee_err ret;
	struct xbee_rxInfo *info;
	struct xbee_tbuf *buf;
	
	struct xbee_modeConType *conType;
	
	struct xbee_frameInfo frameInfo;
	struct xbee_conAddress address;
	struct xbee_pkt *pkt;
	
	struct xbee_con *con;
	
	ret = XBEE_ENONE;
	info = arg;
	buf = NULL;
	
	if (!info->bufList) {
		*restart = 0;
		return XBEE_EINVAL;
	}
	
	memset(&frameInfo, 0, sizeof(frameInfo));
	conType = NULL;
	while (!xbee->die) {
		/* this is here so that it will be triggered AFTER the packet has been queued (assuming a packet needed to be queued)
		   handle any frame info (prod someone who may be waiting for ACK/NAK/etc...) */
		if (info->fBlock && frameInfo.active != 0 && conType && conType->allowFrameId != 0) {
			xbee_log(20, "received Tx status (block: %p, frame: 0x%02X, status: 0x%02X)", info->fBlock, frameInfo.id, frameInfo.retVal);
			if ((ret = xbee_framePost(info->fBlock, frameInfo.id, frameInfo.retVal)) != XBEE_ENONE) {
				xbee_log(2, "failed to respond to frame (block: %p, frame: 0x%02X)... xbee_framePost() returned %d", info->fBlock, frameInfo.id, ret);
				ret = XBEE_ENONE;
			}
		}
		
		xsys_sem_wait(&info->sem);
		
		/* get the next buffer */
		if ((ret = xbee_ll_ext_head(info->bufList, (void**)&buf)) != XBEE_ENONE && ret != XBEE_ERANGE) return XBEE_ELINKEDLIST;
		ret = XBEE_ENONE;
		if (!buf) continue;
		
		/* check we actually have some data to work with... */
		if (buf->len < 1) goto done;
		
		/* locate the connection type of this buffer */
		if ((ret = xbee_modeLocateConType(*info->conTypes, 1, NULL, &buf->data[0], NULL, &conType)) == XBEE_ENOTEXISTS || !conType) {
			xbee_log(4, "Unknown message type recieved... (0x%02X)", buf->data[0]);
			goto done;
		} else if (ret != XBEE_ENONE) {
			/* some other error occured */
			break;
		}
		
		/* prepare the buckets */
		memset(&frameInfo, 0, sizeof(frameInfo));
		memset(&address, 0, sizeof(address));
		pkt = NULL;
		
		/* process the buffer into the buckets */
		if ((ret = conType->rxHandler->func(xbee, info->handlerArg, conType->rxHandler->identifier, buf, &frameInfo, &address, &pkt)) != XBEE_ENONE) break;
		
		/* its possible that the buffer ONLY contained frame information... if so, were done! */
		if (!pkt) goto done;
		
		memcpy(&pkt->address, &address, sizeof(address));
		pkt->conType = conType->name;
		
		if (info->fBlock && frameInfo.active != 0 && conType && conType->allowFrameId != 0) {
			pkt->frameId = frameInfo.id;
		}

		/* if the packet handler didn't fill in the timestamp, then we should do it here */
		if (pkt->timestamp.tv_sec == 0 && pkt->timestamp.tv_nsec == 0) {
			memcpy(&pkt->timestamp, &buf->ts, sizeof(buf->ts));
		}
		
		xbee_log(12, "received '%s' type packet with %d bytes of data...", conType->name, pkt->dataLen);
		
		/* match the address to a connection */
		if (((ret = xbee_conLocate(conType->conList, &address, &con, CON_SNOOZE)) != XBEE_ENONE &&
		      ret != XBEE_ESLEEPING &&
		      ret != XBEE_ECATCHALL) ||
		    !con) {
			xbee_pktFree(pkt);
			if (ret == XBEE_ENOTEXISTS) {
				xbee_log(5, "connectionless '%s' packet (%d bytes)...", conType->name, buf->len);
				xbee_conLogAddress(xbee, 10, &address);
				goto done;
			}
			xbee_log(1, "xbee_conLocate() returned %d...", ret);
			break;
		}
		
		xbee_log(15, "matched packet with con @ %p", con);
		xbee_conLogAddress(xbee, 16, &address);
		
		if (conType->rxHandler->funcPost) {
			xbee_err ret;
			if ((ret = conType->rxHandler->funcPost(xbee, con, pkt)) != XBEE_ENONE) {
				xbee_log(1, "funcPost() failed for con @ %p - returned %d\n", con, ret);
			}
		}
		
		/* wake the connection if necessary */
		if (con->sleepState != CON_AWAKE) {
			con->sleepState = CON_AWAKE;
			xbee_log(1, "woke connection @ %p", con);
		}
		
		con->info.countRx++;
		con->info.lastRxTime = time(NULL);
		
		if (!con->settings.catchAll) {
			if (address.addr16_enabled && !con->address.addr16_enabled && conType->save_addr16) {
				con->address.addr16_enabled = 1;
				memcpy(con->address.addr16, address.addr16, 2);
			}
			if (address.addr64_enabled && !con->address.addr64_enabled && conType->save_addr64) {
				con->address.addr64_enabled = 1;
				memcpy(con->address.addr64, address.addr64, 8);
			}
		}
		
		/* add the packet to the connection's tail! */
		if ((ret = xbee_conLinkPacket(con, pkt)) != XBEE_ENONE) {
			xbee_log(1, "failed to store packet with connection... xbee_conLinkPacket() returned %d", ret);
			break;
		}
		
done:
		xbee_ll_ext_item(needsFree, buf);
		free(buf);
		buf = NULL;
	}
	
	if (buf) {
		xbee_ll_ext_item(needsFree, buf);
		free(buf);
	}
	
	if (xbee->die && ret == XBEE_ENONE) return XBEE_ESHUTDOWN;
	return ret;
}
