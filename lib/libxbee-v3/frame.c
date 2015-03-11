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
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with libxbee. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "internal.h"
#include "frame.h"
#include "conn.h"
#include "ll.h"
#include "log.h"

/* ########################################################################## */

xbee_err xbee_frameBlockAlloc(struct xbee_frameBlock **nfBlock) {
	size_t memSize;
	struct xbee_frameBlock *fBlock;
	int i;
	
	if (!nfBlock) return XBEE_EMISSINGPARAM;
	
	memSize = sizeof(*fBlock);
	
	if (!(fBlock = malloc(memSize))) return XBEE_ENOMEM;
	
	memset(fBlock, 0, memSize);
	xsys_mutex_init(&fBlock->mutex);
	fBlock->numFrames = sizeof(fBlock->frame) / sizeof(fBlock->frame[0]);
	for (i = 0; i < fBlock->numFrames; i++) {
		fBlock->frame[i].id = i;
		xsys_sem_init(&fBlock->frame[i].sem);
	}
	
	*nfBlock = fBlock;
	
	return XBEE_ENONE;
}

xbee_err xbee_frameBlockFree(struct xbee_frameBlock *fBlock) {
	int i;
	if (!fBlock) return XBEE_EMISSINGPARAM;
	
	for (i = 0; i < fBlock->numFrames; i++) {
		xsys_sem_destroy(&fBlock->frame[i].sem);
	}
	xsys_mutex_destroy(&fBlock->mutex);
	
	free(fBlock);
	
	return XBEE_ENONE;
}

/* ########################################################################## */

xbee_err xbee_frameGetFreeID(struct xbee_frameBlock *fBlock, struct xbee_con *con, char abandon) {
	xbee_err ret;
	int i, o;
	
	if (!fBlock || !con) return XBEE_EMISSINGPARAM;
	ret = XBEE_EFAILED;
	
	xbee_mutex_lock(&fBlock->mutex);
	for (i = 0, o = fBlock->lastFrame + 1; i < fBlock->numFrames; i++, o++) {
		o %= fBlock->numFrames;
		if (o == 0) continue; /* skip '0x00', this indicates that no ACK is requested */
		if (fBlock->frame[o].status) continue;
		
		fBlock->lastFrame = o;
		fBlock->frame[o].status = XBEE_FRAME_STATUS_SCHEDULED;
		if (abandon) {
			fBlock->frame[o].status |= XBEE_FRAME_STATUS_ABANDONED;
		} else {
			fBlock->frame[o].con = con;
		}
		con->frameId = fBlock->frame[o].id;
		ret = XBEE_ENONE;
		break;
	}
	xbee_mutex_unlock(&fBlock->mutex);
	
	return ret;
}

xbee_err xbee_frameWait(struct xbee_frameBlock *fBlock, struct xbee_con *con, unsigned char *retVal, struct timespec *timeout) {
	xbee_err ret;
	struct xbee_frame *frame;
	int i, o;
	
	if (!fBlock || !con) return XBEE_EMISSINGPARAM;

	ret = XBEE_EINVAL;
	xbee_mutex_lock(&fBlock->mutex);
	frame = NULL;
	for (i = 0, o = fBlock->lastFrame; i < fBlock->numFrames; i++, o--) {
		if (o < 0) o = fBlock->numFrames - 1;
		if (fBlock->frame[o].id != con->frameId) continue;

		if (fBlock->frame[o].status == 0 || fBlock->frame[o].con != con) {
			ret = XBEE_ESTALE;
		} else {
			frame = &fBlock->frame[o];
			frame->status |= XBEE_FRAME_STATUS_WAITING;
		}
		break;
	}
	xbee_mutex_unlock(&fBlock->mutex);
	if (!frame) return ret;

	ret = XBEE_ENONE;
	if (timeout) {
		if (xsys_sem_timedwait(&frame->sem, timeout)) {
			if (errno == ETIMEDOUT) {
				ret = XBEE_ETIMEOUT;
			} else {
				ret = XBEE_ESEMAPHORE;
			}
		}
	} else {
		if (xsys_sem_wait(&frame->sem)) {
			ret = XBEE_ESEMAPHORE;
		}
	}
	
	xbee_mutex_lock(&fBlock->mutex);
	con->frameId = 0;
	frame->con = NULL;
	if (frame->status & XBEE_FRAME_STATUS_COMPLETE && ret == XBEE_ENONE) {
		if (retVal) *retVal = frame->retVal;
		frame->status = 0;
	} else {
		frame->status &= ~XBEE_FRAME_STATUS_WAITING;
	}
	xbee_mutex_unlock(&fBlock->mutex);
	
	return ret;
}

xbee_err xbee_framePost(struct xbee_frameBlock *fBlock, unsigned char frameId, unsigned char retVal) {
	xbee_err ret;
	struct xbee_frame *frame;
	int i;
	
	if (!fBlock) return XBEE_EMISSINGPARAM;
	if (frameId == 0) return XBEE_ENONE;
	
	xbee_mutex_lock(&fBlock->mutex);

	frame = NULL;
	for (i = 0; i < fBlock->numFrames; i++) {
		if (fBlock->frame[i].id != frameId) continue;

		if (fBlock->frame[i].status != 0) {
			frame = &fBlock->frame[i];
		}
		
		break;
	}

	if (!frame) {
		ret = XBEE_EINVAL;
	} else if (frame->con && (frame->status & XBEE_FRAME_STATUS_WAITING)) {
		ret = XBEE_ENONE;
		frame->status |= XBEE_FRAME_STATUS_COMPLETE;
		frame->retVal = retVal;
		xsys_sem_post(&frame->sem);
	} else {
		if (!(frame->status & XBEE_FRAME_STATUS_ABANDONED)) {
			ret = XBEE_ETIMEOUT;
		}
		if (frame->con) {
			frame->con->frameId = 0;
			frame->con = NULL;
		}
		frame->status = 0;
	}

	xbee_mutex_unlock(&fBlock->mutex);
	
	return ret;
}
