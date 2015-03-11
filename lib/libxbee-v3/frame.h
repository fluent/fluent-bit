#ifndef __XBEE_FRAME_H
#define __XBEE_FRAME_H

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

struct xbee_frameInfo {
	char active;
	unsigned char id;
	int retVal;
};

#define XBEE_FRAME_STATUS_SCHEDULED 0x01
#define XBEE_FRAME_STATUS_WAITING   0x02
#define XBEE_FRAME_STATUS_COMPLETE  0x04
#define XBEE_FRAME_STATUS_ABANDONED 0x08

struct xbee_frame {
	xsys_sem sem;
	struct xbee_con *con;
	unsigned char id;
	unsigned char retVal;
	unsigned char status; /* this used the XBEE_FRAME_STATUS_* bitfield - zero means unused */
};

struct xbee_frameBlock {
	xsys_mutex mutex;
	int numFrames;
	int lastFrame;
	struct xbee_frame frame[0x100]; /* 0x00 - 0xFF */
};

xbee_err xbee_frameBlockAlloc(struct xbee_frameBlock **nfBlock);
xbee_err xbee_frameBlockFree(struct xbee_frameBlock *fBlock);

xbee_err xbee_frameGetFreeID(struct xbee_frameBlock *fBlock, struct xbee_con *con, char abandon);
xbee_err xbee_frameWait(struct xbee_frameBlock *fBlock, struct xbee_con *con, unsigned char *retVal, struct timespec *timeout);
xbee_err xbee_framePost(struct xbee_frameBlock *fBlock, unsigned char frameId, unsigned char retVal);

#endif /* __XBEE_FRAME_H */
