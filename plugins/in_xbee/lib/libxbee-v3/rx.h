#ifndef __XBEE_RX_H
#define __XBEE_RX_H

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

struct xbee_rxInfo {
	char logColor;
	struct xbee_ll_head *bufList;
	xsys_sem sem;
	void *ioArg;
	xbee_err (*ioFunc)(struct xbee *xbee, void *arg, struct xbee_tbuf **buf);
	xbee_t_eofCallback eofCallback;
	void *handlerArg;
	struct xbee_frameBlock *fBlock;
	struct xbee_modeConType **conTypes;
};

xbee_err xbee_rxAlloc(struct xbee_rxInfo **nInfo);
xbee_err xbee_rxFree(struct xbee_rxInfo *info);

xbee_err xbee_rx(struct xbee *xbee, int *restart, void *arg);
xbee_err xbee_rxHandler(struct xbee *xbee, int *restart, void *arg);

#endif /* __XBEE_RX_H */
