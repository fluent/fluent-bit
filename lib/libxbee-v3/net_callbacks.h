#ifndef __XBEE_NET_CALLBACKS_H
#define __XBEE_NET_CALLBACKS_H

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

#ifndef XBEE_NO_NET_SERVER

struct xbee_netCallback {
	const char *name;
	const xbee_t_conCallback callback;
};

void xbee_net_start(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data);
extern const struct xbee_netCallback xbee_netServerCallbacks[];

#endif /* XBEE_NO_NET_SERVER */

#endif /* __XBEE_NET_CALLBACKS_H */
