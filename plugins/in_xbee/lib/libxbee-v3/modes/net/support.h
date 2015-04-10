#ifndef __XBEE_MODE_SUPPORT_H
#define __XBEE_MODE_SUPPORT_H

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

xbee_err xbee_netSupport_conNew(struct xbee *xbee, struct xbee_interface *interface, struct xbee_modeConType *conType, struct xbee_conAddress *address, int *conIdentifier);
xbee_err xbee_netSupport_conValidate(struct xbee_con *con);
xbee_err xbee_netSupport_conSleepSet(struct xbee_con *con, enum xbee_conSleepStates state);
xbee_err xbee_netSupport_conSleepGet(struct xbee_con *con);
xbee_err xbee_netSupport_conSettings(struct xbee_con *con, struct xbee_conSettings *newSettings);
xbee_err xbee_netSupport_conEnd(struct xbee_con *con);

#endif /* __XBEE_MODE_SUPPORT_H */

