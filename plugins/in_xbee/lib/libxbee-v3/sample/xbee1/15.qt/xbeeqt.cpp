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

#include "xbeeqt.h"

libxbee::ConQt::ConQt(libxbee::XBee &parent, std::string type, struct xbee_conAddress *address): QObject(0), ConCallback(parent, type, address) {
	/* nothing */
}
void libxbee::ConQt::xbee_conCallback(libxbee::Pkt **pkt) {
	libxbee::Pkt *kept_pkt = *pkt;
	*pkt = NULL;

	emit Rx(kept_pkt);
}
