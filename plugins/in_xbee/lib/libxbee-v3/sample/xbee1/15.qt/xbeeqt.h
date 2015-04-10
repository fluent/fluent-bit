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

#ifndef __XBEE_QT_H
#define __XBEE_QT_H

#ifndef __cplusplus
#warning This header file is intended for use with C++
#else

#include <QObject>
#include <xbeep.h>

namespace libxbee {
	class ConQt: public QObject, public libxbee::ConCallback {
		Q_OBJECT

		public:
			explicit ConQt(XBee &parent, std::string type, struct xbee_conAddress *address = NULL);

		signals:
			void Rx(libxbee::Pkt *pkt); /* <-- you should connect to this one */

		private:
			virtual void xbee_conCallback(Pkt **pkt);
	};
};

#endif /* __cplusplus */

#endif /* __XBEE_QT_H */
