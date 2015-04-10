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
#include <stdarg.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "../../internal.h"
#include "../../xbee_int.h"
#include "../../log.h"
#include "mode.h"
#include "net.h"

xbee_err xbee_netSetup(struct xbee_modeNetInfo *info) {
	xbee_err ret;
	char rport[7];
	struct addrinfo *rinfo;
	struct addrinfo hints;
	
	if (!info) return XBEE_EMISSINGPARAM;
	
	if (info->host == NULL) return XBEE_EINVAL;
	if (info->port < 0 || info->port > 65535) return XBEE_EINVAL;
	
	info->fd = -1;
	info->f = NULL;
	
	snprintf(rport, sizeof(rport), "%d", info->port);
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if ((ret = getaddrinfo(info->host, rport, &hints, &rinfo)) != 0) return XBEE_EIO;
	
	if ((info->fd = socket(rinfo->ai_family, rinfo->ai_socktype, rinfo->ai_protocol)) == -1) goto die;
	
	if (connect(info->fd, rinfo->ai_addr, rinfo->ai_addrlen) == -1) goto die;
	
	if ((info->f = xsys_fdopen(info->fd, "r+")) == NULL) goto die;
	
	xsys_fflush(info->f);
	setvbuf(info->f, NULL, _IONBF, BUFSIZ);
	
	ret = XBEE_ENONE;
	goto done;
die:
	ret = XBEE_EIO;
done:
	freeaddrinfo(rinfo);
	return ret;
}
