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

#include "internal.h"

EXPORT const char *xbee_errorToStr(xbee_err error) {
	char *str = "Unknown error...";
	
	switch (error) {
		case XBEE_ENONE:
			str = "No error";
			break;
		case XBEE_EUNKNOWN:
		default:
			str = "Unknown error...";
			break;
			
		case XBEE_ENOMEM:
			str = "Out of memory";
			break;
			
		case XBEE_ESELECT:
			str = "select() failed";
			break;
		case XBEE_ESELECTINTERRUPTED:
			str = "select() was interrupted";
			break;
			
		case XBEE_EEOF:
			str = "An EOF character was read";
			break;
		case XBEE_EIO:
			str = "An I/O request failed";
			break;
			
		case XBEE_ESEMAPHORE:
			str = "A semaphore error occured";
			break;
		case XBEE_EMUTEX:
			str = "A mutex error occured";
			break;
		case XBEE_ETHREAD:
			str = "A pthread error occured";
			break;
		case XBEE_ELINKEDLIST:
			str = "A linkedlist error occured";
			break;
			
		case XBEE_ESETUP:
			str = "Setup failed";
			break;
		case XBEE_EMISSINGPARAM:
			str = "A crucial parameter was missing";
			break;
		case XBEE_EINVAL:
			str = "An invalid argument was provided";
			break;
		case XBEE_ERANGE:
			str = "Requested data falls outside the boundaries";
			break;
		case XBEE_ELENGTH:
			str = "A length mis-match occured";
			break;
			
		case XBEE_EFAILED:
			str = "A function call failed";
			break;
		case XBEE_ETIMEOUT:
			str = "A timeout occured";
			break;
		case XBEE_EWOULDBLOCK:
			str = "The call would block, but something is marked 'non-blocking'";
			break;
		case XBEE_EINUSE:
			str = "A the item request is currently in use";
			break;
			
		case XBEE_EEXISTS:
			str = "An item already exists by that name or identifier";
			break;
		case XBEE_ENOTEXISTS:
			str = "The requested item does not exist";
			break;
		case XBEE_ENOFREEFRAMEID:
			str = "There is currently no free frame ID that can be used for the request";
			break;
			
		case XBEE_ESTALE:
			str = "Stale information was used during this function call";
			break;
		case XBEE_ENOTIMPLEMENTED:
			str = "The called functionality has not yet been implemented";
			break;
			
		case XBEE_ETX:
			str = "Transmission failed (check the retVal)";
			break;
			
		case XBEE_EREMOTE:
			str = "An error occured on the remote host, or an error was encountered while communicating with the remote host";
			break;
			
		case XBEE_ESLEEPING:
			str = "The given connection is not currently awake";
			break;
		case XBEE_ECATCHALL:
			str = "The given connection is a catch-all connection";
			break;
	}
	
	return str;
}
