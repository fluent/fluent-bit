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
#include <ctype.h>

#include "../../internal.h"
#include "../../xbee_int.h"
#include "../../log.h"
#include "../../mode.h"
#include "../../frame.h"
#include "../../pkt.h"
#include "../common.h"
#include "mode.h"

static xbee_err init(struct xbee *xbee, va_list ap);

/* this is naughty, but fun :) */
extern const struct xbee_mode * const modeList[];

/* ######################################################################### */

static xbee_err init(struct xbee *xbee, va_list ap) {
	xbee_err ret;
	char *target;
	int i;
	struct xbee_modeData *data;
	
	if (!xbee) return XBEE_EMISSINGPARAM;
	
	if ((target = va_arg(ap, char *)) == NULL) return XBEE_EMISSINGPARAM;
	/* check that the mode argument is reasonable... (length) */
	for (i = 0; i < 256; i++) {
		if (target[i] == '\0') break;
	}
	if (i == 0 || target[i] != '\0') return XBEE_EINVAL;
	/* check we arent trying debug ourself... that would be silly */
	if (!strcasecmp(target, xbee->mode->name)) return XBEE_EINVAL;
	
	for (i = 0; modeList[i]; i++) {
		if (!modeList[i]->name) continue;
		if (strcasecmp(modeList[i]->name, target)) continue;
		break;
	}
	if (modeList[i] == NULL) return XBEE_EINVAL;
	if (modeList[i]->conTypes == NULL) return XBEE_EINVAL;
	
	if ((data = malloc(sizeof(*data))) == NULL) return XBEE_ENOMEM;
	memset(data, 0, sizeof(*data));
	
	data->mode = modeList[i];
	data->modeName = target;
	
	/* import that mode's connection types! */
	for (i = 0; data->mode->conTypes[i]; i++) {
		fprintf(stderr, "Importing conType '%s'\n", data->mode->conTypes[i]->name);
		if ((ret = xbee_modeAddConType(&xbee->iface.conTypes, data->mode->conTypes[i])) != XBEE_ENONE) goto die;
	}
	
	xbee->modeData = data;
	return XBEE_ENONE;
die:
	free(data);
	return ret;
}

/* ######################################################################### */

xbee_err xbee_debugRxIo(struct xbee *xbee, void *arg, struct xbee_tbuf **buf) {
	for (;;) {
		sleep(60*60*24);
	}
}

xbee_err xbee_debugTxIo(struct xbee *xbee, void *arg, struct xbee_sbuf *buf) {
	int i;
	fprintf(stderr,   "------ Packet Tx: ------\n");
	for (i = 0; i < buf->len; i++) {
		fprintf(stderr, " data[%3d]: 0x%02X", i, buf->data[i]);
		if (isprint(buf->data[i])) {
		  fprintf(stderr, " -> '%c'", buf->data[i]);
		}
		fprintf(stderr, "\n");
	}
	fprintf(stderr,   "========================\n");
	return XBEE_ENONE;
}

/* ######################################################################### */

const struct xbee_mode mode_debug = {
	.name = "debug",
	
	.conTypes = NULL,
	
	.init = init,
	.prepare = NULL,
	.shutdown = NULL,
	
	.rx_io = xbee_debugRxIo,
	.tx_io = xbee_debugTxIo,
	
	.thread = NULL,
};

