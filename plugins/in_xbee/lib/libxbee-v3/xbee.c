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

#include "internal.h"
#include "xbee_int.h"
#include "conn.h"
#include "frame.h"
#include "thread.h"
#include "log.h"
#include "mode.h"
#include "rx.h"
#include "tx.h"
#include "net.h"
#include "ll.h"

struct xbee_ll_head *xbeeList = NULL;
struct xbee_ll_head *needsFree = NULL;

EXPORT void xbee_freeMemory(void *ptr) {
	/* because the windows memory model is stupid, memory that is allocated from within
	   the DLL, must also be free'd from within the DLL */
	free(ptr);
}

/* ######################################################################### */

EXPORT xbee_err xbee_validate(struct xbee *xbee) {
	if (xbee_ll_get_item(xbeeList, xbee) != XBEE_ENONE) return XBEE_EINVAL;
	return XBEE_ENONE;
}

/* ######################################################################### */

xbee_err xbee_alloc(struct xbee **nXbee) {
	size_t memSize;
	struct xbee *xbee;
	char *e;
	int logLevel;
	xbee_err ret;
	
	if (!nXbee) return XBEE_EMISSINGPARAM;

	memSize = sizeof(*xbee);

#ifdef XBEE_LOG_LEVEL
	logLevel = XBEE_LOG_LEVEL;
#else
	logLevel = 0;
#endif

	if ((e = getenv("XBEE_LOG_LEVEL")) != NULL) {
		int l;
		if (sscanf(e, "%d", &l) != 1) {
			fprintf(stderr, "libxbee: Failed to initialize log level from environment (not a number)\n");
		} else {
			logLevel = l;
		}
	}
	
	if (!(xbee = malloc(memSize))) return XBEE_ENOMEM;
	
	memset(xbee, 0, memSize);
	if ((ret = xbee_frameBlockAlloc(&xbee->fBlock)) != XBEE_ENONE)         goto die1;
	if ((ret = xbee_logAlloc(&xbee->log, logLevel, stderr)) != XBEE_ENONE) goto die1;
	if ((ret = xbee_txAlloc(&xbee->iface.tx)) != XBEE_ENONE)                     goto die1;
	if ((ret = xbee_rxAlloc(&xbee->iface.rx)) != XBEE_ENONE)                     goto die1;
	
	if ((ret = xbee_ll_add_tail(xbeeList, xbee)) != XBEE_ENONE)                 goto die1;
	
	*nXbee = xbee;
	
	return XBEE_ENONE;
	
die1:
	xbee_free(xbee);
	return ret;
}

xbee_err xbee_free(struct xbee *xbee) {
	int i;

	xbee_ll_ext_item(xbeeList, xbee);
	xbee->die = 1;
	
	if (xbee->iface.rx) {
		xsys_sem_post(&xbee->iface.rx->sem);
	}
	if (xbee->iface.tx) {
		xsys_sem_post(&xbee->iface.tx->sem);
	}
	
	/* sleep for 4 seconds because:
	     the rx thread should timeout every 2-ish econds
	     the rxHandler thread will need to run round one more time to clean up
	     the tx thread will need to run round one more time to clean up */
	for (i = 0; i < 4; i++) usleep(1000000);
	
	xbee_threadDestroyMine(xbee);
	
	if (xbee->netInfo) xbee_netStop(xbee);
	
	if (xbee->mode && xbee->mode->shutdown) xbee->mode->shutdown(xbee);
	
	xbee_modeCleanup(xbee->iface.conTypes);
	xbee_rxFree(xbee->iface.rx);
	xbee_txFree(xbee->iface.tx);
	xbee_logFree(xbee->log);
	xbee_frameBlockFree(xbee->fBlock);
	
	free(xbee);
	
	return XBEE_ENONE;
}

/* ######################################################################### */

EXPORT xbee_err xbee_vsetup(struct xbee **retXbee, const char *mode, va_list ap) {
	xbee_err ret;
	const struct xbee_mode *xbeeMode;
	struct xbee *xbee;
	
	if (!retXbee || !mode) return XBEE_EMISSINGPARAM;
	
	if ((ret = xbee_modeRetrieve(mode, &xbeeMode)) != XBEE_ENONE) return ret;
	
	if ((ret = xbee_alloc(&xbee)) != XBEE_ENONE) return ret;
	
	if ((ret = xbee_modeImport(&xbee->iface.conTypes, xbeeMode)) != XBEE_ENONE) goto die;
	xbee->mode = xbeeMode;
	
	xbee->iface.rx->ioFunc = xbee->mode->rx_io;
	xbee->iface.rx->fBlock = xbee->fBlock;
	xbee->iface.rx->conTypes = &xbee->iface.conTypes;
	
	xbee->iface.tx->ioFunc = xbee->mode->tx_io;
	
	if ((ret = xbee->mode->init(xbee, ap)) != XBEE_ENONE) goto die;
	
	if ((ret = xbee_threadStart(xbee, NULL, 150000, 0, xbee_rx, xbee->iface.rx)) != XBEE_ENONE)                                goto die;
	if ((ret = xbee_threadStart(xbee, NULL, 150000, 0, xbee_rxHandler, xbee->iface.rx)) != XBEE_ENONE)                         goto die;
	if ((ret = xbee_threadStart(xbee, NULL, 150000, 0, xbee_tx, xbee->iface.tx)) != XBEE_ENONE)                                goto die;
	
	if (xbee->mode->prepare) if ((ret = xbee->mode->prepare(xbee)) != XBEE_ENONE)                                              goto die;
	
	if (xbee->mode->thread) if ((ret = xbee_threadStart(xbee, NULL, 150000, 0, xbee->mode->thread, NULL)) != XBEE_ENONE)       goto die;
	
	xbee_ll_add_tail(xbeeList, xbee);
	
	*retXbee = xbee;
	
	return XBEE_ENONE;

die:
	xbee_free(xbee);
	return ret;
}
EXPORT xbee_err xbee_setup(struct xbee **retXbee, const char *mode, ...) {
	xbee_err ret;
	va_list ap;
	
	va_start(ap, mode);
	ret = xbee_vsetup(retXbee, mode, ap);
	va_end(ap);
	
	return ret;
}

xbee_err xbee_shutdownThread(struct xbee *xbee, int *restart, void *arg) {
	/* detach the thread that called shutdown(), dont care on failure (it may well be the initial thread) */
	xsys_thread_detach((xsys_thread)arg);
	xbee_free(xbee);
	*restart = -1;
	return XBEE_ENONE;
}

EXPORT xbee_err xbee_shutdown(struct xbee *xbee) {
	if (!xbee) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_validate(xbee) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */

	/* pluck out the instance - from now on it is invalid */
	xbee_ll_ext_item(xbeeList, xbee);
	/* start a detached thread */
	xbee_threadStart(xbee, NULL, -1, 1, xbee_shutdownThread, (void*)(xsys_thread_self()));
	
	return XBEE_ENONE;
}

EXPORT xbee_err xbee_attachEOFCallback(struct xbee *xbee, xbee_t_eofCallback eofCallback) {
      if (!xbee || !eofCallback) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
      if (xbee_validate(xbee) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
      if (xbee->iface.rx->eofCallback) return XBEE_EINUSE;
      xbee->iface.rx->eofCallback = eofCallback;
      return XBEE_ENONE;
}

EXPORT xbee_err xbee_dataSet(struct xbee *xbee, void *newData, void **oldData) {
	if (!xbee) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_validate(xbee) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	if (oldData) *oldData = xbee->userData;
	xbee->userData = newData;
	return XBEE_ENONE;
}

EXPORT xbee_err xbee_dataGet(struct xbee *xbee, void **curData) {
	if (!xbee || !curData) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_validate(xbee) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	*curData = xbee->userData;
	return XBEE_ENONE;
}
