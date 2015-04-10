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
#include <string.h>

#include "internal.h"
#include "xbee_int.h"
#include "thread.h"
#include "log.h"
#include "ll.h"

struct xbee_ll_head *threadList = NULL;
xsys_thread_key threadInfoKey;

/* ########################################################################## */

EXPORT xbee_err xbee_threadValidate(struct xbee *xbee, struct xbee_threadInfo *thread) {
	if (xbee_ll_get_item(threadList, thread) != XBEE_ENONE) return XBEE_EINVAL;
	if (xbee && thread->xbee != xbee) return XBEE_EINVAL;
	return XBEE_ENONE;
}

/* ########################################################################## */

void *threadFunc(struct xbee_threadInfo *thread) {
	int restart; /* FALSE allows the thread to request that it is not restarted */
	struct xbee *xbee;
	xbee_err ret;
	
	xbee = thread->xbee;
	thread->active = 1;
	
	/* setup the thread info */
	xsys_thread_key_set(threadInfoKey, thread);
	
	if (thread->detached) {
		xsys_thread_detach_self();
	}
	
	if (thread->restartDelay < 0) {
		/* a restartDelay of < 0 indicates that the thread should not restart (by default, the thread can request that it is restarted, in which case -(thread->restartDelay) is used as the delay) */
		restart = 0;
		thread->restartDelay = -thread->restartDelay;
	} else {
		restart = 1;
	}
	
	do {
		xbee_log(15, "starting thread %p, function %s()...", thread, thread->funcName);
	
		thread->running = 1;
		ret = thread->func(thread->xbee, &restart, thread->arg);
		thread->running = 0;
		if (restart == -1) break;

		if (ret != XBEE_ENONE) {
			xbee_log(1, "thread %p, function %s() returned %d...", thread, thread->funcName, ret);
		} else {
			xbee_log(10, "thread %p, function %s() returned without error...", thread, thread->funcName, ret);
		}
		if (!restart || !thread->run) break;
		if (xbee->die) {
			xbee_log(20, "NOT restarting thread %p, function %s() - libxbee instance has been marked for death...", thread, thread->funcName);
		} else if (thread->restartDelay != 0) {
			xbee_log(20, "restarting thread %p, function %s() in %d us...", thread, thread->funcName, thread->restartDelay);
			usleep(thread->restartDelay);
		} else {
			xbee_log(20, "restarting thread %p, function %s() with zero delay...", thread, thread->funcName);
		}
	} while (thread->run && !xbee->die);
	
	thread->active = 0;
	
	if (restart != -1) xbee_log(15, "thread %p, function %s() has now ended...", thread, thread->funcName);
	
	if (thread->detached) free(thread);
	
	return (void*)ret;
}

/* ########################################################################## */

xbee_err _xbee_threadStart(struct xbee *xbee, struct xbee_threadInfo **retThread, int restartDelay, int detach, const char *funcName, xbee_err (*func)(struct xbee *xbee, int *restart, void *arg), void *arg) {
	struct xbee_threadInfo *thread;

	if (!xbee || !func) return XBEE_EMISSINGPARAM;

	if ((thread = malloc(sizeof(*thread))) == NULL) return XBEE_ENOMEM;
	memset(thread, 0, sizeof(*thread));

	thread->xbee = xbee;
	thread->funcName = funcName; /* this should be static (from the macro!) */
	thread->func = func;
	thread->arg = arg;
	thread->run = 1;
	thread->detached = detach;
	thread->restartDelay = restartDelay;
	xsys_sem_init(&thread->mutexSem);

	if ((xsys_thread_create(&thread->tid, (void*(*)(void *))threadFunc, thread)) != 0) {
		xsys_sem_destroy(&thread->mutexSem);
		free(thread);
		return XBEE_ETHREAD;
	}

	if (!detach) {
		xbee_ll_add_tail(threadList, thread);
	}
	if (retThread) *retThread = thread;

	return XBEE_ENONE;
}

/* ########################################################################## */

xbee_err xbee_threadKill(struct xbee *xbee, struct xbee_threadInfo *thread) {
	if (!xbee || !thread) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_threadValidate(xbee, thread) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */

	if (thread->active) {
		thread->run = 0;
		usleep(1000); /* 1ms */
		if (xsys_thread_cancel(thread->tid)) return XBEE_ETHREAD;
		thread->active = 0;
	}

	return XBEE_ENONE;
}
xbee_err xbee_threadKillThis(struct xbee_threadInfo *thread) {
	return xbee_threadKill(NULL, thread);
}

xbee_err xbee_threadJoin(struct xbee *xbee, struct xbee_threadInfo *thread, xbee_err *retVal) {
	if (!xbee || !thread) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_threadValidate(xbee, thread) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */

	if (thread->active != 0) return XBEE_EINUSE;

	if (xsys_thread_join(thread->tid, (void**)retVal)) return XBEE_ETHREAD;

	xbee_ll_ext_item(threadList, thread);
	xsys_sem_destroy(&thread->mutexSem);
	free(thread);

	return XBEE_ENONE;
}

xbee_err xbee_threadKillJoin(struct xbee *xbee, struct xbee_threadInfo *thread, xbee_err *retVal) {
	xbee_err ret;

	if (!xbee || !thread) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_threadValidate(xbee, thread) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */

	if (thread->active) if ((ret = xbee_threadKill(xbee, thread)) != XBEE_ENONE) return ret;
	if ((ret = xbee_threadJoin(xbee, thread, retVal)) != XBEE_ENONE) return ret;
	
	return XBEE_ENONE;
}

xbee_err xbee_threadRelease(struct xbee *xbee, struct xbee_threadInfo *thread) {
	if (!xbee || !thread) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_threadValidate(xbee, thread) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */

	xsys_thread_detach(thread->tid);
	thread->detached = 1;
	xbee_ll_ext_item(threadList, thread);
	
	return XBEE_ENONE;
}

xbee_err xbee_threadStopRelease(struct xbee *xbee, struct xbee_threadInfo *thread) {
	xbee_err ret;

	if (!xbee || !thread) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_threadValidate(xbee, thread) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */

	thread->run = 0;
	if ((ret = xbee_threadRelease(xbee, thread)) != XBEE_ENONE) return ret;
	
	return XBEE_ENONE;
}

xbee_err xbee_threadKillRelease(struct xbee *xbee, struct xbee_threadInfo *thread) {
	xbee_err ret;

	if (!xbee || !thread) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_threadValidate(xbee, thread) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */

	if ((ret = xbee_threadRelease(xbee, thread)) != XBEE_ENONE) return ret;
	if ((ret = xbee_threadKill(xbee, thread)) != XBEE_ENONE) return ret;
	xsys_sem_destroy(&thread->mutexSem);
	free(thread);
	
	return XBEE_ENONE;
}

/* ########################################################################## */

xbee_err xbee_threadDestroyMine(struct xbee *xbee) {
	xbee_err ret;
	struct xbee_threadInfo *thread;
	struct xbee_threadInfo *pThread;

	if (!xbee) return XBEE_EMISSINGPARAM;

	pThread = NULL;
	ret = XBEE_ENONE;
	for (thread = NULL; xbee_ll_get_next(threadList, thread, (void**)&thread) == XBEE_ENONE && thread; ) {
		if (thread->xbee != xbee) {
			pThread = thread;
			continue;
		}
		
		if ((ret = xbee_threadKillJoin(xbee, thread, NULL)) != XBEE_ENONE) {
			xbee_log(1, "failed to destroy thread %p...", thread);
			continue;
		}

		thread = pThread;
	}
	
	return ret;
}
