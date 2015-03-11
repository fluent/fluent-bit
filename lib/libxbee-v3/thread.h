#ifndef __XBEE_THREAD_H
#define __XBEE_THREAD_H

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

extern struct xbee_ll_head *threadList;
extern xsys_thread_key threadInfoKey;

struct xbee_threadInfo {
	int run;     /* FALSE will cause the thread to die once func() returns */
	int detached;/* TRUE will cause the thread to free the info block before it returns */
	int running; /* TRUE means that the function is actually running */
	int active;  /* TRUE means that the thread is alive */

	time_t restartDelay;
	xsys_thread tid;

	xsys_sem mutexSem; /* keeps count of mutexes held, if > 0, then the thread should be locked */

	struct xbee *xbee;
	const char *funcName;
	xbee_err (*func)(struct xbee *xbee, int *restart, void *arg);
	void *arg;
};

#define xbee_threadStart(xbee, retThread, restartDelay, detach, func, arg) \
	_xbee_threadStart(xbee, retThread, restartDelay, detach, #func, func, arg)
xbee_err _xbee_threadStart(struct xbee *xbee, struct xbee_threadInfo **retThread, int restartDelay, int detach, const char *funcName, xbee_err (*func)(struct xbee *xbee, int *restart, void *arg), void *arg);

xbee_err xbee_threadKillThis(struct xbee_threadInfo *thread);
xbee_err xbee_threadKill(struct xbee *xbee, struct xbee_threadInfo *thread);
xbee_err xbee_threadJoin(struct xbee *xbee, struct xbee_threadInfo *thread, xbee_err *retVal);
xbee_err xbee_threadKillJoin(struct xbee *xbee, struct xbee_threadInfo *thread, xbee_err *retVal);
xbee_err xbee_threadRelease(struct xbee *xbee, struct xbee_threadInfo *thread);
xbee_err xbee_threadStopRelease(struct xbee *xbee, struct xbee_threadInfo *thread);
xbee_err xbee_threadKillRelease(struct xbee *xbee, struct xbee_threadInfo *thread);

xbee_err xbee_threadDestroyMine(struct xbee *xbee);


#endif /* __XBEE_THREAD_H */
