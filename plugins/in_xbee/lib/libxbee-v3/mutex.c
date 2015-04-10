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

#include "internal.h"
#include "thread.h"

/* this mechanism is to prevent threads from being killed, while they hold a mutex */

int xbee_mutex_lock(xsys_mutex *mutex) {
	int ret;
	struct xbee_threadInfo *thread;
	ret = xsys_mutex_lock(mutex);
	thread = xsys_thread_key_get(threadInfoKey);
	if (thread && !ret) {
		xsys_sem_post(&thread->mutexSem);
		xsys_thread_lock();
	}
	return ret;
}

int xbee_mutex_trylock(xsys_mutex *mutex) {
	int ret;
	struct xbee_threadInfo *thread;
	ret = xsys_mutex_trylock(mutex);
	thread = xsys_thread_key_get(threadInfoKey);
	if (thread && !ret) {
		xsys_sem_post(&thread->mutexSem);
		xsys_thread_lock();
	}
	return ret;
}

int xbee_mutex_unlock(xsys_mutex *mutex) {
	int ret;
	struct xbee_threadInfo *thread;
	ret = xsys_mutex_unlock(mutex);
	thread = xsys_thread_key_get(threadInfoKey);
	if (thread && !ret) {
		int sVal;
		xsys_sem_trywait(&thread->mutexSem);
		xsys_sem_getvalue(&thread->mutexSem, &sVal);
		if (sVal == 0) xsys_thread_unlock();
	}
	return ret;
}
