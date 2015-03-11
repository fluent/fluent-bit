#ifndef __XBEE_XSYS_LOAD_H
#error This header should be included by xsys.h only
#endif /* __XBEE_XSYS_LOAD_H */
#ifndef __XBEE_XSYS_DARWIN_H
#define __XBEE_XSYS_DARWIN_H

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

#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <semaphore.h>

#ifdef __USE_GNU
#include <pthread.h>
#else
#define __USE_GNU
#include <pthread.h>
#undef __USE_GNU
#endif

/* OSX work arounds  */
#define MSG_NOSIGNAL SO_NOSIGPIPE
#define CLOCK_REALTIME 1
typedef int clockid_t;
int clock_gettime(clockid_t id, struct timespec *tp);
/* -x-x-x-x-x-x-x-x- */


/* ######################################################################### */

typedef pthread_t         xsys_thread;
typedef pthread_key_t     xsys_thread_key;

typedef pthread_mutex_t   xsys_mutex;

struct xsys_sem_t {
	sem_t *sem;
	int opened; /* if true, then sem_close() should be called
	               else sem_destroy(), and free(seM) */
};
typedef struct xsys_sem_t xsys_sem;

typedef size_t            xsys_size_t;
typedef ssize_t           xsys_ssize_t;

struct serialDev {
	int fd;
};
typedef struct serialDev  xsys_serialDev;

#define EXPORT __attribute__((visibility("default")))
#define INIT   __attribute__((constructor))
#define FINI   __attribute__((destructor))


/* ######################################################################### */
/* file I/O */

#define xsys_open(path, flags)                open((path),(flags))
#define xsys_close(fd)                        close((fd))
#define xsys_read(fd, buf, count)             read((fd),(buf),(count))
#define xsys_write(fd, buf, count)            write((fd),(buf),(count))

#define xsys_fopen(path, mode)                fopen((path),(mode))
#define xsys_fdopen(fd, mode)                 fdopen((fd),(mode))
#define xsys_fclose(stream)                   fclose((stream))
#define xsys_fread(ptr, size, nmemb, stream)  fread((ptr),(size),(nmemb),(stream))
#define xsys_fwrite(ptr, size, nmemb, stream) fwrite((ptr),(size),(nmemb),(stream))
#define xsys_fflush(stream)                   fflush((stream))
#define xsys_ferror(stream)                   ferror((stream))
#define xsys_feof(stream)                     feof((stream))
#define xsys_fileno(stream)                   fileno((stream))


/* ######################################################################### */
/* threads */

#define xsys_thread_create(thread, start_routine, arg) \
                                              pthread_create((pthread_t*)(thread), NULL, (start_routine), (arg))
#define xsys_thread_cancel(thread)            pthread_cancel((pthread_t)(thread))
#define xsys_thread_join(thread, retval)      pthread_join((pthread_t)(thread), (retval))
#define xsys_thread_self()                    pthread_self()
#define xsys_thread_detach(thread)            pthread_detach(thread)
#define xsys_thread_detach_self()             pthread_detach(pthread_self())
#define xsys_thread_iAm(thread)               pthread_equal(pthread_self(), (thread))
#define xsys_thread_lock()                    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)
#define xsys_thread_unlock()                  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)

#define xsys_thread_key_init(key, destructor) pthread_key_create((key), (destructor))
#define xsys_thread_key_set(key, value)       pthread_setspecific((key), (value))
#define xsys_thread_key_get(key)              pthread_getspecific((key))


/* ######################################################################### */
/* mutexes */

#define xsys_mutex_init(mutex)                pthread_mutex_init((pthread_mutex_t*)(mutex), NULL)
#define xsys_mutex_destroy(mutex)             pthread_mutex_destroy((pthread_mutex_t*)(mutex))
#define xsys_mutex_lock(mutex)                pthread_mutex_lock((pthread_mutex_t*)(mutex))
#define xsys_mutex_trylock(mutex)             pthread_mutex_trylock((pthread_mutex_t*)(mutex))
#define xsys_mutex_unlock(mutex)              pthread_mutex_unlock((pthread_mutex_t*)(mutex))


/* ######################################################################### */
/* semaphores */

int _xsys_sem_init(xsys_sem *info);
int _xsys_sem_destroy(xsys_sem *info);
int _xsys_sem_timedwait(sem_t *sem, const struct timespec *abs_timeout);

#define xsys_sem_init(info)                   _xsys_sem_init(info)
#define xsys_sem_destroy(info)                _xsys_sem_destroy(info)
#define xsys_sem_wait(info)                   sem_wait((info)->sem)
#define xsys_sem_trywait(info)                sem_trywait((info)->sem)
#define xsys_sem_timedwait(info, to)          sem_timedwait((info)->sem, (to))
#define xsys_sem_post(info)                   sem_post((info)->sem)
#define xsys_sem_getvalue(info, value)        sem_getvalue((info)->sem, (value))


#endif /* __XBEE_XSYS_DARWIN_H */
