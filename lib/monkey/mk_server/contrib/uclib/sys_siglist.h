/*
 * Copyright (C) 2002     Manuel Novoa III
 * Copyright (C) 2000-2005 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <features.h>
#define __need_NULL
#include <stddef.h>
#include <signal.h>

#ifndef UCLIB_SYS_SIGLIST
#define UCLIB_SYS_SIGLIST

const char _string_syssigmsgs[];
const char *const sys_siglist[_NSIG] = {
	[0] =				NULL,
	[SIGHUP] =			_string_syssigmsgs + 1,
	[SIGINT] =			_string_syssigmsgs + 8,
	[SIGQUIT] =			_string_syssigmsgs + 18,
	[SIGILL] =			_string_syssigmsgs + 23,
	[SIGTRAP] =			_string_syssigmsgs + 43,
	[SIGABRT] =			_string_syssigmsgs + 65,
	[SIGBUS] =			_string_syssigmsgs + 73,
	[SIGFPE] =			_string_syssigmsgs + 83,
	[SIGKILL] =			_string_syssigmsgs + 108,
	[SIGUSR1] =			_string_syssigmsgs + 115,
	[SIGSEGV] =			_string_syssigmsgs + 137,
	[SIGUSR2] =			_string_syssigmsgs + 156,
	[SIGPIPE] =			_string_syssigmsgs + 178,
	[SIGALRM] =			_string_syssigmsgs + 190,
	[SIGTERM] =			_string_syssigmsgs + 202,
#if defined SIGSTKFLT /* not all arches define this, yeah ! */
	[SIGSTKFLT] =			_string_syssigmsgs + 213,
#endif
	[SIGCHLD] =			_string_syssigmsgs + 225,
	[SIGCONT] =			_string_syssigmsgs + 238,
	[SIGSTOP] =			_string_syssigmsgs + 248,
	[SIGTSTP] =			_string_syssigmsgs + 265,
	[SIGTTIN] =			_string_syssigmsgs + 273,
	[SIGTTOU] =			_string_syssigmsgs + 293,
	[SIGURG] =			_string_syssigmsgs + 314,
	[SIGXCPU] =			_string_syssigmsgs + 335,
	[SIGXFSZ] =			_string_syssigmsgs + 359,
	[SIGVTALRM] =			_string_syssigmsgs + 384,
	[SIGPROF] =			_string_syssigmsgs + 406,
	[SIGWINCH] =			_string_syssigmsgs + 430,
	[SIGIO] =			_string_syssigmsgs + 445,
	[SIGPWR] =			_string_syssigmsgs + 458,
	[SIGSYS] =			_string_syssigmsgs + 472,
#if defined SIGEMT /* only some arches define this, yeah ! */
	[SIGEMT] =			_string_syssigmsgs + 488,
#endif
};

#endif
