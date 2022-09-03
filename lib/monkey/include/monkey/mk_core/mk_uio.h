#ifndef MK_UIO_H
#define MK_UIO_H

#include "mk_core_info.h"

#ifdef MK_HAVE_SYS_UIO_H
#include <sys/uio.h>
#define mk_iovec iovec
#else
#include "external/winuio.h"
#endif

#endif
