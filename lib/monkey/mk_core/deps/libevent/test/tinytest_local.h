
#include "util-internal.h"
#if defined(_WIN64) || defined(_WIN32)
#include <winsock2.h>
#endif

#include "event2/util.h"

#ifdef snprintf
#undef snprintf
#endif
#define snprintf evutil_snprintf
