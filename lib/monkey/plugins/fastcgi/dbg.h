/* Modified version of Zed's Awesome Debug Macros.
 *
 * http://c.learncodethehardway.org/book/learn-c-the-hard-waych21.html
 */
#ifndef __DBG_H__
#define __DBG_H__

#include <errno.h>
#include <monkey/mk_api.h>

#ifndef DEBUG
#define debug(M, ...) (void)0
#else
#define debug(M, ...) log_info(M, ##__VA_ARGS__)
#endif

#define clean_errno() (errno == 0 ? "None" : strerror(errno))

#define log_err(M, ...) mk_err("[fastcgi] (%s:%d: errno: %s) " M, __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)

#define log_warn(M, ...) mk_warn("[fastcgi] (%s:%d: errno: %s) " M, __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)

#define log_info(M, ...) mk_info("[fastcgi] (%s:%d) " M, __FILE__, __LINE__, ##__VA_ARGS__)

#define check(A, M, ...) if (!(A)) { log_err(M, ##__VA_ARGS__); errno = 0; goto error; }

#define sentinel(M, ...) { log_err(M, ##__VA_ARGS__); errno = 0; goto error; }

#define check_mem(A) check((A), "Out of memory.")

#define check_debug(A, M, ...) if (!(A)) { debug(M, ##__VA_ARGS__); errno = 0; goto error; }

#endif /* __DBG_H__ */
