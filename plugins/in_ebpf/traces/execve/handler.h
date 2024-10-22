#ifndef EXECVE_HANDLER_H
#define EXECVE_HANDLER_H

#include <stddef.h>  

int trace_execve_handler(void *ctx, void *data, size_t data_sz);

#endif // EXECVE_HANDLER_H