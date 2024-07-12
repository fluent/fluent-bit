#ifndef WINSOCK_UTILS_H
#define WINSOCK_UTILS_H

#ifdef _WIN32
#include <winsock2.h>
void initialize_winsock();
void cleanup_winsock();
#endif

#endif // WINSOCK_UTILS_H
