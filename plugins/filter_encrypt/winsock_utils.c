#include "winsock_utils.h"

#ifdef _WIN32
#include <stdio.h>
#include <stdlib.h>

void initialize_winsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", result);
        exit(EXIT_FAILURE);
    }
}

void cleanup_winsock() {
    WSACleanup();
}
#endif
