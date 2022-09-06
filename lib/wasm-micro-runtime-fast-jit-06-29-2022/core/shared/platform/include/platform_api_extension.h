/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef PLATFORM_API_EXTENSION_H
#define PLATFORM_API_EXTENSION_H

#include "platform_common.h"
/**
 * The related data structures should be defined
 * in platform_internal.h
 **/
#include "platform_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************
 *                                                 *
 *                Extension interface              *
 *                                                 *
 ***************************************************/

/****************************************************
 *                     Section 1                    *
 *                Multi thread support              *
 ****************************************************/

/**
 * NOTES:
 * 1. If you are building VM core only, it must be implemented to
 *    enable multi-thread support, otherwise no need to implement it
 * 2. To build the app-mgr and app-framework, you must implement it
 */

/**
 * Creates a thread
 *
 * @param p_tid  [OUTPUT] the pointer of tid
 * @param start  main routine of the thread
 * @param arg  argument passed to main routine
 * @param stack_size  bytes of stack size
 *
 * @return 0 if success.
 */
int
os_thread_create(korp_tid *p_tid, thread_start_routine_t start, void *arg,
                 unsigned int stack_size);

/**
 * Creates a thread with priority
 *
 * @param p_tid  [OUTPUT] the pointer of tid
 * @param start  main routine of the thread
 * @param arg  argument passed to main routine
 * @param stack_size  bytes of stack size
 * @param prio the priority
 *
 * @return 0 if success.
 */
int
os_thread_create_with_prio(korp_tid *p_tid, thread_start_routine_t start,
                           void *arg, unsigned int stack_size, int prio);

/**
 * Waits for the thread specified by thread to terminate
 *
 * @param thread the thread to wait
 * @param retval if not NULL, output the exit status of the terminated thread
 *
 * @return return 0 if success
 */
int
os_thread_join(korp_tid thread, void **retval);

/**
 * Detach the thread specified by thread
 *
 * @param thread the thread to detach
 *
 * @return return 0 if success
 */
int os_thread_detach(korp_tid);

/**
 * Exit current thread
 *
 * @param retval the return value of the current thread
 */
void
os_thread_exit(void *retval);

/**
 * Initialize current thread environment if current thread
 * is created by developer but not runtime
 *
 * @return 0 if success, -1 otherwise
 */
int
os_thread_env_init();

/**
 * Destroy current thread environment
 */
void
os_thread_env_destroy();

/**
 * Whether the thread environment is initialized
 */
bool
os_thread_env_inited();

/**
 * Suspend execution of the calling thread for (at least)
 * usec microseconds
 *
 * @return 0 if success, -1 otherwise
 */
int
os_usleep(uint32 usec);

/**
 * Creates a recursive mutex
 *
 * @param mutex [OUTPUT] pointer to mutex initialized.
 *
 * @return 0 if success
 */
int
os_recursive_mutex_init(korp_mutex *mutex);

/**
 * This function creates a condition variable
 *
 * @param cond [OUTPUT] pointer to condition variable
 *
 * @return 0 if success
 */
int
os_cond_init(korp_cond *cond);

/**
 * This function destroys condition variable
 *
 * @param cond pointer to condition variable
 *
 * @return 0 if success
 */
int
os_cond_destroy(korp_cond *cond);

/**
 * Wait a condition variable.
 *
 * @param cond pointer to condition variable
 * @param mutex pointer to mutex to protect the condition variable
 *
 * @return 0 if success
 */
int
os_cond_wait(korp_cond *cond, korp_mutex *mutex);

/**
 * Wait a condition varible or return if time specified passes.
 *
 * @param cond pointer to condition variable
 * @param mutex pointer to mutex to protect the condition variable
 * @param useconds microseconds to wait
 *
 * @return 0 if success
 */
int
os_cond_reltimedwait(korp_cond *cond, korp_mutex *mutex, uint64 useconds);

/**
 * Signals the condition variable
 *
 * @param cond condition variable
 *
 * @return 0 if success
 */
int
os_cond_signal(korp_cond *cond);

/**
 * Broadcast the condition variable
 *
 * @param cond condition variable
 *
 * @return 0 if success
 */
int
os_cond_broadcast(korp_cond *cond);

/****************************************************
 *                     Section 2                    *
 *                   Socket support                 *
 ****************************************************/

/**
 * NOTES:
 * Socket APIs are required by source debugging feature.
 * If you don't need source debugging feature, then no
 * need to implement these APIs
 */

/**
 * Create a socket
 *
 * @param sock [OUTPUT] the pointer of socket
 * @param tcp_or_udp 1 for tcp, 0 for udp
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_create(bh_socket_t *sock, int tcp_or_udp);

/**
 * Assign the address and port to the socket
 *
 * @param socket the socket to bind
 * @param addr the ip address, only IPv4 supported currently
 * @param port [INPUT/OUTPUT] the port number, if the value is 0,
 *             it will use a port assigned by OS. On return it will
 *             contain the actual bound port number
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_bind(bh_socket_t socket, const char *addr, int *port);

/**
 * Set timeout for the given socket
 *
 * @param socket the socket to set timeout
 * @param timeout_us timeout in microseconds
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_settimeout(bh_socket_t socket, uint64 timeout_us);

/**
 * Make the socket as a passive socket to accept incoming connection requests
 *
 * @param socket the socket to listen
 * @param max_client maximum clients
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_listen(bh_socket_t socket, int max_client);

/**
 * Accept an incoming connection
 *
 * @param server_sock the socket to accept new connections
 * @param sock [OUTPUT] the connected socket
 * @param addr [OUTPUT] the address of the peer socket. If addr is NULL,
 *             nothing is filled in, and addrlen will not be used
 * @param addrlen [INPUT/OUTPUT] the size (in bytes) of the structure
 *                pointed to by addr, on return it will contain the actual
 *                size of the peer address
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_accept(bh_socket_t server_sock, bh_socket_t *sock, void *addr,
                 unsigned int *addrlen);

/**
 * initiate a connection on a socket
 *
 * @param socket the socket to connect with
 * @param addr the ip address, only IPv4 supported currently
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_connect(bh_socket_t socket, const char *addr, int port);

/**
 * Blocking receive message from a socket.
 *
 * @param socket the socket to receive message from
 * @param buf the buffer to store the data
 * @param len length of the buffer, this API does not guarantee that
 *            [len] bytes are received
 *
 * @return number of bytes received if success, -1 otherwise
 */
int
os_socket_recv(bh_socket_t socket, void *buf, unsigned int len);

/**
 * Blocking send message on a socket
 *
 * @param socket the socket to send message
 * @param buf the buffer of data to be sent
 * @param len length of the buffer
 *
 * @return number of bytes sent if success, -1 otherwise
 */
int
os_socket_send(bh_socket_t socket, const void *buf, unsigned int len);

/**
 * Close a socket
 *
 * @param socket the socket to be closed
 *
 * @return always return 0
 */
int
os_socket_close(bh_socket_t socket);

/**
 * Shutdown a socket
 *
 * @param socket the socket to be shutdown
 *
 * @return always return 0
 */
int
os_socket_shutdown(bh_socket_t socket);

/**
 * converts cp into a number in host byte order suitable for use as
 * an Internet network address
 *
 * @param cp a string in IPv4 numbers-and-dots notation
 *
 * @return On success, the converted address is  returned.
 * If the input is invalid, -1 is returned
 */
int
os_socket_inet_network(const char *cp, uint32 *out);

#ifdef __cplusplus
}
#endif

#endif /* #ifndef PLATFORM_API_EXTENSION_H */
