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

/**
 * Creates a new POSIX-like semaphore or opens an existing
 * semaphore.  The semaphore is identified by name.  For details of
 * the construction of name, please refer to
 * https://man7.org/linux/man-pages/man3/sem_open.3.html.
 *
 * @param name semaphore name
 * @param oflasg specifies flags that control the operation of the call
 * @param mode permission flags
 * @param val initial value of the named semaphore.
 *
 * @return korp_sem * if success, NULL otherwise
 */
korp_sem *
os_sem_open(const char *name, int oflags, int mode, int val);

/**
 * Closes the named semaphore referred to by sem,
 * allowing any resources that the system has allocated to the
 * calling process for this semaphore to be freed.
 *
 * @param sem
 *
 * @return 0 if success
 */
int
os_sem_close(korp_sem *sem);

/**
 * Decrements (locks) the semaphore pointed to by sem.
 * If the semaphore's value is greater than zero, then the decrement
 * proceeds, and the function returns, immediately.  If the
 * semaphore currently has the value zero, then the call blocks
 * until either it becomes possible to perform the decrement (i.e.,
 * the semaphore value rises above zero), or a signal handler
 * interrupts the call.
 *
 * @return 0 if success
 */
int
os_sem_wait(korp_sem *sem);

/**
 * Is the same as sem_wait(), except that if the
 * decrement cannot be immediately performed, then call returns an
 * error (errno set to EAGAIN) instead of blocking.
 *
 * @return 0 if success
 */
int
os_sem_trywait(korp_sem *sem);

/**
 * Increments (unlocks) the semaphore pointed to by sem.
 * If the semaphore's value consequently becomes greater than zero,
 * then another process or thread blocked in a sem_wait(3) call will
 * be woken up and proceed to lock the semaphore.
 *
 * @return 0 if success
 */
int
os_sem_post(korp_sem *sem);

/**
 * Places the current value of the semaphore pointed
 * to sem into the integer pointed to by sval.
 *
 * @return 0 if success
 */
int
os_sem_getvalue(korp_sem *sem, int *sval);

/**
 * Remove the named semaphore referred to by name.
 * The semaphore name is removed immediately.  The semaphore is
 * destroyed once all other processes that have the semaphore open
 * close it.
 *
 * @param name semaphore name
 *
 * @return 0 if success
 */
int
os_sem_unlink(const char *name);

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

typedef union {
    uint32 ipv4;
    uint16 ipv6[8];
    uint8 data[1];
} bh_ip_addr_buffer_t;

typedef struct {
    bh_ip_addr_buffer_t addr_bufer;
    uint16 port;
    bool is_ipv4;
} bh_sockaddr_t;

/**
 * Create a socket
 *
 * @param sock [OUTPUT] the pointer of socket
 * @param is_ipv4 true for IPv4, false for IPv6
 * @param is_tcp true for tcp, false for udp
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_create(bh_socket_t *sock, bool is_ipv4, bool is_tcp);

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
 * Blocking receive message from a socket.
 *
 * @param socket the socket to send message
 * @param buf the buffer to store the data
 * @param len length of the buffer, this API does not guarantee that
 *            [len] bytes are received
 * @param flags control the operation
 * @param src_addr source address
 *
 * @return number of bytes sent if success, -1 otherwise
 */
int
os_socket_recv_from(bh_socket_t socket, void *buf, unsigned int len, int flags,
                    bh_sockaddr_t *src_addr);

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
 * Blocking send message on a socket to the target address
 *
 * @param socket the socket to send message
 * @param buf the buffer of data to be sent
 * @param len length of the buffer
 * @param flags control the operation
 * @param dest_addr target address
 *
 * @return number of bytes sent if success, -1 otherwise
 */
int
os_socket_send_to(bh_socket_t socket, const void *buf, unsigned int len,
                  int flags, const bh_sockaddr_t *dest_addr);

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
 * @param is_ipv4 a flag that indicates whether the string is an IPv4 or
 * IPv6 address
 *
 * @param cp a string in IPv4 numbers-and-dots notation or IPv6
 * numbers-and-colons notation
 *
 * @param out an output buffer to store binary address
 *
 * @return On success, the function returns 0.
 * If the input is invalid, -1 is returned
 */
int
os_socket_inet_network(bool is_ipv4, const char *cp, bh_ip_addr_buffer_t *out);

typedef struct {
    bh_sockaddr_t sockaddr;
    uint8_t is_tcp;
} bh_addr_info_t;

/**
 * Resolve a host a hostname and a service to one or more IP addresses
 *
 * @param host a host to resolve
 *
 * @param service a service to find a port for
 *
 * @param hint_is_tcp an optional flag that determines a preferred socket type
 (TCP or UDP).
 *
 * @param hint_is_ipv4 an optional flag that determines a preferred address
 family (IPv4 or IPv6)
 *
 * @param addr_info a buffer for resolved addresses
 *
 * @param addr_info_size a size of the buffer for resolved addresses

 * @param max_info_size a maximum number of addresses available (can be bigger
 or smaller than buffer size)

 * @return On success, the function returns 0; otherwise, it returns -1
 */
int
os_socket_addr_resolve(const char *host, const char *service,
                       uint8_t *hint_is_tcp, uint8_t *hint_is_ipv4,
                       bh_addr_info_t *addr_info, size_t addr_info_size,
                       size_t *max_info_size);

/**
 * Returns an binary address and a port of the local socket
 *
 * @param socket the local socket
 *
 * @param sockaddr a buffer for storing the address
 *
 * @return On success, returns 0; otherwise, it returns -1.
 */
int
os_socket_addr_local(bh_socket_t socket, bh_sockaddr_t *sockaddr);

/**
 * Returns an binary address and a port of the remote socket
 *
 * @param socket the remote socket
 *
 * @param sockaddr a buffer for storing the address
 *
 * @return On success, returns 0; otherwise, it returns -1.
 */
int
os_socket_addr_remote(bh_socket_t socket, bh_sockaddr_t *sockaddr);

/**
 * Set the maximum send buffer size.
 *
 * @param socket the socket to set
 * @param bufsiz requested kernel buffer size
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_send_buf_size(bh_socket_t socket, size_t bufsiz);

/**
 * Get the maximum send buffer size.
 *
 * @param socket the socket to set
 * @param bufsiz the returned kernel buffer size
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_send_buf_size(bh_socket_t socket, size_t *bufsiz);

/**
 * Set the maximum receive buffer size.
 *
 * @param socket the socket to set
 * @param bufsiz requested kernel buffer size
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_recv_buf_size(bh_socket_t socket, size_t bufsiz);

/**
 * Get the maximum receive buffer size.
 *
 * @param socket the socket to set
 * @param bufsiz the returned kernel buffer size
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_recv_buf_size(bh_socket_t socket, size_t *bufsiz);

/**
 * Enable sending of keep-alive messages on connection-oriented sockets
 *
 * @param socket the socket to set the flag
 * @param is_enabled 1 to enable or 0 to disable
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_keep_alive(bh_socket_t socket, bool is_enabled);

/**
 * Get if sending of keep-alive messages on connection-oriented sockets is
 * enabled
 *
 * @param socket the socket to check
 * @param is_enabled 1 if enabled or 0 if disabled
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_keep_alive(bh_socket_t socket, bool *is_enabled);

/**
 * Set the send timeout until reporting an error
 *
 * @param socket the socket to set
 * @param time_us microseconds until timeout
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_send_timeout(bh_socket_t socket, uint64 timeout_us);

/**
 * Get the send timeout until reporting an error
 *
 * @param socket the socket to set
 * @param time_us the returned microseconds until timeout
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_send_timeout(bh_socket_t socket, uint64 *timeout_us);

/**
 * Set the recv timeout until reporting an error
 *
 * @param socket the socket to set
 * @param time_us microseconds until timeout
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_recv_timeout(bh_socket_t socket, uint64 timeout_us);

/**
 * Get the recv timeout until reporting an error
 *
 * @param socket the socket to set
 * @param time_us the returned microseconds until timeout
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_recv_timeout(bh_socket_t socket, uint64 *timeout_us);

/**
 * Enable re-use of local addresses
 *
 * @param socket the socket to set
 * @param is_enabled 1 to enable or 0 to disable
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_reuse_addr(bh_socket_t socket, bool is_enabled);

/**
 * Get whether re-use of local addresses is enabled
 *
 * @param socket the socket to set
 * @param is_enabled 1 for enabled or 0 for disabled
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_reuse_addr(bh_socket_t socket, bool *is_enabled);

/**
 * Enable re-use of local ports
 *
 * @param socket the socket to set
 * @param is_enabled 1 to enable or 0 to disable
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_reuse_port(bh_socket_t socket, bool is_enabled);

/**
 * Get whether re-use of local ports is enabled
 *
 * @param socket the socket to set
 * @param is_enabled 1 for enabled or 0 for disabled
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_reuse_port(bh_socket_t socket, bool *is_enabled);

/**
 * Set the linger options for the given socket
 *
 * @param socket the socket to set
 * @param is_enabled whether linger is enabled
 * @param linger_s linger time (seconds)
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_linger(bh_socket_t socket, bool is_enabled, int linger_s);

/**
 * Get the linger options for the given socket
 *
 * @param socket the socket to get
 * @param is_enabled whether linger is enabled
 * @param linger_s linger time (seconds)
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_linger(bh_socket_t socket, bool *is_enabled, int *linger_s);

/**
 * Set no delay TCP
 * If set, disable the Nagle algorithm.
 * This means that segments are always sent as soon as possible,
 * even if there is only a small amount of data
 *
 * @param socket the socket to set the flag
 * @param is_enabled 1 to enable or 0 to disable
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_tcp_no_delay(bh_socket_t socket, bool is_enabled);

/**
 * Get no delay TCP
 * If set, disable the Nagle algorithm.
 * This means that segments are always sent as soon as possible,
 * even if there is only a small amount of data
 *
 * @param socket the socket to check
 * @param is_enabled 1 if enabled or 0 if disabled
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_tcp_no_delay(bh_socket_t socket, bool *is_enabled);

/**
 * Enable/Disable tcp quickack mode
 * In quickack mode, acks are sent immediately, rather than delayed if needed in
 * accordance to normal TCP operation
 *
 * @param socket the socket to set the flag
 * @param is_enabled 1 to enable or 0 to disable
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_tcp_quick_ack(bh_socket_t socket, bool is_enabled);

/**
 * Enable/Disable tcp quickack mode
 * In quickack mode, acks are sent immediately, rather than delayed if needed in
 * accordance to normal TCP operation
 *
 * @param socket the socket to check
 * @param is_enabled 1 if enabled or 0 if disabled
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_tcp_quick_ack(bh_socket_t socket, bool *is_enabled);

/**
 * Set the time the connection needs to remain idle before sending keepalive
 * probes
 *
 * @param socket the socket to set
 * @param time_s seconds until keepalive probes are sent
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_tcp_keep_idle(bh_socket_t socket, uint32_t time_s);

/**
 * Gets the time the connection needs to remain idle before sending keepalive
 * probes
 *
 * @param socket the socket to check
 * @param time_s seconds until keepalive probes are sent
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_tcp_keep_idle(bh_socket_t socket, uint32_t *time_s);

/**
 * Set the time between individual keepalive probes
 *
 * @param socket the socket to set
 * @param time_us seconds between individual keepalive probes
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_tcp_keep_intvl(bh_socket_t socket, uint32_t time_s);

/**
 * Get the time between individual keepalive probes
 *
 * @param socket the socket to get
 * @param time_s seconds between individual keepalive probes
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_tcp_keep_intvl(bh_socket_t socket, uint32_t *time_s);

/**
 * Set use of TCP Fast Open
 *
 * @param socket the socket to set
 * @param is_enabled 1 to enable or 0 to disable
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_tcp_fastopen_connect(bh_socket_t socket, bool is_enabled);

/**
 * Get whether use of TCP Fast Open is enabled
 *
 * @param socket the socket to get
 * @param is_enabled 1 to enabled or 0 to disabled
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_tcp_fastopen_connect(bh_socket_t socket, bool *is_enabled);

/**
 * Set enable or disable IPv4 or IPv6 multicast loopback.
 *
 * @param socket the socket to set
 * @param ipv6 true to set ipv6 loopback or false for ipv4
 * @param is_enabled 1 to enable or 0 to disable
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_ip_multicast_loop(bh_socket_t socket, bool ipv6, bool is_enabled);

/**
 * Get enable or disable IPv4 or IPv6 multicast loopback.
 *
 * @param socket the socket to check
 * @param ipv6 true to set ipv6 loopback or false for ipv4
 * @param is_enabled 1 for enabled or 0 for disabled
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_ip_multicast_loop(bh_socket_t socket, bool ipv6,
                                bool *is_enabled);

/**
 * Add membership to a group
 *
 * @param socket the socket to add membership to
 * @param imr_multiaddr the group multicast address (IPv4 or IPv6)
 * @param imr_interface the interface to join on
 * @param is_ipv6 whether the imr_multiaddr is IPv4 or IPv6 (true for IPv6)
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_ip_add_membership(bh_socket_t socket,
                                bh_ip_addr_buffer_t *imr_multiaddr,
                                uint32_t imr_interface, bool is_ipv6);

/**
 * Drop membership of a group
 *
 * @param socket the socket to drop membership to
 * @param imr_multiaddr the group multicast address (IPv4 or IPv6)
 * @param imr_interface the interface to join on
 * @param is_ipv6 whether the imr_multiaddr is IPv4 or IPv6 (true for IPv6)
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_ip_drop_membership(bh_socket_t socket,
                                 bh_ip_addr_buffer_t *imr_multiaddr,
                                 uint32_t imr_interface, bool is_ipv6);

/**
 * Set the current time-to-live field that is
 * used in every packet sent from this socket.
 * @param socket the socket to set the flag
 * @param ttl_s time to live (seconds)
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_ip_ttl(bh_socket_t socket, uint8_t ttl_s);

/**
 * Retrieve the current time-to-live field that is
 * used in every packet sent from this socket.
 * @param socket the socket to set the flag
 * @param ttl_s time to live (seconds)
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_ip_ttl(bh_socket_t socket, uint8_t *ttl_s);

/**
 * Set the time-to-live value of outgoing multicast
 * packets for this socket
 * @param socket the socket to set the flag
 * @param ttl_s time to live (seconds)
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_ip_multicast_ttl(bh_socket_t socket, uint8_t ttl_s);

/**
 * Read the time-to-live value of outgoing multicast
 * packets for this socket
 * @param socket the socket to set the flag
 * @param ttl_s time to live (seconds)
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_ip_multicast_ttl(bh_socket_t socket, uint8_t *ttl_s);

/**
 * Restrict to sending and receiving IPv6 packets only
 *
 * @param socket the socket to set
 * @param is_enabled 1 to enable or 0 to disable
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_ipv6_only(bh_socket_t socket, bool is_enabled);

/**
 * Get whether only sending and receiving IPv6 packets
 *
 * @param socket the socket to check
 * @param is_enabled 1 for enabled or 0 for disabled
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_ipv6_only(bh_socket_t socket, bool *is_enabled);

/**
 * Set whether broadcast is enabled
 * When enabled, datagram sockets are allowed
 * to send packets to a broadcast address.
 *
 * @param socket the socket to set the flag
 * @param is_enabled 1 to enable or 0 to disable
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_set_broadcast(bh_socket_t socket, bool is_enabled);

/**
 * Get whether broadcast is enabled
 * When enabled, datagram sockets are allowed
 * to send packets to a broadcast address.
 *
 * @param socket the socket to check
 * @param is_enabled 1 if enabled or 0 if disabled
 *
 * @return 0 if success, -1 otherwise
 */
int
os_socket_get_broadcast(bh_socket_t socket, bool *is_enabled);

#ifdef __cplusplus
}
#endif

#endif /* #ifndef PLATFORM_API_EXTENSION_H */
