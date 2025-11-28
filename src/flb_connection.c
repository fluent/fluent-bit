#include <assert.h>

#include <fluent-bit/flb_connection.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_network_verifier.h>

int flb_connection_setup(struct flb_connection *connection,
                         flb_sockfd_t socket,
                         int type,
                         void *stream,
                         struct mk_event_loop *event_loop,
                         struct flb_coro *coroutine)
{
    assert(connection != NULL);

    memset(connection, 0, sizeof(struct flb_connection));

    connection->fd                      = socket;
    connection->type                    = type;
    connection->stream                  = stream;
    connection->net_error               = -1;
    connection->evl                     = event_loop;
    connection->coroutine               = coroutine;
    connection->tls_session             = NULL;
    connection->ts_created              = time(NULL);
    connection->ts_assigned             = time(NULL);
    connection->busy_flag               = FLB_FALSE;
    connection->shutdown_flag           = FLB_FALSE;

    connection->net = &connection->stream->net;

    assert(connection->net != NULL);

    MK_EVENT_ZERO(&connection->event);

    flb_connection_unset_connection_timeout(connection);
    flb_connection_unset_io_timeout(connection);

    return 0;
}

struct flb_connection *flb_connection_create(flb_sockfd_t socket,
                                             int type,
                                             void *stream,
                                             struct mk_event_loop *event_loop,
                                             struct flb_coro *coroutine)
{
    struct flb_connection *connection;
    int                    result;

    connection = flb_calloc(1, sizeof(struct flb_connection));

    if (connection == NULL) {
        flb_errno();
    }
    else {
        result = flb_connection_setup(connection,
                                      socket,
                                      type,
                                      stream,
                                      event_loop,
                                      coroutine);

        if (result != 0) {
            flb_connection_destroy(connection);

            connection = NULL;
        }
        else {
            connection->dynamically_allocated = FLB_TRUE;
        }
    }

    return connection;
}

void flb_connection_destroy(struct flb_connection *connection)
{
    assert(connection != NULL);

    if (connection->dynamically_allocated) {
        flb_free(connection);
    }
}

static void compose_user_friendly_remote_host(struct flb_connection *connection)
{
    int connection_type;

    connection_type = connection->stream->transport;

    if (connection_type == FLB_TRANSPORT_TCP) {
        snprintf(connection->user_friendly_remote_host,
                 sizeof(connection->user_friendly_remote_host),
                 "tcp://%s:%u",
                 connection->remote_host,
                 connection->remote_port);
    }
    else if (connection_type == FLB_TRANSPORT_UDP) {
        snprintf(connection->user_friendly_remote_host,
                 sizeof(connection->user_friendly_remote_host),
                 "udp://%s:%u",
                 connection->remote_host,
                 connection->remote_port);
    }
    else if (connection_type == FLB_TRANSPORT_UNIX_STREAM) {
        snprintf(connection->user_friendly_remote_host,
                 sizeof(connection->user_friendly_remote_host),
                 "unix://%s",
                 connection->remote_host);
    }
    else if (connection_type == FLB_TRANSPORT_UNIX_DGRAM) {
        snprintf(connection->user_friendly_remote_host,
                 sizeof(connection->user_friendly_remote_host),
                 "unix://%s",
                 connection->remote_host);
    }
}

void flb_connection_set_remote_host(struct flb_connection *connection,
                                    struct sockaddr *remote_host)
{
    size_t address_size;

    address_size = flb_network_address_size((struct sockaddr_storage *) remote_host);

    if (address_size > 0 &&
        address_size < sizeof(struct sockaddr_storage)) {
        memcpy(&connection->raw_remote_host,
               remote_host,
               address_size);
    }
}

char *flb_connection_get_remote_address(struct flb_connection *connection)
{
    int    address_refresh_required;
    size_t dummy_size_receptacle;
    int    refresh_required;
    int    stream_type;
    int    transport;
    int    result;

    stream_type = connection->stream->type;
    transport = connection->stream->transport;

    address_refresh_required = FLB_FALSE;
    refresh_required = FLB_FALSE;

    if (stream_type == FLB_DOWNSTREAM) {
        if (transport == FLB_TRANSPORT_UDP) {
            if (connection->raw_remote_host.ss_family != AF_UNSPEC) {
                refresh_required = FLB_TRUE;
            }
        }
        else if (transport == FLB_TRANSPORT_TCP ||
                 transport == FLB_TRANSPORT_UNIX_STREAM) {
            if (connection->raw_remote_host.ss_family == AF_UNSPEC) {
                address_refresh_required = FLB_TRUE;
            }
        }
    }
    else if (stream_type == FLB_UPSTREAM) {
        if (transport == FLB_TRANSPORT_TCP ||
            transport == FLB_TRANSPORT_UNIX_STREAM) {
            if (connection->raw_remote_host.ss_family == AF_UNSPEC) {
                address_refresh_required = FLB_TRUE;
            }
        }
    }

    if (connection->remote_port == 0) {
        refresh_required = FLB_TRUE;
    }

    if (refresh_required) {
        if (address_refresh_required) {
            result = flb_net_socket_peer_address(connection->fd,
                                                 &connection->raw_remote_host);
        }

        result = flb_net_socket_address_info(connection->fd,
                                             &connection->raw_remote_host,
                                             &connection->remote_port,
                                             connection->remote_host,
                                             sizeof(connection->remote_host),
                                             &dummy_size_receptacle);

        if (result == 0) {
            compose_user_friendly_remote_host(connection);
        }
    }

    return connection->user_friendly_remote_host;
}

int flb_connection_get_flags(struct flb_connection *connection)
{
    return flb_stream_get_flags(connection->stream);
}

void flb_connection_reset_connection_timeout(struct flb_connection *connection)
{
    time_t current_time;
    time_t timeout_time;

    assert(connection != NULL);

    if (connection->type == FLB_UPSTREAM_CONNECTION) {
        if (connection->net->connect_timeout > 0) {
            current_time = time(NULL);
            timeout_time = current_time + connection->net->connect_timeout;

            connection->ts_connect_start = current_time;
            connection->ts_connect_timeout = timeout_time;
        }
    }
    else if(connection->type == FLB_DOWNSTREAM_CONNECTION) {
        if (connection->net->accept_timeout > 0) {
            current_time = time(NULL);
            timeout_time = current_time + connection->net->accept_timeout;

            connection->ts_connect_start = current_time;
            connection->ts_connect_timeout = timeout_time;
        }
    }
}

void flb_connection_unset_connection_timeout(struct flb_connection *connection)
{
    assert(connection != NULL);

    connection->ts_connect_start = -1;
    connection->ts_connect_timeout = -1;
}

void flb_connection_reset_io_timeout(struct flb_connection *connection)
{
    time_t current_time;
    time_t timeout_time;

    assert(connection != NULL);

    if (connection->net->io_timeout > 0) {
        current_time = time(NULL);
        timeout_time = current_time + connection->net->io_timeout;

        connection->ts_io_timeout = timeout_time;
    }
}

void flb_connection_unset_io_timeout(struct flb_connection *connection)
{
    assert(connection != NULL);

    connection->ts_io_timeout = -1;
}

void flb_connection_notify_error(const struct flb_connection* conn,
    const char* dest, int port, int error_code, const char* error_msg)
{
    struct flb_network_verifier_instance* conn_verifier = NULL;

    if (conn && conn->stream) {
        conn_verifier = conn->stream->verifier_ins;
    }

    if (conn_verifier && conn_verifier->plugin && 
        conn_verifier->plugin->cb_connection_failure) {
        conn_verifier->plugin->cb_connection_failure(conn_verifier, dest, port, 
                                                     error_code, error_msg);
    }
}