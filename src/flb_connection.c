#include <fluent-bit/flb_connection.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_downstream.h>

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

    if (type == FLB_UPSTREAM_CONNECTION) {
        connection->net = &connection->upstream->net;
    }
    else if (type == FLB_DOWNSTREAM_CONNECTION) {
        connection->net = &connection->downstream->net;
    }

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

    connection_type = FLB_CONNECTION_TYPE_UNSET;

    if (connection->type == FLB_UPSTREAM_CONNECTION) {
        connection_type = FLB_CONNECTION_TYPE_TCP;
    }
    else if (connection->type == FLB_DOWNSTREAM_CONNECTION) {
        switch (connection->downstream->type) {
            case FLB_DOWNSTREAM_TYPE_TCP:
                connection_type = FLB_CONNECTION_TYPE_TCP;
                break;
            case FLB_DOWNSTREAM_TYPE_UDP:
                connection_type = FLB_CONNECTION_TYPE_UDP;
                break;
            case FLB_DOWNSTREAM_TYPE_UNIX_STREAM:
                connection_type = FLB_CONNECTION_TYPE_UNIX_STREAM;
                break;
            case FLB_DOWNSTREAM_TYPE_UNIX_DGRAM:
                connection_type = FLB_CONNECTION_TYPE_UNIX_DGRAM;
                break;
        }
    }

    if (connection_type == FLB_CONNECTION_TYPE_TCP) {
        snprintf(connection->user_friendly_remote_host,
                 sizeof(connection->user_friendly_remote_host),
                 "tcp://%s:%u",
                 connection->remote_host,
                 connection->remote_port);
    }
    else if (connection_type == FLB_CONNECTION_TYPE_UDP) {
        snprintf(connection->user_friendly_remote_host,
                 sizeof(connection->user_friendly_remote_host),
                 "udp://%s:%u",
                 connection->remote_host,
                 connection->remote_port);
    }
    else if (connection_type == FLB_CONNECTION_TYPE_UNIX_STREAM) {
        snprintf(connection->user_friendly_remote_host,
                 sizeof(connection->user_friendly_remote_host),
                 "unix://%s",
                 connection->remote_host);
    }
    else if (connection_type == FLB_CONNECTION_TYPE_UNIX_DGRAM) {
        snprintf(connection->user_friendly_remote_host,
                 sizeof(connection->user_friendly_remote_host),
                 "unix://%s",
                 connection->remote_host);
    }
}

char *flb_connection_get_remote_address(struct flb_connection *connection)
{
    int    address_refresh_required;
    size_t dummy_size_receptacle;
    int    refresh_required;
    int    result;

    address_refresh_required = FLB_FALSE;
    refresh_required = FLB_FALSE;

    if (connection->type == FLB_DOWNSTREAM_CONNECTION) {
        if (connection->downstream->type == FLB_DOWNSTREAM_TYPE_UDP) {
            if (connection->raw_remote_host.ss_family != AF_UNSPEC) {
                refresh_required = FLB_TRUE;
            }
        }
        else if (connection->downstream->type == FLB_DOWNSTREAM_TYPE_TCP ||
                 connection->downstream->type == FLB_DOWNSTREAM_TYPE_UNIX_STREAM) {
            if (connection->raw_remote_host.ss_family == AF_UNSPEC) {
                address_refresh_required = FLB_TRUE;
                refresh_required = FLB_TRUE;
            }
        }
    }
    else if (connection->type == FLB_UPSTREAM_CONNECTION) {
        if (connection->downstream->type == FLB_DOWNSTREAM_TYPE_TCP ||
            connection->downstream->type == FLB_DOWNSTREAM_TYPE_UNIX_STREAM) {
            if (connection->raw_remote_host.ss_family == AF_UNSPEC) {
                address_refresh_required = FLB_TRUE;
                refresh_required = FLB_TRUE;
            }
        }
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
    int result;

    if (connection->type == FLB_UPSTREAM_CONNECTION) {
        result = connection->upstream->flags;
    }
    else if (connection->type == FLB_DOWNSTREAM_CONNECTION) {
        result = connection->downstream->flags;
    }
    else {
        result = -1;
    }

    return result;
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