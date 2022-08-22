#include <fluent-bit/flb_connection.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_downstream.h>

void flb_connection_init(struct flb_connection *connection,
                         flb_sockfd_t socket,
                         int type,
                         void *stream,
                         struct mk_event_loop *event_loop,
                         struct flb_coro *coroutine)
{
    assert(connection != NULL);

    connection->fd                     = socket;
    connection->type                   = type;
    connection->stream                 = stream;
    connection->net_error              = -1;
    connection->evl                    = event_loop;
    connection->coroutine              = coroutine;
    connection->tls_session            = NULL;

    connection->raw_remote_host_family = 0;
    connection->raw_remote_host[0]     = '\0';

    connection->remote_host[0]         = '\0';
    connection->remote_port            = 0;

    connection->ka_count               = 0;
    connection->ts_created             = time(NULL);
    connection->ts_assigned            = time(NULL);
    connection->ts_available           = 0;

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
}

int flb_connection_get_remote_address(struct flb_connection *connection)
{
    size_t dummy_size_receptacle;

    return flb_net_socket_peer_info(connection->fd,
                                    &connection->remote_port,
                                    connection->raw_remote_host,
                                    sizeof(connection->raw_remote_host),
                                    &dummy_size_receptacle,
                                    connection->remote_host,
                                    sizeof(connection->remote_host),
                                    &dummy_size_receptacle,
                                    &connection->raw_remote_host_family);
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