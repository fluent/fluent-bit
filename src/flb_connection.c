#include <fluent-bit/flb_connection.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_downstream.h>

void flb_connection_init(struct flb_connection *connection,
                         flb_sockfd_t socket,
                         int type,
                         void *stream,
                         struct mk_event_loop *event_loop,
                         struct flb_coro *coroutine,
                         void *type_specific_attributes)
{
    assert(connection != NULL);

    connection->fd          = socket;
    connection->type        = type;
    connection->stream      = stream;
    connection->net_error   = -1;
    connection->evl         = event_loop;
    connection->coroutine   = coroutine;
    connection->attrs       = type_specific_attributes;
    connection->tls_session = NULL;

    connection->remote_host = (char *) "remote host unset";
    connection->remote_port = 0;

    connection->ka_count = 0;
    connection->ts_created = time(NULL);
    connection->ts_assigned = time(NULL);
    connection->ts_available = 0;

    if (type == FLB_UPSTREAM_CONNECTION) {
        connection->net = &connection->upstream->net;
    }
    else if (type == FLB_DOWNSTREAM_CONNECTION) {
        connection->net = &connection->downstream->net;
    }

    assert(connection->net != NULL);

    MK_EVENT_ZERO(&connection->event);

    flb_connection_reset_connection_timeout(connection);
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

void flb_connection_set_connection_timeout(struct flb_connection *connection)
{
    time_t current_time;
    time_t timeout_time;

    assert(connection != NULL);

    if (connection->net->connect_timeout > 0) {
        current_time = time(NULL);
        timeout_time = current_time + connection->net->connect_timeout;

        connection->ts_connect_start = current_time;
        connection->ts_connect_timeout = timeout_time;
    }
}

void flb_connection_reset_connection_timeout(struct flb_connection *connection)
{
    assert(connection != NULL);

    connection->ts_connect_start = -1;
    connection->ts_connect_timeout = -1;
}
