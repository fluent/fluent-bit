/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <monkey/monkey.h>
#include <monkey/mk_core.h>
#include <monkey/mk_stream.h>
#include <monkey/mk_scheduler.h>

/* Create a new stream instance */
struct mk_stream *mk_stream_new(int type, struct mk_channel *channel,
                           void *buffer, size_t size, void *data,
                           void (*cb_finished) (struct mk_stream *),
                           void (*cb_bytes_consumed) (struct mk_stream *, long),
                           void (*cb_exception) (struct mk_stream *, int))
{
    struct mk_stream *stream;

    stream = mk_mem_malloc(sizeof(struct mk_stream));
    mk_stream_set(stream, type, channel,
                  buffer, size,
                  data,
                  cb_finished,
                  cb_bytes_consumed,
                  cb_exception);

    return stream;
}


/* Create a new channel */
struct mk_channel *mk_channel_new(int type, int fd)
{
    struct mk_channel *channel;

    channel = mk_mem_malloc(sizeof(struct mk_channel));
    channel->type = type;
    channel->fd   = fd;

    mk_list_init(&channel->streams);

    return channel;
}

static inline size_t channel_write_stream_file(struct mk_channel *channel,
                                               struct mk_stream *stream)
{
    ssize_t bytes = 0;

    MK_TRACE("[CH %i] STREAM_FILE %i, bytes=%lu",
             channel->fd, stream->fd, stream->bytes_total);

    /* Direct write */
    bytes = mk_sched_conn_sendfile(channel,
                                    stream->fd,
                                    &stream->bytes_offset,
                                    stream->bytes_total
                                    );
    MK_TRACE("[CH=%d] [FD=%i] WRITE STREAM FILE: %lu bytes",
             channel->fd, stream->fd, bytes);

    return bytes;
}

static inline void mk_copybuf_consume(struct mk_stream *stream, size_t bytes)
{
    /*
     * Copybuf is a dynamic buffer allocated when the stream was configured,
     * if the number of bytes consumed is equal to the total size, the buffer
     * can be freed, otherwise we need to adjust the buffer for the next
     * round of 'write'.
     *
     * Note: we don't touch the stream->bytes_total field as this is adjusted
     * on the caller mk_channel_write().
     */
    if (bytes == stream->bytes_total) {
        mk_mem_free(stream->buffer);
    }
    else {
        memmove(stream->buffer,
                stream->buffer + bytes,
                stream->bytes_total - bytes);
    }
}

/*
 * It 'intent' to write a few streams over the channel and alter the
 * channel notification side if required: READ -> WRITE.
 */
int mk_channel_flush(struct mk_channel *channel)
{
    int ret = 0;
    size_t count;
    size_t total = 0;

    do {
        ret = mk_channel_write(channel, &count);
        total += count;
    } while (total <= 4096 && //sched->mem_pagesize &&
             (ret & ~(MK_CHANNEL_DONE | MK_CHANNEL_ERROR | MK_CHANNEL_EMPTY)));

    if (ret == MK_CHANNEL_DONE) {
        return ret;
    }
    else if (ret & (MK_CHANNEL_FLUSH | MK_CHANNEL_BUSY)) {
        if (channel->event.mask & ~MK_EVENT_WRITE) {
            mk_event_add(mk_sched_loop(),
                         channel->event.fd,
                         MK_EVENT_CONNECTION,
                         MK_EVENT_WRITE,
                         (void *) &channel->event);
        }
    }

    return ret;
}

/* It perform a direct stream I/O write through the network layer */
int mk_channel_write(struct mk_channel *channel, size_t *count)
{
    ssize_t bytes = -1;
    struct mk_iov *iov;
    mk_ptr_t *ptr;
    struct mk_stream *stream;

    if (mk_list_is_empty(&channel->streams) == 0) {
        MK_TRACE("[CH %i] CHANNEL_EMPTY", channel->fd);
        return MK_CHANNEL_EMPTY;
    }

    /* Get the input source */
    stream = mk_list_entry_first(&channel->streams, struct mk_stream, _head);

    /*
     * Based on the Stream type we consume on that way, not all inputs
     * requires to read from buffer, e.g: Static File, Pipes.
     */
    if (channel->type == MK_CHANNEL_SOCKET) {
        if (stream->type == MK_STREAM_FILE) {
            bytes = channel_write_stream_file(channel, stream);
        }
        else if (stream->type == MK_STREAM_IOV) {
            MK_TRACE("[CH %i] STREAM_IOV, wrote %lu bytes",
                     channel->fd, stream->bytes_total);

            iov   = stream->buffer;
            bytes = mk_sched_conn_writev(channel, iov);
            if (bytes > 0) {
                /* Perform the adjustment on mk_iov */
                mk_iov_consume(iov, bytes);
            }
        }
        else if (stream->type == MK_STREAM_PTR) {
            MK_TRACE("[CH %i] STREAM_PTR, bytes=%lu",
                     channel->fd, stream->bytes_total);

            ptr = stream->buffer;
            bytes = mk_sched_conn_write(channel, ptr->data, ptr->len);
            if (bytes > 0) {
                /* FIXME OFFSET */
            }
        }
        else if (stream->type == MK_STREAM_COPYBUF) {
            MK_TRACE("[CH %i] STREAM_COPYBUF, bytes=%lu",
                     channel->fd, stream->bytes_total);
            bytes = mk_sched_conn_write(channel,
                                        stream->buffer, stream->bytes_total);
            if (bytes > 0) {
                mk_copybuf_consume(stream, bytes);
            }
        }

        if (bytes > 0) {
            *count = bytes;
            mk_stream_bytes_consumed(stream, bytes);

            /* notification callback, optional */
            if (stream->cb_bytes_consumed) {
                stream->cb_bytes_consumed(stream, bytes);
            }

            if (stream->bytes_total == 0) {
                MK_TRACE("Stream done, unlinking");

                if (stream->cb_finished) {
                    stream->cb_finished(stream);
                }

                if (stream->preserve == MK_FALSE) {
                    mk_stream_unlink(stream);
                }
            }

            if (mk_list_is_empty(&channel->streams) == 0) {
                MK_TRACE("[CH %i] CHANNEL_DONE", channel->fd);
                return MK_CHANNEL_DONE;
            }

            MK_TRACE("[CH %i] CHANNEL_FLUSH", channel->fd);
            return MK_CHANNEL_FLUSH;
        }
        else if (bytes < 0) {
            if (errno == EAGAIN) {
                return MK_CHANNEL_BUSY;
            }
            return MK_CHANNEL_ERROR;
        }
        else if (bytes == 0) {
            if (stream->cb_exception) {
                stream->cb_exception(stream, errno);
            }
            return MK_CHANNEL_ERROR;
        }
    }

    return MK_CHANNEL_UNKNOWN;
}
