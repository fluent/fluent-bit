/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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
#include <monkey/mk_stream.h>
#include <assert.h>

/* Create a new channel */
struct mk_channel *mk_channel_new(int type, int fd)
{
    struct mk_channel *channel;

    channel = mk_mem_alloc(sizeof(struct mk_channel));
    if (!channel) {
        return NULL;
    }
    channel->type   = type;
    channel->fd     = fd;
    channel->status = MK_CHANNEL_OK;
    mk_list_init(&channel->streams);

    return channel;
}

int mk_channel_release(struct mk_channel *channel)
{
    mk_mem_free(channel);
    return 0;
}

static inline size_t channel_write_in_file(struct mk_channel *channel,
                                           struct mk_stream_input *in)
{
    ssize_t bytes = 0;

    MK_TRACE("[CH %i] STREAM_FILE [fd=%i], bytes=%lu",
             channel->fd, in->fd, in->bytes_total);

    /* Direct write */
    bytes = mk_sched_conn_sendfile(channel,
                                   in->fd,
                                   &in->bytes_offset,
                                   in->bytes_total
                                   );
    MK_TRACE("[CH=%d] [FD=%i] WRITE STREAM FILE: %lu bytes",
             channel->fd, in->fd, bytes);

    return bytes;
}

size_t mk_stream_size(struct mk_stream *stream)
{
    return (stream->bytes_total - stream->bytes_offset);
}

/*
 * It 'intent' to write a few streams over the channel and alter the
 * channel notification side if required: READ -> WRITE.
 */
int mk_channel_flush(struct mk_channel *channel)
{
    int ret = 0;
    size_t count = 0;
    size_t total = 0;
    uint32_t stop = (MK_CHANNEL_DONE | MK_CHANNEL_ERROR | MK_CHANNEL_EMPTY);

    do {
        ret = mk_channel_write(channel, &count);
        total += count;

#ifdef MK_HAVE_TRACE
        MK_TRACE("Channel flush: %d bytes", count);
        if (ret & MK_CHANNEL_DONE) {
            MK_TRACE("Channel was empty");
        }
        if (ret & MK_CHANNEL_ERROR) {
            MK_TRACE("Channel error");
        }
        if (ret & MK_CHANNEL_EMPTY) {
            MK_TRACE("Channel empty");
        }
#endif
    } while (total <= 4096 && ((ret & stop) == 0));

    if (ret == MK_CHANNEL_DONE) {
        MK_TRACE("Channel done");
        return ret;
    }
    else if (ret & (MK_CHANNEL_FLUSH | MK_CHANNEL_BUSY)) {
        MK_TRACE("Channel FLUSH | BUSY");
        if ((channel->event->mask & MK_EVENT_WRITE) == 0) {
            mk_event_add(mk_sched_loop(),
                         channel->fd,
                         MK_EVENT_CONNECTION,
                         MK_EVENT_WRITE,
                         channel->event);
        }
    }

    return ret;
}

int mk_stream_in_release(struct mk_stream_input *in)
{
    if (in->cb_finished) {
        in->cb_finished(in);
    }

    mk_stream_input_unlink(in);
    if (in->dynamic == MK_TRUE) {
        mk_mem_free(in);
    }

    return 0;
}

int mk_channel_stream_write(struct mk_stream *stream, size_t *count)
{
    ssize_t bytes = 0;
    struct mk_iov *iov;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_channel *channel;
    struct mk_stream_input *input;

    channel = stream->channel;

    /* Validate channel status */
    if (channel->status != MK_CHANNEL_OK) {
        return -MK_CHANNEL_ERROR;
    }

    /* Iterate inputs and process stream */
    mk_list_foreach_safe(head, tmp, &stream->inputs) {
        input = mk_list_entry(head, struct mk_stream_input, _head);
        if (input->type == MK_STREAM_FILE) {
            bytes = channel_write_in_file(channel, input);
        }
        else if (input->type == MK_STREAM_IOV) {
            iov = input->buffer;
            if (!iov) {
                return MK_CHANNEL_EMPTY;
            }

            bytes = mk_sched_conn_writev(channel, iov);

            MK_TRACE("[CH %i] STREAM_IOV, wrote %d bytes",
                     channel->fd, bytes);
            if (bytes > 0) {
                /* Perform the adjustment on mk_iov */
                mk_iov_consume(iov, bytes);
            }
        }
        else if (input->type == MK_STREAM_RAW) {
            bytes = mk_sched_conn_write(channel,
                                        input->buffer, input->bytes_total);
            MK_TRACE("[CH %i] STREAM_RAW, bytes=%lu/%lu\n",
                     channel->fd, bytes, input->bytes_total);
        }

        if (bytes > 0) {
            *count = bytes;
            mk_stream_input_consume(input, bytes);

            /* notification callback, optional */
            if (stream->cb_bytes_consumed) {
                stream->cb_bytes_consumed(stream, bytes);
            }

            if (input->cb_consumed) {
                input->cb_consumed(input, bytes);
            }

            if (input->bytes_total == 0) {
                MK_TRACE("Input done, unlinking (channel=%p)", channel);
                mk_stream_in_release(input);
            }
            MK_TRACE("[CH %i] CHANNEL_FLUSH", channel->fd);
        }
        else if (bytes < 0) {
            mk_stream_in_release(input);
            return -MK_CHANNEL_ERROR;
        }
        else if (bytes == 0) {
            mk_stream_in_release(input);
            return -MK_CHANNEL_ERROR;
        }
    }

    return bytes;
}

/* It perform a direct stream I/O write through the network layer */
int mk_channel_write(struct mk_channel *channel, size_t *count)
{
    ssize_t bytes = -1;
    struct mk_iov *iov;
    struct mk_stream *stream = NULL;
    struct mk_stream_input *input;

    errno = 0;

    if (mk_list_is_empty(&channel->streams) == 0) {
        MK_TRACE("[CH %i] CHANNEL_EMPTY", channel->fd);
        return MK_CHANNEL_EMPTY;
    }

    /* Get the input source */
    stream = mk_list_entry_first(&channel->streams, struct mk_stream, _head);
    if (mk_list_is_empty(&stream->inputs) == 0) {
        return MK_CHANNEL_EMPTY;
    }
    input = mk_list_entry_first(&stream->inputs, struct mk_stream_input, _head);

    /*
     * Based on the Stream Input type we consume on that way, not all inputs
     * requires to read from buffer, e.g: Static File, Pipes.
     */
    if (channel->type == MK_CHANNEL_SOCKET) {
        if (input->type == MK_STREAM_FILE) {
            bytes = channel_write_in_file(channel, input);
        }
        else if (input->type == MK_STREAM_IOV) {
            iov   = input->buffer;
            if (!iov) {
                return MK_CHANNEL_EMPTY;
            }

            bytes = mk_sched_conn_writev(channel, iov);

            MK_TRACE("[CH %i] STREAM_IOV, wrote %d bytes",
                     channel->fd, bytes);
            if (bytes > 0) {
                /* Perform the adjustment on mk_iov */
                mk_iov_consume(iov, bytes);
            }
        }
        else if (input->type == MK_STREAM_RAW) {
            bytes = mk_sched_conn_write(channel,
                                        input->buffer, input->bytes_total);
            MK_TRACE("[CH %i] STREAM_RAW, bytes=%lu/%lu",
                     channel->fd, bytes, input->bytes_total);
            if (bytes > 0) {
                /* DEPRECATED: consume_raw(input, bytes); */
            }
        }

        if (bytes > 0) {
            *count = bytes;
            mk_stream_input_consume(input, bytes);

            /* notification callback, optional */
            if (stream->cb_bytes_consumed) {
                stream->cb_bytes_consumed(stream, bytes);
            }

            if (input->cb_consumed) {
                input->cb_consumed(input, bytes);
            }

            if (input->bytes_total == 0) {
                MK_TRACE("Input done, unlinking (channel=%p)", channel);
                mk_stream_in_release(input);
            }

            if (mk_list_is_empty(&stream->inputs) == 0) {
                /* Everytime the stream is empty, we notify the trigger the cb */
                if (stream->cb_finished) {
                    stream->cb_finished(stream);
                }

                if (mk_channel_is_empty(channel) == 0) {
                    MK_TRACE("[CH %i] CHANNEL_DONE", channel->fd);
                    return MK_CHANNEL_DONE;
                }
                else {
                    MK_TRACE("[CH %i] CHANNEL_FLUSH", channel->fd);
                    return MK_CHANNEL_FLUSH;
                }
            }

            MK_TRACE("[CH %i] CHANNEL_FLUSH", channel->fd);
            return MK_CHANNEL_FLUSH;
        }
        else if (bytes < 0) {
            if (errno == EAGAIN) {
                return MK_CHANNEL_BUSY;
            }

            mk_stream_in_release(input);
            return MK_CHANNEL_ERROR;
        }
        else if (bytes == 0) {
            mk_stream_in_release(input);
            return MK_CHANNEL_ERROR;
        }
    }

    return MK_CHANNEL_ERROR;
}

/* Remove any dynamic memory associated */
int mk_channel_clean(struct mk_channel *channel)
{
    struct mk_list *tmp;
    struct mk_list *tmp_in;
    struct mk_list *head;
    struct mk_list *head_in;
    struct mk_stream *stream;
    struct mk_stream_input *in;

    mk_list_foreach_safe(head, tmp, &channel->streams) {
        stream = mk_list_entry(head, struct mk_stream, _head);
        mk_list_foreach_safe(head_in, tmp_in, &stream->inputs) {
            in = mk_list_entry(head_in, struct mk_stream_input, _head);
            mk_stream_in_release(in);
        }
        mk_stream_release(stream);
    }

    return 0;
}
