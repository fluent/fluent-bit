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

#ifndef MK_STREAM_H
#define MK_STREAM_H

#include <monkey/mk_core.h>
#include <monkey/mk_plugin_net.h>

/*
 * Stream types: each stream can have a different
 * source of information and for hence it handler
 * may need to be different for each cases.
 */
#define MK_STREAM_RAW       0  /* raw data from buffer */
#define MK_STREAM_IOV       1  /* mk_iov struct        */
#define MK_STREAM_FILE      2  /* opened file          */
#define MK_STREAM_SOCKET    3  /* socket, scared..     */
#define MK_STREAM_COPYBUF   4  /* raw data, copy data into a dynamic buffer */
#define MK_STREAM_EOF       5  /* end of stream, trigger callback */

/* Channel return values for write event */
#define MK_CHANNEL_DONE     1  /* channel consumed all streams */
#define MK_CHANNEL_ERROR    2  /* exception when flusing data  */
#define MK_CHANNEL_FLUSH    4  /* channel flushed some data    */
#define MK_CHANNEL_EMPTY    8  /* no streams available         */
#define MK_CHANNEL_BUSY    16  /* cannot write, busy (EAGAIN)  */
#define MK_CHANNEL_UNKNOWN 32  /* unhandled                    */

/* Channel status */
#define MK_CHANNEL_DISABLED 0 /* channel is sleeping */
#define MK_CHANNEL_ENABLED  1 /* channel enabled, have some data */

/*
 * Channel types: by default the only channel supported
 * is a direct write to the network layer.
 */
#define MK_CHANNEL_SOCKET 0

/*
 * A channel represents an end-point of a stream, for short
 * where the stream data consumed is send to.
 */
struct mk_channel {
    int type;
    int fd;
    int status;

    struct mk_event *event;
    struct mk_plugin_network *io;
    struct mk_list streams;
};

/*
 * A stream represents an Input of data that can be consumed
 * from a specific resource given it's type.
 */
struct mk_stream {
    int type;              /* stream type                      */
    int fd;                /* file descriptor                  */
    int preserve;          /* preserve stream? (do not unlink) */
    int encoding;          /* some output encoding ?           */
    int dynamic;           /* dynamic allocated ?              */

    /* bytes info */
    size_t bytes_total;
    off_t  bytes_offset;

    /* the outgoing channel, we do this for all streams */
    struct mk_channel *channel;

    /*
     * Based on the stream type, 'data' could reference a RAW buffer
     * or a mk_iov struct.
     */
    void *buffer;

    /* Some data the user may want to reference with the stream (optional) */
    void *data;

    /* callbacks */
    void (*cb_finished) (struct mk_stream *);
    void (*cb_bytes_consumed) (struct mk_stream *, long);
    void (*cb_exception) (struct mk_stream *, int);

    /* Link to the Channel parent */
    struct mk_list _head;
};

static inline int mk_channel_is_empty(struct mk_channel *channel)
{
    return mk_list_is_empty(&channel->streams);
}

/* exported functions */
static inline void mk_channel_append_stream(struct mk_channel *channel,
                                            struct mk_stream *stream)
{
    mk_list_add(&stream->_head, &channel->streams);
}

static inline void mk_stream_set(struct mk_stream *stream,
                                 int type,
                                 struct mk_channel *channel,
                                 void *buffer,
                                 size_t size,
                                 void *data,
                                 void (*cb_finished) (struct mk_stream *),
                                 void (*cb_bytes_consumed) (struct mk_stream *, long),
                                 void (*cb_exception) (struct mk_stream *, int))
{
    struct mk_iov *iov;

    /*
     * The copybuf stream type it's a lazy stream mechanism on which the
     * stream it self and the buffer are allocated dynamically. It just
     * exists as an optional interface that do not care too much about
     * performance and aim to make things easier. The COPYBUF type is not
     * used by Monkey core, at the moment the only caller is the CGI plugin.
     */
    if (!stream) {
        stream = mk_mem_malloc(sizeof(struct mk_stream));
        stream->dynamic = MK_TRUE;
    }
    else {
        stream->dynamic = MK_FALSE;
    }

    stream->type         = type;
    stream->channel      = channel;
    stream->bytes_offset = 0;
    stream->buffer       = buffer;
    stream->data         = data;
    stream->preserve     = MK_FALSE;

    if (type == MK_STREAM_IOV) {
        iov = buffer;
        stream->bytes_total = iov->total_len;
    }
    else if (type == MK_STREAM_COPYBUF) {
        stream->buffer = mk_mem_malloc(size);
        stream->bytes_total = size;
        memcpy(stream->buffer, buffer, size);
    }
    else {
        stream->bytes_total = size;
    }

    /* callbacks */
    stream->cb_finished       = cb_finished;
    stream->cb_bytes_consumed = cb_bytes_consumed;
    stream->cb_exception      = cb_exception;

    mk_list_add(&stream->_head, &channel->streams);
}

static inline void mk_stream_unlink(struct mk_stream *stream)
{
    mk_list_del(&stream->_head);
}

/* Mark a specific number of bytes served (just on successfull flush) */
static inline void mk_stream_bytes_consumed(struct mk_stream *stream, long bytes)
{
#ifdef TRACE
    char *fmt = NULL;

    if (stream->type == MK_STREAM_RAW) {
        fmt = "[STREAM_RAW %p] bytes consumed %lu/%lu";
    }
    else if (stream->type == MK_STREAM_IOV) {
        fmt = "[STREAM_IOV %p] bytes consumed %lu/%lu";
    }
    else if (stream->type == MK_STREAM_FILE) {
        fmt = "[STREAM_FILE %p] bytes consumed %lu/%lu";
    }
    else if (stream->type == MK_STREAM_SOCKET) {
        fmt = "[STREAM_SOCK %p] bytes consumed %lu/%lu";
    }
    else if (stream->type == MK_STREAM_COPYBUF) {
        fmt = "[STREAM_CBUF %p] bytes consumed %lu/%lu";
    }
    else {
        fmt = "[STREAM_UNKW %p] bytes consumed %lu/%lu";
    }
    MK_TRACE(fmt, stream, bytes, stream->bytes_total);
#endif

    stream->bytes_total -= bytes;
}

static inline void mk_channel_debug(struct mk_channel *channel)
{
    int i = 0;
    struct mk_list *head;
    struct mk_stream *stream;

    printf("\n*** Channel ***\n");
    mk_list_foreach(head, &channel->streams) {
        stream = mk_list_entry(head, struct mk_stream, _head);
        switch (stream->type) {
        case MK_STREAM_RAW:
            printf("%i) [%p] STREAM RAW    : ", i, stream);
            break;
        case MK_STREAM_IOV:
            printf("%i) [%p] STREAM IOV    : ", i, stream);
            break;
        case MK_STREAM_FILE:
            printf("%i) [%p] STREAM FILE   : ", i, stream);
            break;
        case MK_STREAM_SOCKET:
            printf("%i) [%p] STREAM SOCKET : ", i, stream);
            break;
        case MK_STREAM_COPYBUF:
            printf("%i) [%p] STREAM COPYBUF: ", i, stream);
            break;
        }
#if defined(__APPLE__)
        printf("bytes=%lld/%lu\n", stream->bytes_offset, stream->bytes_total);
#else
        printf("bytes=%ld/%zu\n", stream->bytes_offset, stream->bytes_total);
#endif
        i++;
    }
}

struct mk_stream *mk_stream_new(int type, struct mk_channel *channel,
                                void *buffer, size_t size, void *data,
                                void (*cb_finished) (struct mk_stream *),
                                void (*cb_bytes_consumed) (struct mk_stream *, long),
                                void (*cb_exception) (struct mk_stream *, int));
struct mk_channel *mk_channel_new(int type, int fd);

int mk_channel_flush(struct mk_channel *channel);
int mk_channel_write(struct mk_channel *channel, size_t *count);
int mk_channel_clean(struct mk_channel *channel);

#endif
