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

/* Channel return values for write event */
#define MK_CHANNEL_OK       0  /* channel is ok (channel->status) */
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
 * where the stream data consumed and is send to. The channel
 * knows how to read/write to a TCP connection through a
 * defined network plugin.
 */
struct mk_channel {
    int type;
    int fd;
    int status;

    struct mk_event *event;
    struct mk_plugin_network *io;
    struct mk_list streams;
    void *thread;
};

/* Stream input source */
struct mk_stream_input {
    int type;              /* input type                      */
    int fd;                /* file descriptor (files)         */
    int dynamic;

    size_t bytes_total;    /* Total of data from the input    */
    off_t  bytes_offset;   /* Data already sent               */

    /*
     * Based on the stream input type, 'data' could reference a RAW buffer
     * or a mk_iov struct.
     */
    void *buffer;
    void *context;

    /* callbacks */
    void (*cb_consumed)(struct mk_stream_input *, long);
    void (*cb_finished)(struct mk_stream_input *);

    struct mk_stream *stream; /* reference to parent stream */
    struct mk_list _head;     /* link to inputs stream list */
};

/*
 * A stream holds a queue of components that refers to different
 * data sources such as: static file, raw buffer, etc.
 */
struct mk_stream {
    int preserve;          /* preserve stream? (do not unlink) */
    int encoding;          /* some output encoding ?           */
    int dynamic;           /* dynamic allocated ?              */

    size_t bytes_total;    /* Total of data from stream_input  */
    off_t  bytes_offset;   /* Data already sent                */

    /* the outgoing channel, we do this for all streams */
    struct mk_channel *channel;

    /* Context the caller may want to reference with the stream (optional) */
    void *context;

    /* callbacks */
    void (*cb_finished) (struct mk_stream *);
    void (*cb_bytes_consumed) (struct mk_stream *, long);
    void (*cb_exception) (struct mk_stream *, int);

    /* Head of stream_input nodes */
    struct mk_list inputs;

    /* Link to the Channel parent */
    struct mk_list _head;
};

int mk_stream_in_release(struct mk_stream_input *in);


static inline int mk_channel_is_empty(struct mk_channel *channel)
{
    return mk_list_is_empty(&channel->streams);
}

static inline void mk_channel_append_stream(struct mk_channel *channel,
                                            struct mk_stream *stream)
{
    mk_list_add(&stream->_head, &channel->streams);
}

static inline void mk_stream_append(struct mk_stream_input *in,
                                    struct mk_stream *stream)
{
    mk_list_add(&in->_head, &stream->inputs);
}

static inline int mk_stream_input(struct mk_stream *stream,
                                  struct mk_stream_input *in,
                                  int type,
                                  int fd,
                                  void *buffer, size_t size,
                                  off_t offset,
                                  void (*cb_consumed) (struct mk_stream_input *, long),
                                  void (*cb_finished)(struct mk_stream_input *))

{
    struct mk_iov *iov;

    if (!in) {
        in = mk_mem_alloc(sizeof(struct mk_stream_input));
        if (!in) {
            return -1;
        }
        in->dynamic  = MK_TRUE;
    }
    else {
        in->dynamic  = MK_FALSE;
    }

    in->fd           = fd;
    in->type         = type;
    in->bytes_offset = offset;
    in->buffer       = buffer;
    in->cb_consumed  = cb_consumed;
    in->cb_finished  = cb_finished;
    in->stream       = stream;

    if (type == MK_STREAM_IOV) {
        iov = buffer;
        in->bytes_total = iov->total_len;
    }
    else {
        in->bytes_total = size;
    }

    mk_list_add(&in->_head, &stream->inputs);
    return 0;
}

static inline int mk_stream_in_file(struct mk_stream *stream,
                                    struct mk_stream_input *in, int fd,
                                    size_t total_bytes,
                                    off_t offset,
                                    void (*cb_consumed)(struct mk_stream_input *, long),
                                    void (*cb_finished)(struct mk_stream_input *))

{
    return mk_stream_input(stream,
                           in,
                           MK_STREAM_FILE,
                           fd,
                           NULL, total_bytes, offset,
                           cb_consumed, cb_finished);
}

static inline int mk_stream_in_iov(struct mk_stream *stream,
                                   struct mk_stream_input *in,
                                   struct mk_iov *iov,
                                   void (*cb_consumed)(struct mk_stream_input *, long),
                                   void (*cb_finished)(struct mk_stream_input *))

{
    return mk_stream_input(stream,
                           in,
                           MK_STREAM_IOV,
                           0,
                           iov, 0, 0,
                           cb_consumed, cb_finished);
}

static inline int mk_stream_in_raw(struct mk_stream *stream,
                                   struct mk_stream_input *in,
                                   char *buf, size_t length,
                                   void (*cb_consumed)(struct mk_stream_input *, long),
                                   void (*cb_finished)(struct mk_stream_input *))
{
    return mk_stream_input(stream,
                           in,
                           MK_STREAM_RAW,
                           -1,
                           buf, length,
                           0,
                           cb_consumed, cb_finished);
}


static inline void mk_stream_release(struct mk_stream *stream)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_stream_input *in;

    /* Release any pending input */
    mk_list_foreach_safe(head, tmp, &stream->inputs) {
        in = mk_list_entry(head, struct mk_stream_input, _head);
        mk_stream_in_release(in);
    }

    if (stream->cb_finished) {
        stream->cb_finished(stream);
    }

    stream->channel = NULL;
    mk_list_del(&stream->_head);
    if (stream->dynamic == MK_TRUE) {
        mk_mem_free(stream);
    }
}

static inline
struct mk_stream *mk_stream_set(struct mk_stream *stream,
                                struct mk_channel *channel,
                                void *data,
                                void (*cb_finished) (struct mk_stream *),
                                void (*cb_bytes_consumed) (struct mk_stream *, long),
                                void (*cb_exception) (struct mk_stream *, int))
{
    /*
     * The copybuf stream type it's a lazy stream mechanism on which the
     * stream it self and the buffer are allocated dynamically. It just
     * exists as an optional interface that do not care too much about
     * performance and aim to make things easier. The COPYBUF type is not
     * used by Monkey core, at the moment the only caller is the CGI plugin.
     */
    if (!stream) {
        stream = mk_mem_alloc(sizeof(struct mk_stream));
        if (!stream) {
            return NULL;
        }
        stream->dynamic = MK_TRUE;
    }
    else {
        stream->dynamic = MK_FALSE;
    }

    stream->channel      = channel;
    stream->bytes_offset = 0;
    stream->context      = data;
    stream->preserve     = MK_FALSE;

    /* callbacks */
    stream->cb_finished       = cb_finished;
    stream->cb_bytes_consumed = cb_bytes_consumed;
    stream->cb_exception      = cb_exception;

    mk_list_init(&stream->inputs);
    mk_list_add(&stream->_head, &channel->streams);

    return stream;
}

static inline void mk_stream_input_unlink(struct mk_stream_input *in)
{
    mk_list_del(&in->_head);
}

/* Mark a specific number of bytes served (just on successfull flush) */
static inline void mk_stream_input_consume(struct mk_stream_input *in, long bytes)
{
#ifdef TRACE
    char *fmt = NULL;

    if (in->type == MK_STREAM_RAW) {
        fmt = "[INPUT_RAW %p] bytes consumed %lu/%lu";
    }
    else if (in->type == MK_STREAM_IOV) {
        fmt = "[INPUT_IOV %p] bytes consumed %lu/%lu";
    }
    else if (in->type == MK_STREAM_FILE) {
        fmt = "[INPUT_FILE %p] bytes consumed %lu/%lu";
    }
    else if (in->type == MK_STREAM_SOCKET) {
        fmt = "[INPUT_SOCK %p] bytes consumed %lu/%lu";
    }
    else if (in->type == MK_STREAM_COPYBUF) {
        fmt = "[INPUT_CBUF %p] bytes consumed %lu/%lu";
    }
    else {
        fmt = "[INPUT_UNKW %p] bytes consumed %lu/%lu";
    }
    MK_TRACE(fmt, in, bytes, in->bytes_total);
#endif

    in->bytes_total -= bytes;
}

#ifdef TRACE
static inline void mk_channel_debug(struct mk_channel *channel)
{
    int i = 0;
    int i_input;
    struct mk_list *head;
    struct mk_list *h_inputs;
    struct mk_stream *stream;
    struct mk_stream_input *in;

    printf("\n*** Channel ***\n");
    mk_list_foreach(head, &channel->streams) {
        stream = mk_list_entry(head, struct mk_stream, _head);
        i_input = 0;

        mk_list_foreach(h_inputs, &stream->inputs) {
            in = mk_list_entry(h_inputs, struct mk_stream_input, _head);
            switch (in->type) {
            case MK_STREAM_RAW:
                printf("     in.%i] %p RAW    : ", i_input, in);
                break;
            case MK_STREAM_IOV:
                printf("     in.%i] %p IOV    : ", i_input, in);
                break;
            case MK_STREAM_FILE:
                printf("     in.%i] %p FILE   : ", i_input, in);
                break;
            case MK_STREAM_SOCKET:
                printf("     in.%i] %p SOCKET : ", i_input, in);
                break;
            case MK_STREAM_COPYBUF:
                printf("     in.%i] %p COPYBUF: ", i_input, in);
                break;
            case MK_STREAM_EOF:
                printf("%i) [%p] STREAM EOF    : ", i, stream);
                break;
            }
#if defined(__APPLE__)
            printf("bytes=%lld/%lu\n", in->bytes_offset, in->bytes_total);
#else
            printf("bytes=%ld/%zu\n", in->bytes_offset, in->bytes_total);
#endif
            i_input++;
        }
    }
}
#endif

struct mk_stream *mk_stream_new(int type, struct mk_channel *channel,
                                void *buffer, size_t size, void *data,
                                void (*cb_finished) (struct mk_stream *),
                                void (*cb_bytes_consumed) (struct mk_stream *, long),
                                void (*cb_exception) (struct mk_stream *, int));

int mk_channel_stream_write(struct mk_stream *stream, size_t *count);

struct mk_channel *mk_channel_new(int type, int fd);
int mk_channel_release(struct mk_channel *channel);

int mk_channel_flush(struct mk_channel *channel);
int mk_channel_write(struct mk_channel *channel, size_t *count);
int mk_channel_clean(struct mk_channel *channel);
#endif
