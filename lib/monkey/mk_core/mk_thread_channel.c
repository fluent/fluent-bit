/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server (Duda I/O)
 *  -----------------------------
 *  Copyright 2017 Eduardo Silva <eduardo@monkey.io>
 *  Copyright 2014, Zeying Xie <swpdtz at gmail dot com>
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

#include <stdlib.h>
#include <assert.h>

#include <mk_core/mk_memory.h>
#include <mk_core/mk_thread.h>
#include <mk_core/mk_thread_channel.h>

struct mk_thread_channel_elem {
    void *data;
    struct mk_list _head;
};

struct mk_thread_channel_elem *mk_thread_channel_elem_create(void *data)
{
    struct mk_thread_channel_elem *elem;

    elem = mk_mem_alloc(sizeof(*elem));
    if (!elem) {
        return NULL;
    }
    elem->data = data;
    return elem;
}

static void mk_thread_channel_elem_free(struct mk_thread_channel_elem *elem)
{
    assert(elem);
    mk_list_del(&elem->_head);
    mk_mem_free(elem);
}

/*
 * @METHOD_NAME: chan_create
 * @METHOD_DESC: create a channel(pipe) for dthread communication.
 * @METHOD_PROTO: mk_thread_channel_t *chan_create(int size)
 * @METHOD_PARAM: size the buffered size of the channel.
 * @METHOD_RETURN: returns a new channel.
 */
struct mk_thread_channel *mk_thread_channel_create(int size)
{
    struct mk_thread_channel *chan;

    chan = mk_mem_alloc(sizeof(*chan));
    if (!chan) {
        return NULL;
    }

	chan->size = size + 1;
    chan->used = 0;
    mk_list_init(&chan->bufs);
    chan->sender = -1;
    chan->receiver = -1;
    chan->ended = 0;
    chan->done = 0;
	return chan;
}

/*
 * @METHOD_NAME: chan_free
 * @METHOD_DESC: release a given channel.
 * @METHOD_PROTO: void chan_free(mk_thread_channel_t *chan)
 * @METHOD_PARAM: chan the target channel to be released.
 * @METHOD_RETURN: this method do not return any value.
 */
void mk_thread_channel_free(struct mk_thread_channel *chan)
{
    assert(chan);
    if (chan->receiver != -1) {
        mk_list_del(&chan->_head);
    }
    mk_mem_free(chan);
}

/*
 * @METHOD_NAME: chan_send
 * @METHOD_DESC: add a new element to the given channel.
 * @METHOD_PROTO: int chan_send(mk_thread_channel_t *chan, void *data)
 * @METHOD_PARAM: chan the target channel to send.
 * @METHOD_PARAM: data the new element to be sent to channel.
 * @METHOD_RETURN: return THREAD_CHANNEL_BROKEN if the other side of the pipe
 * is closed, otherwise return THREAD_CHANNEL_OK.
 */
int mk_thread_channel_send(struct mk_thread_channel *chan, void *data)
{
    struct mk_thread_channel_elem *elem;

    assert(chan);
    if (chan->receiver == -1) {
        return MK_THREAD_CHANNEL_BROKEN;
    }
    if (chan->used == chan->size) {
        // channel is full
        mk_thread_resume(chan->receiver);
    }

    elem = mk_thread_channel_elem_create(data);
    mk_list_add(&elem->_head, &chan->bufs);
    chan->used++;
    return MK_THREAD_CHANNEL_OK;
}

/*
 * @METHOD_NAME: chan_recv
 * @METHOD_DESC: remove an element from a given channel.
 * @METHOD_PROTO: void *chan_recv(mk_thread_channel_t *chan)
 * @METHOD_PARAM: chan the target channel to receive.
 * @METHOD_RETURN: the front element of the channel.
 */
void *mk_thread_channel_recv(struct mk_thread_channel *chan)
{
    void *data;
    struct mk_thread_channel_elem *elem;

    assert(chan);
    assert(!chan->done);

    if (chan->used == 0) {
        /* channel is empty */
        mk_thread_resume(chan->sender);
    }

    elem = mk_list_entry_first(&chan->bufs, struct mk_thread_channel_elem, _head);
    data = elem->data;
    mk_thread_channel_elem_free(elem);
    chan->used--;
    if (chan->used == 0 && chan->ended) {
        chan->done = 1;
    }
    return data;
}
