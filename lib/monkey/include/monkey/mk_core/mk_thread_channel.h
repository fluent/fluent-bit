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

#ifndef MK_THREAD_CHANNEL_H
#define MK_THREAD_CHANNEL_H

#include <errno.h>
#include "mk_list.h"

#define MK_THREAD_CHANNEL_OK      0
#define MK_THREAD_CHANNEL_BROKEN  -EPIPE

struct mk_thread_channel {
    int size;
    int used;
    struct mk_list bufs;
    int sender;
    int receiver;
    int ended;
    int done;
    struct mk_list _head;
};

/*
 * @METHOD_NAME: chan_get_sender
 * @METHOD_DESC: get sender of the given channel.
 * @METHOD_PROTO: int chan_get_sender(mk_thread_channel_t *chan)
 * @METHOD_PARAM: chan the target channel.
 * @METHOD_RETURN: the dthread id of sender of the channel.
 */
static inline int mk_thread_channel_get_sender(struct mk_thread_channel *chan)
{
    return chan->sender;
}

/*
 * @METHOD_NAME: chan_set_sender
 * @METHOD_DESC: set sender of the given channel.
 * @METHOD_PROTO: void chan_set_sender(mk_thread_channel_t *chan, int sender)
 * @METHOD_PARAM: chan the target channel.
 * @METHOD_PARAM: sender the dthread id of target sender.
 * @METHOD_RETURN: this method do not return any value.
 */
static inline void mk_thread_channel_set_sender(struct mk_thread_channel *chan,
                                                int sender)
{
    chan->sender = sender;
}

/*
 * @METHOD_NAME: chan_get_receiver
 * @METHOD_DESC: get receiver of the given channel.
 * @METHOD_PROTO: int chan_get_receiver(mk_thread_channel_t *chan)
 * @METHOD_PARAM: chan the target channel.
 * @METHOD_RETURN: the dthread id of receiver of the channel.
 */
static inline int mk_thread_channel_get_receiver(struct mk_thread_channel *chan)
{
    return chan->receiver;
}

void mk_thread_add_channel(int id, struct mk_thread_channel *chan);

/*
 * @METHOD_NAME: chan_set_receiver
 * @METHOD_DESC: set receiver of the given channel.
 * @METHOD_PROTO: void chan_set_receiver(mk_thread_channel_t *chan, int receiver)
 * @METHOD_PARAM: chan the target channel.
 * @METHOD_PARAM: receiver the dthread id of target receiver.
 * @METHOD_RETURN: this method do not return any value.
 */
static inline void mk_thread_channel_set_receiver(struct mk_thread_channel *chan,
                                                  int receiver)
{
    chan->receiver = receiver;
    mk_thread_add_channel(receiver, chan);
}

/*
 * @METHOD_NAME: chan_done
 * @METHOD_DESC: whether the channel is no longer necessary(this will be the case
 * that a channel is empty and the sender won't send any more).
 * @METHOD_PROTO: int chan_done(mk_thread_channel_t *chan)
 * @METHOD_PARAM: chan the target channel.
 * @METHOD_RETURN: returns 1 if the channel is no longer necessary, otherwise 0.
 */
static inline int mk_thread_channel_done(struct mk_thread_channel *chan)
{
    return chan->done;
}

/*
 * @METHOD_NAME: chan_end
 * @METHOD_DESC: it is used by the sender to tell the channel no more data will be
 * sent.
 * @METHOD_PROTO: void chan_end(mk_thread_channel_t *chan)
 * @METHOD_PARAM: chan the target channel.
 * @METHOD_RETURN: this method do not return any value.
 */
static inline void mk_thread_channel_end(struct mk_thread_channel *chan)
{
    chan->ended = 1;
}

struct mk_thread_channel *mk_thread_channel_create(int size);
void mk_thread_channel_free(struct mk_thread_channel *chan);
int mk_thread_channel_send(struct mk_thread_channel *chan, void *data);
void *mk_thread_channel_recv(struct mk_thread_channel *chan);

#endif
