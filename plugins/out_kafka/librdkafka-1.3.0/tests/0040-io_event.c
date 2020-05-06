/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2013, Magnus Edenhill
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met: 
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Tests the queue IO event signalling.
 */


#include "test.h"

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h"  /* for Kafka driver */

#include <fcntl.h>
#ifdef _MSC_VER
#include <io.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <poll.h>
#endif



int main_0040_io_event (int argc, char **argv) {
	rd_kafka_conf_t *conf;
	rd_kafka_topic_conf_t *tconf;
	rd_kafka_t *rk_p, *rk_c;
	const char *topic;
	rd_kafka_topic_t *rkt_p;
	rd_kafka_queue_t *queue;
	uint64_t testid;
        int msgcnt = test_quick ? 10 : 100;
	int recvd = 0;
	int fds[2];
	int wait_multiplier = 1;
	struct pollfd pfd;
        int r;
        rd_kafka_resp_err_t err;
	enum {
		_NOPE,
		_YEP,
		_REBALANCE
	} expecting_io = _REBALANCE;

#ifdef _MSC_VER
        TEST_SKIP("WSAPoll and pipes are not reliable on Win32 (FIXME)\n");
        return 0;
#endif
	testid = test_id_generate();
	topic = test_mk_topic_name(__FUNCTION__, 1);

	rk_p = test_create_producer();
	rkt_p = test_create_producer_topic(rk_p, topic, NULL);
	err = test_auto_create_topic_rkt(rk_p, rkt_p, tmout_multip(5000));
        TEST_ASSERT(!err, "Topic auto creation failed: %s",
                    rd_kafka_err2str(err));

	test_conf_init(&conf, &tconf, 0);
	rd_kafka_conf_set_events(conf, RD_KAFKA_EVENT_REBALANCE);
	test_conf_set(conf, "session.timeout.ms", "6000");
	test_conf_set(conf, "enable.partition.eof", "false");
	/* Speed up propagation of new topics */
	test_conf_set(conf, "metadata.max.age.ms", "1000");
	test_topic_conf_set(tconf, "auto.offset.reset", "earliest");
	rk_c = test_create_consumer(topic, NULL, conf, tconf);

	queue = rd_kafka_queue_get_consumer(rk_c);

	test_consumer_subscribe(rk_c, topic);

#ifndef _MSC_VER
        r = pipe(fds);
#else
        r = _pipe(fds, 2, _O_BINARY);
#endif
        if (r == -1)
		TEST_FAIL("pipe() failed: %s\n", strerror(errno));
	
	rd_kafka_queue_io_event_enable(queue, fds[1], "1", 1);

	pfd.fd = fds[0];
	pfd.events = POLLIN;
	pfd.revents = 0;

	/**
	 * 1) Wait for rebalance event
	 * 2) Wait 1 interval (1s) expecting no IO (nothing produced).
	 * 3) Produce half the messages
	 * 4) Expect IO
	 * 5) Consume the available messages
	 * 6) Wait 1 interval expecting no IO.
	 * 7) Produce remaing half
	 * 8) Expect IO
	 * 9) Done.
	 */
	while (recvd < msgcnt) {
		int r;

#ifndef _MSC_VER
		r = poll(&pfd, 1, 1000 * wait_multiplier);
#else
                r = WSAPoll(&pfd, 1, 1000 * wait_multiplier);
#endif
		if (r == -1) {
			TEST_FAIL("poll() failed: %s", strerror(errno));
			
		} else if (r == 1) {
			rd_kafka_event_t *rkev;
			char b;
			int eventcnt = 0;

			if (pfd.events & POLLERR)
				TEST_FAIL("Poll error\n");
			if (!(pfd.events & POLLIN)) {
				TEST_SAY("Stray event 0x%x\n", (int)pfd.events);
				continue;
			}

			TEST_SAY("POLLIN\n");
                        /* Read signaling token to purge socket queue and
                         * eventually silence POLLIN */
#ifndef _MSC_VER
			r = read(pfd.fd, &b, 1);
#else
			r = _read((int)pfd.fd, &b, 1);
#endif
			if (r == -1)
				TEST_FAIL("read failed: %s\n", strerror(errno));

			if (!expecting_io)
				TEST_WARN("Got unexpected IO after %d/%d msgs\n",
					  recvd, msgcnt);

			while ((rkev = rd_kafka_queue_poll(queue, 0))) {
				eventcnt++;
				switch (rd_kafka_event_type(rkev))
				{
				case RD_KAFKA_EVENT_REBALANCE:
					TEST_SAY("Got %s: %s\n", rd_kafka_event_name(rkev),
						 rd_kafka_err2str(rd_kafka_event_error(rkev)));
					if (expecting_io != _REBALANCE)
						TEST_FAIL("Got Rebalance when expecting message\n");
					if (rd_kafka_event_error(rkev) == RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS) {
						rd_kafka_assign(rk_c, rd_kafka_event_topic_partition_list(rkev));
						expecting_io = _NOPE;
					} else
						rd_kafka_assign(rk_c, NULL);
					break;
					
				case RD_KAFKA_EVENT_FETCH:
					if (expecting_io != _YEP)
						TEST_FAIL("Did not expect more messages at %d/%d\n",
							  recvd, msgcnt);
					recvd++;
					if (recvd == (msgcnt / 2) || recvd == msgcnt)
						expecting_io = _NOPE;
					break;

				case RD_KAFKA_EVENT_ERROR:
					TEST_FAIL("Error: %s\n", rd_kafka_event_error_string(rkev));
					break;

				default:
					TEST_SAY("Ignoring event %s\n", rd_kafka_event_name(rkev));
				}
					
				rd_kafka_event_destroy(rkev);
			}
			TEST_SAY("%d events, Consumed %d/%d messages\n", eventcnt, recvd, msgcnt);

			wait_multiplier = 1;

		} else {
			if (expecting_io == _REBALANCE) {
				continue;
			} else if (expecting_io == _YEP) {
				TEST_FAIL("Did not see expected IO after %d/%d msgs\n",
					  recvd, msgcnt);
			}

			TEST_SAY("IO poll timeout (good)\n");

			TEST_SAY("Got idle period, producing\n");
			test_produce_msgs(rk_p, rkt_p, testid, 0, recvd, msgcnt/2,
					  NULL, 10);

			expecting_io = _YEP;
			/* When running slowly (e.g., valgrind) it might take
			 * some time before the first message is received
			 * after producing. */
			wait_multiplier = 3;
		}
	}
	TEST_SAY("Done\n");

	rd_kafka_topic_destroy(rkt_p);
	rd_kafka_destroy(rk_p);

	rd_kafka_queue_destroy(queue);
	rd_kafka_consumer_close(rk_c);
	rd_kafka_destroy(rk_c);

#ifndef _MSC_VER
	close(fds[0]);
	close(fds[1]);
#else
        _close(fds[0]);
        _close(fds[1]);
#endif

	return 0;
}
