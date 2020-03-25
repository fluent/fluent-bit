/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2015, Magnus Edenhill
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

#include <iostream>
#include "testcpp.h"


 /**
   * @brief Test log callbacks and log queues
   */

class myLogCb : public RdKafka::EventCb {
private:
        enum {
                _EXP_NONE,
                _EXP_LOG
        } state_;
        int cnt_;
public:
        myLogCb (): state_(_EXP_NONE), cnt_(0) {}
        void expecting (bool b) {
                state_ = b ? _EXP_LOG : _EXP_NONE;
        }
        int count () {
                return cnt_;
        }
        void event_cb (RdKafka::Event &event) {
                switch (event.type())
                {
                  case RdKafka::Event::EVENT_LOG:
                                cnt_++;
                                Test::Say(tostr() << "Log: " <<
                                          "level " << event.severity() <<
                                          ", facility " << event.fac() <<
                                          ", str " << event.str() << "\n");
                                if (state_ != _EXP_LOG)
                                        Test::Fail("Received unexpected "
                                                   "log message");
                                break;
                        default:
                                break;
                }
        }
};

static void test_log (std::string what, bool main_queue) {
        RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
        myLogCb my_log;
        std::string errstr;

        Test::conf_set(conf, "client.id", test_curr_name());
        Test::conf_set(conf, "debug", "generic"); // generate some logs
        Test::conf_set(conf, "log.queue", "true");

        if (conf->set("event_cb", &my_log, errstr) != RdKafka::Conf::CONF_OK)
                Test::Fail(errstr);

        Test::Say(what + "Creating producer, not expecting any log messages\n");
        my_log.expecting(false);
        RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
        if (!p)
                Test::Fail(what + "Failed to create Producer: " + errstr);
        delete conf;

        RdKafka::Queue *queue = NULL;
        if (!main_queue) {
                queue = RdKafka::Queue::create(p);
                queue->poll(1000);
        } else {
                p->poll(1000);
        }

        Test::Say(what + "Setting log queue\n");
        p->set_log_queue(queue); /* Redirect logs to main queue */

        Test::Say(what + "Expecting at least one log message\n");
        my_log.expecting(true);
        if (queue)
                queue->poll(1000);
        else
                p->poll(1000);  /* Should not spontaneously call logs */

        Test::Say(tostr() << what << "Saw " << my_log.count() << " logs\n");
        if (my_log.count() < 1)
                Test::Fail(what + "No logs seen: expected at least one broker "
                           "failure");

        if (queue)
                delete queue;
        delete(p);
}

extern "C" {
        int main_0058_log (int argc, char **argv) {
                test_log("main.queue: ", true);
                test_log("local.queue: ", false);
                return 0;
        }
}
