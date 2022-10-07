/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019, Magnus Edenhill
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

extern "C" {
#include "rdkafka.h"            /* For interceptor interface */
#include "../src/tinycthread.h" /* For mutexes */
}

class myThreadCb {
 public:
  myThreadCb() : startCnt_(0), exitCnt_(0) {
    mtx_init(&lock_, mtx_plain);
  }
  ~myThreadCb() {
    mtx_destroy(&lock_);
  }
  int startCount() {
    int cnt;
    mtx_lock(&lock_);
    cnt = startCnt_;
    mtx_unlock(&lock_);
    return cnt;
  }
  int exitCount() {
    int cnt;
    mtx_lock(&lock_);
    cnt = exitCnt_;
    mtx_unlock(&lock_);
    return cnt;
  }
  virtual void thread_start_cb(const char *threadname) {
    Test::Say(tostr() << "Started thread: " << threadname << "\n");
    mtx_lock(&lock_);
    startCnt_++;
    mtx_unlock(&lock_);
  }
  virtual void thread_exit_cb(const char *threadname) {
    Test::Say(tostr() << "Exiting from thread: " << threadname << "\n");
    mtx_lock(&lock_);
    exitCnt_++;
    mtx_unlock(&lock_);
  }

 private:
  int startCnt_;
  int exitCnt_;
  mtx_t lock_;
};


/**
 * @brief C to C++ callback trampoline.
 */
static rd_kafka_resp_err_t on_thread_start_trampoline(
    rd_kafka_t *rk,
    rd_kafka_thread_type_t thread_type,
    const char *threadname,
    void *ic_opaque) {
  myThreadCb *threadcb = (myThreadCb *)ic_opaque;

  Test::Say(tostr() << "on_thread_start(" << thread_type << ", " << threadname
                    << ") called\n");

  threadcb->thread_start_cb(threadname);

  return RD_KAFKA_RESP_ERR_NO_ERROR;
}

/**
 * @brief C to C++ callback trampoline.
 */
static rd_kafka_resp_err_t on_thread_exit_trampoline(
    rd_kafka_t *rk,
    rd_kafka_thread_type_t thread_type,
    const char *threadname,
    void *ic_opaque) {
  myThreadCb *threadcb = (myThreadCb *)ic_opaque;

  Test::Say(tostr() << "on_thread_exit(" << thread_type << ", " << threadname
                    << ") called\n");

  threadcb->thread_exit_cb(threadname);

  return RD_KAFKA_RESP_ERR_NO_ERROR;
}

/**
 * @brief This interceptor is called when a new client instance is created
 *        prior to any threads being created.
 *        We use it to set up the instance's thread interceptors.
 */
static rd_kafka_resp_err_t on_new(rd_kafka_t *rk,
                                  const rd_kafka_conf_t *conf,
                                  void *ic_opaque,
                                  char *errstr,
                                  size_t errstr_size) {
  Test::Say("on_new() interceptor called\n");
  rd_kafka_interceptor_add_on_thread_start(
      rk, "test:0100", on_thread_start_trampoline, ic_opaque);
  rd_kafka_interceptor_add_on_thread_exit(rk, "test:0100",
                                          on_thread_exit_trampoline, ic_opaque);
  return RD_KAFKA_RESP_ERR_NO_ERROR;
}

/**
 * @brief The on_conf_dup() interceptor let's use add the on_new interceptor
 *        in case the config object is copied, since interceptors are not
 *        automatically copied.
 */
static rd_kafka_resp_err_t on_conf_dup(rd_kafka_conf_t *new_conf,
                                       const rd_kafka_conf_t *old_conf,
                                       size_t filter_cnt,
                                       const char **filter,
                                       void *ic_opaque) {
  Test::Say("on_conf_dup() interceptor called\n");
  return rd_kafka_conf_interceptor_add_on_new(new_conf, "test:0100", on_new,
                                              ic_opaque);
}



static void test_thread_cbs() {
  RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
  std::string errstr;
  rd_kafka_conf_t *c_conf;
  myThreadCb my_threads;

  Test::conf_set(conf, "bootstrap.servers", "127.0.0.1:1");

  /* Interceptors are not supported in the C++ API, instead use the C API:
   *  1. Extract the C conf_t object
   *  2. Set up an on_new() interceptor
   *  3. Set up an on_conf_dup() interceptor to add interceptors in the
   *     case the config object is copied (which the C++ Conf always does).
   *  4. In the on_new() interceptor, add the thread interceptors. */
  c_conf = conf->c_ptr_global();
  rd_kafka_conf_interceptor_add_on_new(c_conf, "test:0100", on_new,
                                       &my_threads);
  rd_kafka_conf_interceptor_add_on_conf_dup(c_conf, "test:0100", on_conf_dup,
                                            &my_threads);

  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create Producer: " + errstr);
  p->poll(500);
  delete conf;
  delete p;

  Test::Say(tostr() << my_threads.startCount() << " thread start calls, "
                    << my_threads.exitCount() << " thread exit calls seen\n");

  /* 3 = rdkafka main thread + internal broker + bootstrap broker */
  if (my_threads.startCount() < 3)
    Test::Fail("Did not catch enough thread start callback calls");
  if (my_threads.exitCount() < 3)
    Test::Fail("Did not catch enough thread exit callback calls");
  if (my_threads.startCount() != my_threads.exitCount())
    Test::Fail("Did not catch same number of start and exit callback calls");
}


extern "C" {
int main_0100_thread_interceptors(int argc, char **argv) {
  test_thread_cbs();
  return 0;
}
}
