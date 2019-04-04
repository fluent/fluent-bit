/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
#include <pulsar/Producer.h>
#include "SharedBuffer.h"
#include <pulsar/MessageBuilder.h>

#include "Utils.h"
#include "ProducerImpl.h"

namespace pulsar {

static const std::string EMPTY_STRING;

Producer::Producer() : impl_() {}

Producer::Producer(ProducerImplBasePtr impl) : impl_(impl) {}

const std::string& Producer::getTopic() const { return impl_ != NULL ? impl_->getTopic() : EMPTY_STRING; }

Result Producer::send(const Message& msg) {
    Promise<Result, Message> promise;
    sendAsync(msg, WaitForCallbackValue<Message>(promise));

    Message m;
    Result result = promise.getFuture().get(m);
    return result;
}

void Producer::sendAsync(const Message& msg, SendCallback callback) {
    if (!impl_) {
        callback(ResultProducerNotInitialized, msg);
        return;
    }

    impl_->sendAsync(msg, callback);
}

const std::string& Producer::getProducerName() const { return impl_->getProducerName(); }

int64_t Producer::getLastSequenceId() const { return impl_->getLastSequenceId(); }

Result Producer::close() {
    Promise<bool, Result> promise;
    closeAsync(WaitForCallback(promise));

    Result result;
    promise.getFuture().get(result);
    return result;
}

void Producer::closeAsync(CloseCallback callback) {
    if (!impl_) {
        callback(ResultProducerNotInitialized);
        return;
    }

    impl_->closeAsync(callback);
}
}  // namespace pulsar
