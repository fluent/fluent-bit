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
#include "utils.h"

#include <boost/python/suite/indexing/map_indexing_suite.hpp>

std::string MessageId_str(const MessageId& msgId) {
    std::stringstream ss;
    ss << msgId;
    return ss.str();
}

bool MessageId_eq(const MessageId& a, const MessageId& b) {
    return a == b;
}

bool MessageId_ne(const MessageId& a, const MessageId& b) {
    return a != b;
}

bool MessageId_lt(const MessageId& a, const MessageId& b) {
    return a < b;
}

bool MessageId_le(const MessageId& a, const MessageId& b) {
    return a <= b;
}

bool MessageId_gt(const MessageId& a, const MessageId& b) {
    return a > b;
}

bool MessageId_ge(const MessageId& a, const MessageId& b) {
    return a >= b;
}

boost::python::object MessageId_serialize(const MessageId& msgId) {
    std::string serialized;
    msgId.serialize(serialized);
    return boost::python::object(boost::python::handle<>(PyBytes_FromStringAndSize(serialized.c_str(), serialized.length())));
}

std::string Message_str(const Message& msg) {
    std::stringstream ss;
    ss << msg;
    return ss.str();
}

boost::python::object Message_data(const Message& msg) {
    return boost::python::object(boost::python::handle<>(PyBytes_FromStringAndSize((const char*)msg.getData(), msg.getLength())));
}

const MessageId& Message_getMessageId(const Message& msg) {
    return msg.getMessageId();
}

void export_message() {
    using namespace boost::python;

    MessageBuilder& (MessageBuilder::*MessageBuilderSetContentString)(const std::string&) = &MessageBuilder::setContent;

    class_<MessageBuilder, boost::noncopyable>("MessageBuilder")
            .def("content", MessageBuilderSetContentString, return_self<>())
            .def("property", &MessageBuilder::setProperty, return_self<>())
            .def("properties", &MessageBuilder::setProperties, return_self<>())
            .def("sequence_id", &MessageBuilder::setSequenceId, return_self<>())
            .def("partition_key", &MessageBuilder::setPartitionKey, return_self<>())
            .def("event_timestamp", &MessageBuilder::setEventTimestamp, return_self<>())
            .def("replication_clusters", &MessageBuilder::setReplicationClusters, return_self<>())
            .def("disable_replication", &MessageBuilder::disableReplication, return_self<>())
            .def("build", &MessageBuilder::build)
            ;

    class_<Message::StringMap>("MessageStringMap")
            .def(map_indexing_suite<Message::StringMap>())
            ;

    static const MessageId& _MessageId_earliest = MessageId::earliest();
    static const MessageId& _MessageId_latest = MessageId::latest();

    class_<MessageId>("MessageId")
            .def("__str__", &MessageId_str)
            .def("__eq__", &MessageId_eq)
            .def("__ne__", &MessageId_ne)
            .def("__le__", &MessageId_le)
            .def("__lt__", &MessageId_lt)
            .def("__ge__", &MessageId_ge)
            .def("__gt__", &MessageId_gt)
            .add_static_property("earliest", make_getter(&_MessageId_earliest))
            .add_static_property("latest", make_getter(&_MessageId_latest))
            .def("serialize", &MessageId_serialize)
            .def("deserialize", &MessageId::deserialize).staticmethod("deserialize")
            ;

    class_<Message>("Message")
            .def("properties", &Message::getProperties, return_value_policy<copy_const_reference>())
            .def("data", &Message_data)
            .def("length", &Message::getLength)
            .def("partition_key", &Message::getPartitionKey, return_value_policy<copy_const_reference>())
            .def("publish_timestamp", &Message::getPublishTimestamp)
            .def("event_timestamp", &Message::getEventTimestamp)
            .def("message_id", &Message_getMessageId, return_value_policy<copy_const_reference>())
            .def("__str__", &Message_str)
            ;
}
