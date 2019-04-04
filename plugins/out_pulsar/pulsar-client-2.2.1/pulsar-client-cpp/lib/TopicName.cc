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
#include "NamedEntity.h"
#include "LogUtils.h"
#include "PartitionedProducerImpl.h"

#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/find.hpp>
#include <boost/make_shared.hpp>
#include <lib/TopicName.h>
#include <vector>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <exception>

DECLARE_LOG_OBJECT()
namespace pulsar {

typedef boost::unique_lock<boost::mutex> Lock;
// static members
CURL* TopicName::curl = NULL;
boost::mutex TopicName::curlHandleMutex;

CURL* TopicName::getCurlHandle() {
    if (curl == NULL) {
        // this handle can not be shared across threads, so had to get here everytime
        curl = curl_easy_init();
    }
    return curl;
}
//********************************************************************
TopicName::TopicName() {}

bool TopicName::init(const std::string& topicName) {
    topicName_ = topicName;
    if (topicName.find("://") == std::string::npos) {
        std::string topicNameCopy_ = topicName;
        std::vector<std::string> pathTokens;
        boost::algorithm::split(pathTokens, topicNameCopy_, boost::algorithm::is_any_of("/"));
        if (pathTokens.size() == 3) {
            topicName_ = "persistent://" + pathTokens[0] + "/" + pathTokens[1] + "/" + pathTokens[2];
        } else if (pathTokens.size() == 1) {
            topicName_ = "persistent://public/default/" + pathTokens[0];
        } else {
            LOG_ERROR(
                "Topic name is not valid, short topic name should be in the format of '<topic>' or "
                "'<property>/<namespace>/<topic>' - "
                << topicName);
            return false;
        }
    }
    isV2Topic_ = parse(topicName_, domain_, property_, cluster_, namespacePortion_, localName_);
    if (isV2Topic_ && !cluster_.empty()) {
        LOG_ERROR("V2 Topic name is not valid, cluster is not empty - " << topicName_ << " : cluster "
                                                                        << cluster_);
        return false;
    } else if (!isV2Topic_ && cluster_.empty()) {
        LOG_ERROR("V1 Topic name is not valid, cluster is empty - " << topicName_);
        return false;
    }
    if (localName_.empty()) {
        LOG_ERROR("Topic name is not valid, topic name is empty - " << topicName_);
        return false;
    }
    if (isV2Topic_ && cluster_.empty()) {
        namespaceName_ = NamespaceName::get(property_, namespacePortion_);
    } else {
        namespaceName_ = NamespaceName::get(property_, cluster_, namespacePortion_);
    }
    return true;
}
bool TopicName::parse(const std::string& topicName, std::string& domain, std::string& property,
                      std::string& cluster, std::string& namespacePortion, std::string& localName) {
    std::string topicNameCopy = topicName;
    boost::replace_first(topicNameCopy, "://", "/");
    std::vector<std::string> pathTokens;
    boost::algorithm::split(pathTokens, topicNameCopy, boost::algorithm::is_any_of("/"));
    if (pathTokens.size() < 4) {
        LOG_ERROR("Topic name is not valid, does not have enough parts - " << topicName);
        return false;
    }
    domain = pathTokens[0];
    size_t numSlashIndexes;
    bool isV2Topic;
    if (pathTokens.size() == 4) {
        // New topic name without cluster name
        property = pathTokens[1];
        cluster = "";
        namespacePortion = pathTokens[2];
        localName = pathTokens[3];
        numSlashIndexes = 3;
        isV2Topic = true;
    } else {
        // Legacy topic name that includes cluster name
        property = pathTokens[1];
        cluster = pathTokens[2];
        namespacePortion = pathTokens[3];
        localName = pathTokens[4];
        numSlashIndexes = 4;
        isV2Topic = false;
    }
    size_t slashIndex = -1;
    // find `numSlashIndexes` '/', whatever is left is topic local name
    for (int i = 0; i < numSlashIndexes; i++) {
        slashIndex = topicNameCopy.find('/', slashIndex + 1);
    }
    // get index to next char to '/'
    slashIndex++;
    localName = topicNameCopy.substr(slashIndex, (topicNameCopy.size() - slashIndex));
    return isV2Topic;
}
std::string TopicName::getEncodedName(const std::string& nameBeforeEncoding) {
    Lock lock(curlHandleMutex);
    std::string nameAfterEncoding;
    if (getCurlHandle()) {
        char* encodedName =
            curl_easy_escape(getCurlHandle(), nameBeforeEncoding.c_str(), nameBeforeEncoding.size());
        if (encodedName) {
            nameAfterEncoding.assign(encodedName);
            curl_free(encodedName);
        } else {
            LOG_ERROR("Unable to encode the name using curl_easy_escape, name - " << nameBeforeEncoding);
        }
    } else {
        LOG_ERROR("Unable to get CURL handle to encode the name - " << nameBeforeEncoding);
    }
    return nameAfterEncoding;
}

bool TopicName::isV2Topic() { return isV2Topic_; }

std::string TopicName::getDomain() { return domain_; }

std::string TopicName::getProperty() { return property_; }

std::string TopicName::getCluster() { return cluster_; }

std::string TopicName::getNamespacePortion() { return namespacePortion_; }

std::string TopicName::getLocalName() { return localName_; }

std::string TopicName::getEncodedLocalName() { return getEncodedName(localName_); }

bool TopicName::operator==(const TopicName& other) {
    return (this->topicName_.compare(other.topicName_) == 0);
}

bool TopicName::validate() {
    // check domain matches to "persistent", in future check "memory" when server is ready
    if (domain_.compare("persistent") != 0 && domain_.compare("non-persistent") != 0) {
        return false;
    }
    // cluster_ can be empty
    if (!isV2Topic_ && !property_.empty() && !cluster_.empty() && !namespacePortion_.empty() &&
        !localName_.empty()) {
        // v1 topic format
        return NamedEntity::checkName(property_) && NamedEntity::checkName(cluster_) &&
               NamedEntity::checkName(namespacePortion_);
    } else if (isV2Topic_ && !property_.empty() && !namespacePortion_.empty() && !localName_.empty()) {
        // v2 topic format
        return NamedEntity::checkName(property_) && NamedEntity::checkName(namespacePortion_);
    } else {
        return false;
    }
}

boost::shared_ptr<TopicName> TopicName::get(const std::string& topicName) {
    boost::shared_ptr<TopicName> ptr(new TopicName());
    if (!ptr->init(topicName)) {
        LOG_ERROR("Topic name initialization failed");
        return boost::shared_ptr<TopicName>();
    }
    if (ptr->validate()) {
        return ptr;
    } else {
        LOG_ERROR("Topic name validation Failed - " << topicName);
        return boost::shared_ptr<TopicName>();
    }
}

// TODO - for now return empty string if there's any error in format, later think about better error handling
std::string TopicName::getLookupName() {
    std::stringstream ss;
    std::string seperator("/");
    if (isV2Topic_ && cluster_.empty()) {
        ss << domain_ << seperator << property_ << seperator << namespacePortion_ << seperator
           << getEncodedLocalName();
    } else {
        ss << domain_ << seperator << property_ << seperator << cluster_ << seperator << namespacePortion_
           << seperator << getEncodedLocalName();
    }
    return ss.str();
}

std::string TopicName::toString() {
    std::stringstream ss;
    std::string seperator("/");
    if (isV2Topic_ && cluster_.empty()) {
        ss << domain_ << "://" << property_ << seperator << namespacePortion_ << seperator << localName_;
    } else {
        ss << domain_ << "://" << property_ << seperator << cluster_ << seperator << namespacePortion_
           << seperator << localName_;
    }
    return ss.str();
}

const std::string TopicName::getTopicPartitionName(unsigned int partition) {
    std::stringstream topicPartitionName;
    // make this topic name as well
    topicPartitionName << toString() << PartitionedProducerImpl::PARTITION_NAME_SUFFIX << partition;
    return topicPartitionName.str();
}

NamespaceNamePtr TopicName::getNamespaceName() { return namespaceName_; }

}  // namespace pulsar
