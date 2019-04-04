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
#pragma once

#include <boost/shared_ptr.hpp>

#pragma GCC visibility push(default)

namespace pulsar {

class Logger {
   public:
    enum Level
    {
        DEBUG = 0,
        INFO = 1,
        WARN = 2,
        ERROR = 3
    };

    virtual ~Logger() {}

    virtual bool isEnabled(Level level) = 0;

    virtual void log(Level level, int line, const std::string& message) = 0;
};

class LoggerFactory {
   public:
    virtual ~LoggerFactory() {}

    virtual Logger* getLogger(const std::string& fileName) = 0;
};

typedef boost::shared_ptr<LoggerFactory> LoggerFactoryPtr;
}  // namespace pulsar
#pragma GCC visibility pop
