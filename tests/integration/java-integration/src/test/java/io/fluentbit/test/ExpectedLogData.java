/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2022 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
package io.fluentbit.test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.UncheckedIOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * This class keeps track of the log messages expected and how often they were received.
 */
public class ExpectedLogData {
    private final Map<String, AtomicInteger> expectedLogData;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ExpectedLogData(int count) {
        this.expectedLogData = Collections.synchronizedMap(new HashMap<>(count));
    }

    public void addExpectation(String data) {
        AtomicInteger existing = expectedLogData.put(data, new AtomicInteger(0));
        if (existing != null) {
            throw new RuntimeException("Duplicated data " + data);
        }
    }

    public void dataReceived(String data) {
        try {
            AtomicInteger counter = expectedLogData.get(objectMapper.readValue(data, LogEntry.class).getData());
            if (counter == null) {
                throw new RuntimeException("Can't find for '%s' the counter. Logical error in the test? Or data completely broken by Fluent-Bit?");
            }
            counter.incrementAndGet();
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(String.format("Cant parse '%s'", e), e);
        }
    }

    public Map<String, AtomicInteger> get() {
        return expectedLogData;
    }
}
