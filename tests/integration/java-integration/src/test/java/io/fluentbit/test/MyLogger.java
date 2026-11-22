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

import org.komamitsu.fluency.Fluency;
import org.komamitsu.fluency.fluentd.FluencyBuilderForFluentd;

import java.io.IOException;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;

/**
 * This class emulates the application logger. It uses fluency as a library to talk to Fluent Bit.
 */
public class MyLogger implements AutoCloseable {

    private final Fluency fluency;
    private final ExpectedLogData expectedLogData;
    private final AtomicInteger submissionErrors = new AtomicInteger(0);

    public MyLogger(ExpectedLogData expectedLogData) {
        this.expectedLogData = expectedLogData;
        FluencyBuilderForFluentd builder = new FluencyBuilderForFluentd();
        builder.setAckResponseMode(true);
        builder.setBufferChunkInitialSize(64 * 1024);
        builder.setBufferChunkRetentionSize(128 * 1024);
        builder.setFlushAttemptIntervalMillis(100);
        builder.setJvmHeapBufferMode(false);
        builder.setMaxBufferSize((long) (64 * 1024 * 1024));
        fluency = builder.build(Config.getFluentBitHost(), Config.getFluentBitPort());
    }

    public void log(String data) {
        expectedLogData.addExpectation(data);
        try {
            fluency.emit("junit", Collections.singletonMap("data", data));
        } catch (IOException e) {
            // The errors not directly propagated, since this code will be called in a thread and then we need to handle the errors
            // in each and every test. The close method is propagating those errors later.
            e.printStackTrace();
            submissionErrors.incrementAndGet();
        }
    }

    @Override
    public void close() throws IOException {
        fluency.flush();
        fluency.close();
        assertEquals("MyLogger had submission errors", 0, submissionErrors.get());
    }
}
