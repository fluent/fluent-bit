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

import org.junit.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static io.fluentbit.test.Util.sleep;
import static io.fluentbit.test.Util.waitFor;
import static org.junit.Assert.assertTrue;

public class IntegrationTest {


    /**
     * A very simple test. One message is send, all services are up and behaving.
     */
    @Test
    public void happyPathOneMessage() throws Exception {
        ExpectedLogData expectedLogData = new ExpectedLogData(1);
        try (LoggingDestinationServer loggingDestinationServer = new LoggingDestinationServer(expectedLogData)) {
            try (FluentBit fluentBit = new FluentBit()) {
                try (MyLogger logger = new MyLogger(expectedLogData)) {
                    logger.log("message");
                }
                // wait for up to 15 seconds for the message to be processed
                waitForMessagesProcessed(TimeUnit.SECONDS, 15, expectedLogData);
            }
        }
    }

    /**
     * This test starts to log a message, but the logging destination is down. After 15s it gets started. Fluent-Bit then needs to send that
     * log message upstream within 5 minutes.
     */
    @Test
    public void logDestinationDownOneMessage() throws Exception {
        ExpectedLogData expectedLogData = new ExpectedLogData(1);
        try (FluentBit fluentBit = new FluentBit()) {
            try (MyLogger logger = new MyLogger(expectedLogData)) {
                logger.log("message");
            }
            sleep(TimeUnit.SECONDS, 15);

            try (LoggingDestinationServer loggingDestinationServer = new LoggingDestinationServer(expectedLogData)) {
                // wait for up to 5 minutes for the message to be processed
                waitForMessagesProcessed(TimeUnit.MINUTES, 5, expectedLogData);
            }
        }
    }

    /**
     * This sends 25k messages reasonably fast. 25 threads are feeding into the fluency logging library (see https://github.com/komamitsu/fluency).
     * That doesn't mean that 25 threads are talking to fluent-bit, but it creates a decent amount of load. Between each message,
     * there is a very short pause to be a bit realistic.
     */
    @Test
    public void happyPathHighLoad() throws Exception {
        int threads = 25;
        int count = 25_000;

        CountDownLatch countDownLatch = new CountDownLatch(threads);
        ExecutorService executorService = Executors.newFixedThreadPool(threads);

        ExpectedLogData expectedLogData = new ExpectedLogData(count);
        try (LoggingDestinationServer loggingDestinationServer = new LoggingDestinationServer(expectedLogData)) {
            try (FluentBit fluentBit = new FluentBit()) {
                try (MyLogger logger = new MyLogger(expectedLogData)) {
                    for (int t = 0; t < threads; t++) {
                        int start = t * count;
                        int end = t * count + count;
                        executorService.submit(() -> {
                            countDownLatch.countDown();
                            for (int i = start; i < end; i++) {
                                sleep(TimeUnit.MILLISECONDS, 1);
                                logger.log(String.format("STARTaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%05dEND", i));
                            }
                        });
                    }
                    executorService.shutdown();
                    assertTrue("Failed to shutdown executorService", executorService.awaitTermination(15, TimeUnit.MINUTES));
                }
            }
            // wait for up to 15 minutes for the message to be processed
            waitForMessagesProcessed(TimeUnit.MINUTES, 15, expectedLogData);
        }
    }

    /**
     * Similar to happyPathHighLoad, but the messages are all sent and then the log destination is started. So fluent-bit needs to buffer
     * all the data.
     */
    @Test
    public void logDestinationDownHighLoad() throws Exception {
        int threads = 25;
        int count = 25_000;

        CountDownLatch countDownLatch = new CountDownLatch(threads);
        ExecutorService executorService = Executors.newFixedThreadPool(threads);

        ExpectedLogData expectedLogData = new ExpectedLogData(count);
        try (FluentBit fluentBit = new FluentBit()) {
            try (MyLogger logger = new MyLogger(expectedLogData)) {
                for (int t = 0; t < threads; t++) {
                    int start = t * count;
                    int end = t * count + count;
                    executorService.submit(() -> {
                        countDownLatch.countDown();
                        for (int i = start; i < end; i++) {
                            sleep(TimeUnit.MILLISECONDS, 1);
                            logger.log(String.format("STARTaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%05dEND", i));
                        }
                    });
                }
                executorService.shutdown();
                assertTrue("Failed to shutdown executorService", executorService.awaitTermination(15, TimeUnit.MINUTES));
            }
            try (LoggingDestinationServer loggingDestinationServer = new LoggingDestinationServer(expectedLogData)) {
                // wait for up to 45 minutes for the message to be processed
                waitForMessagesProcessed(TimeUnit.MINUTES, 45, expectedLogData);
            }
        }
    }

    /**
     * This methods waits for the messages to be processed. The provided duration is the maximum time. It checks every 5s if the messages
     * have arrived.
     */
    private void waitForMessagesProcessed(TimeUnit unit, long duration, ExpectedLogData expectedLogData) {
        waitFor(unit, duration, () -> expectedLogData.get()
                .entrySet()
                .stream()
                .noneMatch(x -> x.getValue().get() == 0), 5_000);
    }
}

