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

import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

public class Util {
    public static void waitFor(TimeUnit unit, long duration, BooleanSupplier check) {
        waitFor(unit, duration, check, 100);
    }

    public static void waitFor(TimeUnit unit, long duration, BooleanSupplier check, int sleepInMillis) {
        long start = System.currentTimeMillis();
        long end = start + unit.toMillis(duration);
        while (end > System.currentTimeMillis()) {
            if (check.getAsBoolean()) {
                return;
            } else {
                sleep(TimeUnit.MILLISECONDS, sleepInMillis);
            }
        }
        throw new RuntimeException("Condition not satified!");
    }

    public static boolean isPortOpen(String host, int port) {
        try (Socket socket = new Socket(host, port)) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public static void sleep(TimeUnit timeUnit, long duration) {
        try {
            Thread.sleep(timeUnit.toMillis(duration));
        } catch (InterruptedException e) {
            // this is ok for our tests
        }
    }
}
