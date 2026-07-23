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
import java.io.UncheckedIOException;
import java.net.URL;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import static io.fluentbit.test.Util.isPortOpen;
import static io.fluentbit.test.Util.waitFor;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * This class wraps the Fluent-Bit process.
 */
public class FluentBit implements AutoCloseable {

    private final Process fluentbit;

    public FluentBit() {
        URL config = FluentBit.class.getResource("/fluentbit.conf");
        if (config == null) {
            throw new RuntimeException("Can't find fluentbit.conf");
        }

        try {
            if (Config.getFluentBitStartCommand().isEmpty()) {
                Process dockerPull = new ProcessBuilder()
                        .inheritIO()
                        .command(Arrays.asList(
                                System.getenv().getOrDefault("CONTAINER_RUNTIME", "docker"),
                                "pull",
                                Config.getFluentBitDockerImage()))
                        .start();
                try {
                    dockerPull.waitFor(5, TimeUnit.MINUTES);
                } catch (InterruptedException e) {
                    // if we are interrupted, we just continue
                }
                int rc = dockerPull.exitValue();
                if (rc != 0) {
                    throw new RuntimeException("Failed to pull docker container, received RC " + rc);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to start Fluent-Bit", e);
        }

        try {
            ProcessBuilder processBuilder = new ProcessBuilder()
                    .inheritIO()
                    .command(
                            Config.getFluentBitStartCommand()
                                    .orElse(Arrays.asList(
                                            System.getenv().getOrDefault("CONTAINER_RUNTIME", "docker"),
                                            "run",
                                            "--rm",
                                            "-e", "LOG_DEST_HOST",
                                            "-e", "LOG_DEST_PORT",
                                            "--network=host",
                                            "-v", config.getPath() + ":/fluentbit.conf",
                                            Config.getFluentBitDockerImage(),
                                            "/fluent-bit/bin/fluent-bit", "-c", "/fluentbit.conf")));
            processBuilder.environment().put("LOG_DEST_HOST", Config.getLogDestinationHost());
            processBuilder.environment().put("LOG_DEST_PORT", Integer.toString(Config.getLogDestinationPort()));
            fluentbit = processBuilder.start();
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to start Fluent-Bit", e);
        }

        try {
            // we give it up to 1 minute to start
            waitFor(TimeUnit.MINUTES, 1, () -> isPortOpen(Config.getFluentBitHost(), Config.getFluentBitPort()));
            System.out.println("Fluent-Bit started");
        } catch (Throwable t) {
            System.err.println("Fluent-Bit is not starting...");
            fluentbit.destroyForcibly();
            throw t;
        }
    }

    @Override
    public void close() throws Exception {
        try {
            fluentbit.destroy();
            assertTrue("FluentBit did not stop after 1 minute", fluentbit.waitFor(1, TimeUnit.MINUTES));
            assertEquals(0, fluentbit.exitValue());
        } finally {
            // make sure the fluent-bit process is always terminated
            fluentbit.destroyForcibly();
        }
    }
}
