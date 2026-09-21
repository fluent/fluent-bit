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

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * This class allows to configure the test run via environment variables.
 */
public class Config {
    private static final int DEFAULT_FLUENTBIT_PORT = 24224;
    private static final int DEFAULT_LOG_DEST_PORT = 5170;

    /**
     * @return the Fluent-Bit host. This is used by the application logger. If you let Fluent-Bit run somewhere else,
     * you might want to change it.
     */
    public static String getFluentBitHost() {
        return Optional.ofNullable(System.getenv("FLUENTBIT_HOST")).orElse("127.0.0.1");
    }

    /**
     * @return the Fluent-Bit port. This is used by the application logger. If you let Fluent-Bit run somewhere else,
     * you might want to change it.
     */
    public static int getFluentBitPort() {
        return Optional.ofNullable(System.getenv("FLUENTBIT_PORT")).map(Integer::parseInt).orElse(DEFAULT_FLUENTBIT_PORT);
    }

    /**
     * @return the hostname of the logging destination. This is used by the default fluentbit.conf and also by the logging destination server itself
     * so it knows on which IP to listen
     */
    public static String getLogDestinationHost() {
        return Optional.ofNullable(System.getenv("LOG_DEST_HOST")).orElse("127.0.0.1");
    }

    /**
     * @return the port of the logging destination. This is used by the default fluentbit.conf and also by the logging destination server itself
     * so it knows on which port to listen
     */
    public static int getLogDestinationPort() {
        return Optional.ofNullable(System.getenv("LOG_DEST_PORT")).map(Integer::parseInt).orElse(DEFAULT_LOG_DEST_PORT);
    }

    public static Optional<List<String>> getFluentBitStartCommand() {
        return Optional.ofNullable(System.getenv("FLUENTBIT_COMMAND")).map(x -> Arrays.stream(x.split(" ")).collect(Collectors.toList()));
    }

    public static String getFluentBitDockerImage() {
        return Optional.ofNullable(System.getenv("FLUENTBIT_DOCKER_IMAGE")).orElse("fluent/fluent-bit:latest");
    }
}
