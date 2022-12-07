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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.TimeUnit;

import static io.fluentbit.test.Util.waitFor;
import static org.junit.Assert.assertFalse;

public class LoggingDestinationServer implements AutoCloseable {
    private final ExpectedLogData expectedLogData;
    private final Server server;

    private volatile boolean hasErrors = false;

    public LoggingDestinationServer(ExpectedLogData expectedLogData) {
        this.expectedLogData = expectedLogData;
        server = new Server();
        new Thread(server, "logging-dest-server-main").start();
        // wait for up to 5 seconds for the server to start up
        waitFor(TimeUnit.SECONDS, 5, () -> server.running);
        System.out.println("Logging Destination Started");
    }

    @Override
    public void close() throws IOException {
        server.stop();
        assertFalse("Logging Destination Server has errors", hasErrors);
        System.out.println("Logging Destination Stopped");
    }

    private final class Server implements Runnable {
        private final ServerSocket serverSocket;
        private volatile boolean running = false;

        private Server() {
            String host = Config.getLogDestinationHost();
            int port = Config.getLogDestinationPort();
            try {
                serverSocket = new ServerSocket(port, 0, InetAddress.getByName(host));
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to create Logging Destination Server", e);
            }
        }


        @Override
        public void run() {
            try {
                running = true;

                while (running) {
                    new Thread(new RequestHandler(serverSocket.accept())).start();
                }

                serverSocket.close();
            } catch (IOException e) {
                if (!running && "Socket closed".equals(e.getMessage())) {
                    System.out.println("Stopped Server");
                } else {
                    hasErrors = true;
                    e.printStackTrace();
                }
            }
        }

        private void stop() throws IOException {
            running = false;
            serverSocket.close();
        }
    }

    private final class RequestHandler implements Runnable {
        private final Socket clientSocket;

        public RequestHandler(Socket socket) {
            this.clientSocket = socket;
        }

        public void run() {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                String line;
                while ((line = in.readLine()) != null) {
                    expectedLogData.dataReceived(line);
                }
                in.close();
                clientSocket.close();
            } catch (Exception e) {
                hasErrors = true;
                e.printStackTrace();
            }
        }
    }
}
