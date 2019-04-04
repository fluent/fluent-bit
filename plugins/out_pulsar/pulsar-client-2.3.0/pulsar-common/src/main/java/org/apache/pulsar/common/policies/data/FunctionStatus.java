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
package org.apache.pulsar.common.policies.data;

import lombok.Data;
import org.apache.pulsar.common.util.ObjectMapperFactory;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

@Data
public class FunctionStatus {

    public int numInstances;
    public int numRunning;
    public List<FunctionInstanceStatus> instances = new LinkedList<>();

    @Data
    public static class FunctionInstanceStatus {
        public int instanceId;
        public FunctionInstanceStatusData status;

        @Data
        public static class FunctionInstanceStatusData {

            public boolean running;

            public String error;

            public long numRestarts;

            public long numReceived;

            public long numSuccessfullyProcessed;

            public long numUserExceptions;

            public List<ExceptionInformation> latestUserExceptions;

            public long numSystemExceptions;

            public List<ExceptionInformation> latestSystemExceptions;

            public double averageLatency;

            public long lastInvocationTime;

            public String workerId;
        }

    }

    public void addInstance(FunctionInstanceStatus functionInstanceStatus) {
        instances.add(functionInstanceStatus);
    }

    public static FunctionStatus decode(String json) throws IOException {
        return ObjectMapperFactory.getThreadLocal().readValue(json, FunctionStatus.class);
    }
}
