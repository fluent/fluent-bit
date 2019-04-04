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

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;

import org.apache.pulsar.common.api.proto.PulsarApi.CommandSubscribe.SubType;

import com.google.common.collect.Lists;

/**
 */
public class SubscriptionStats {
    /** Total rate of messages delivered on this subscription. msg/s */
    public double msgRateOut;

    /** Total throughput delivered on this subscription. bytes/s */
    public double msgThroughputOut;

    /** Total rate of messages redelivered on this subscription. msg/s */
    public double msgRateRedeliver;

    /** Number of messages in the subscription backlog */
    public long msgBacklog;

    /** Flag to verify if subscription is blocked due to reaching threshold of unacked messages */
    public boolean blockedSubscriptionOnUnackedMsgs;
    
    /** Number of unacknowledged messages for the subscription */
    public long unackedMessages;

    /** Whether this subscription is Exclusive or Shared or Failover */
    public SubType type;

    /** The name of the consumer that is active for single active consumer subscriptions i.e. failover or exclusive */
    public String activeConsumerName;

    /** Total rate of messages expired on this subscription. msg/s */
    public double msgRateExpired;

    /** List of connected consumers on this subscription w/ their stats */
    public List<ConsumerStats> consumers;

    public SubscriptionStats() {
        this.consumers = Lists.newArrayList();
    }

    public void reset() {
        msgRateOut = 0;
        msgThroughputOut = 0;
        msgRateRedeliver = 0;
        msgBacklog = 0;
        unackedMessages = 0;
        msgRateExpired = 0;
        consumers.clear();
    }

    // if the stats are added for the 1st time, we will need to make a copy of these stats and add it to the current
    // stats
    public SubscriptionStats add(SubscriptionStats stats) {
        checkNotNull(stats);
        this.msgRateOut += stats.msgRateOut;
        this.msgThroughputOut += stats.msgThroughputOut;
        this.msgRateRedeliver += stats.msgRateRedeliver;
        this.msgBacklog += stats.msgBacklog;
        this.unackedMessages += stats.unackedMessages;
        this.msgRateExpired += stats.msgRateExpired;
        if (this.consumers.size() != stats.consumers.size()) {
            for (int i = 0; i < stats.consumers.size(); i++) {
                ConsumerStats consumerStats = new ConsumerStats();
                this.consumers.add(consumerStats.add(stats.consumers.get(i)));
            }
        } else {
            for (int i = 0; i < stats.consumers.size(); i++) {
                this.consumers.get(i).add(stats.consumers.get(i));
            }
        }
        return this;
    }
}
