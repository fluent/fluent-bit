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
package org.apache.pulsar.policies.data.loadbalancer;

/**
 */
public class NamespaceBundleStats implements Comparable<NamespaceBundleStats> {

    public double msgRateIn;
    public double msgThroughputIn;
    public double msgRateOut;
    public double msgThroughputOut;
    public int consumerCount;
    public int producerCount;
    public long topics;
    public long cacheSize;

    // Consider the throughput equal if difference is less than 100 KB/s
    private static double ThroughputDifferenceThreshold = 1e5;
    // Consider the msgRate equal if the difference is less than 100
    private static double MsgRateDifferenceThreshold = 100;
    // Consider the total topics/producers/consumers equal if the difference is less than 500
    private static long TopicConnectionDifferenceThreshold = 500;
    // Consider the cache size equal if the difference is less than 100 kb
    private static long CacheSizeDifferenceThreshold = 100000;

    public NamespaceBundleStats() {
        reset();
    }

    public void reset() {
        this.msgRateIn = 0;
        this.msgThroughputIn = 0;
        this.msgRateOut = 0;
        this.msgThroughputOut = 0;
        this.consumerCount = 0;
        this.producerCount = 0;
        this.topics = 0;
        this.cacheSize = 0;
    }

    // compare 2 bundles in below aspects:
    // 1. Inbound bandwidth
    // 2. Outbound bandwidth
    // 3. Total megRate (both in and out)
    // 4. Total topics and producers/consumers
    // 5. Total cache size
    public int compareTo(NamespaceBundleStats other) {
        int result = this.compareByBandwidthIn(other);

        if (result == 0) {
            result = this.compareByBandwidthOut(other);
        }
        if (result == 0) {
            result = this.compareByMsgRate(other);
        }
        if (result == 0) {
            result = this.compareByTopicConnections(other);
        }
        if (result == 0) {
            result = this.compareByCacheSize(other);
        }

        return result;
    }

    public int compareByMsgRate(NamespaceBundleStats other) {
        double thisMsgRate = this.msgRateIn + this.msgRateOut;
        double otherMsgRate = other.msgRateIn + other.msgRateOut;
        if (Math.abs(thisMsgRate - otherMsgRate) > MsgRateDifferenceThreshold) {
            return Double.compare(thisMsgRate, otherMsgRate);
        }
        return 0;
    }

    public int compareByTopicConnections(NamespaceBundleStats other) {
        long thisTopicsAndConnections = this.topics + this.consumerCount + this.producerCount;
        long otherTopicsAndConnections = other.topics + other.consumerCount + other.producerCount;
        if (Math.abs(thisTopicsAndConnections - otherTopicsAndConnections) > TopicConnectionDifferenceThreshold) {
            return Long.compare(thisTopicsAndConnections, otherTopicsAndConnections);
        }
        return 0;
    }

    public int compareByCacheSize(NamespaceBundleStats other) {
        if (Math.abs(this.cacheSize - other.cacheSize) > CacheSizeDifferenceThreshold) {
            return Long.compare(this.cacheSize, other.cacheSize);
        }
        return 0;
    }

    public int compareByBandwidthIn(NamespaceBundleStats other) {
        if (Math.abs(this.msgThroughputIn - other.msgThroughputIn) > ThroughputDifferenceThreshold) {
            return Double.compare(this.msgThroughputIn, other.msgThroughputIn);
        }
        return 0;
    }

    public int compareByBandwidthOut(NamespaceBundleStats other) {
        if (Math.abs(this.msgThroughputOut - other.msgThroughputOut) > ThroughputDifferenceThreshold) {
            return Double.compare(this.msgThroughputOut, other.msgThroughputOut);
        }
        return 0;
    }
}
