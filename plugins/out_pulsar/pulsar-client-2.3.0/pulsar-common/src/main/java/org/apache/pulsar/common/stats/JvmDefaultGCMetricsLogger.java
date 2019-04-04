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
package org.apache.pulsar.common.stats;

import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Maps;

@SuppressWarnings("restriction")
public class JvmDefaultGCMetricsLogger implements JvmGCMetricsLogger {

    private static final Logger log = LoggerFactory.getLogger(JvmDefaultGCMetricsLogger.class);

    private volatile long accumulatedFullGcCount = 0;
    private volatile long currentFullGcCount = 0;
    private volatile long accumulatedFullGcTime = 0;
    private volatile long currentFullGcTime = 0;

    @SuppressWarnings("restriction")
    private static sun.management.HotspotRuntimeMBean runtime;

    private Map<String, GCMetrics> gcMetricsMap = Maps.newHashMap();

    static {
        try {
            runtime = sun.management.ManagementFactoryHelper.getHotspotRuntimeMBean();
        } catch (Exception e) {
            log.warn("Failed to get Runtime bean", e.getMessage());
        }
    }

    static class GCMetrics {
        volatile long accumulatedGcCount = 0;
        volatile long currentGcCount = 0;
        volatile long accumulatedGcTime = 0;
        volatile long currentGcTime = 0;
    }

    @Override
    public void logMetrics(Metrics metrics) {
        metrics.put("jvm_full_gc_pause", currentFullGcTime);
        metrics.put("jvm_full_gc_count", currentFullGcCount);
        gcMetricsMap.forEach((name, metric) -> {
            metrics.put("jvm_" + name + "_gc_pause", metric.currentGcTime);
            metrics.put("jvm_" + name + "_gc_count", metric.currentGcCount);
        });
    }

    @SuppressWarnings("restriction")
    @Override
    public void refresh() {
        List<GarbageCollectorMXBean> gcBeans = ManagementFactory.getGarbageCollectorMXBeans();

        try {
            if (gcBeans != null) {
                for (GarbageCollectorMXBean gc : gcBeans) {
                    GCMetrics gcMetric = gcMetricsMap.computeIfAbsent(gc.getName(), gcName -> new GCMetrics());
                    long newGcTime = gc.getCollectionTime();
                    long newGcCount = gc.getCollectionCount();
                    gcMetric.currentGcCount = newGcCount - gcMetric.accumulatedGcCount;
                    gcMetric.currentGcTime = newGcTime - gcMetric.accumulatedGcTime;
                    gcMetric.accumulatedGcCount = newGcCount;
                    gcMetric.accumulatedGcTime = newGcTime;
                }
            }

            /**
             * Returns the accumulated time spent at safepoints in milliseconds. This is the accumulated elapsed time
             * that the application has been stopped for safepoint operations.
             * http://www.docjar.com/docs/api/sun/management/HotspotRuntimeMBean.html
             */
            long newSafePointTime = runtime.getTotalSafepointTime();
            long newSafePointCount = runtime.getSafepointCount();
            currentFullGcTime = newSafePointTime - accumulatedFullGcTime;
            currentFullGcCount = newSafePointCount - accumulatedFullGcCount;
            accumulatedFullGcTime = newSafePointTime;
            accumulatedFullGcCount = newSafePointCount;

        } catch (Exception e) {
            log.error("Failed to collect GC stats: {}", e.getMessage());
        }
    }

}
