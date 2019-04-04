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
package org.apache.pulsar.common.util.collections;

import static com.google.common.base.Preconditions.checkArgument;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.StampedLock;

/**
 * Concurrent hash set where values are composed of pairs of longs.
 *
 ** <p>
 * (long,long)
 * <p>
 * Provides similar methods as a ConcurrentHashSet<V> but since it's an open hash set with linear probing, no node
 * allocations are required to store the keys and values, and no boxing is required.
 * <p>
 * Values <strong>MUST</strong> be >= 0.
 */
public class ConcurrentLongPairSet {

    private static final long EmptyItem = -1L;
    private static final long DeletedItem = -2L;

    private static final float SetFillFactor = 0.66f;

    private static final int DefaultExpectedItems = 256;
    private static final int DefaultConcurrencyLevel = 16;

    private final Section[] sections;

    public static interface ConsumerLong {
        void accept(LongPair item);
    }

    public interface LongPairPredicate {
        boolean test(long v1, long v2);
    }

    public static interface LongPairConsumer {
        void accept(long v1, long v2);
    }

    public ConcurrentLongPairSet() {
        this(DefaultExpectedItems);
    }

    public ConcurrentLongPairSet(int expectedItems) {
        this(expectedItems, DefaultConcurrencyLevel);
    }

    public ConcurrentLongPairSet(int expectedItems, int concurrencyLevel) {
        checkArgument(expectedItems > 0);
        checkArgument(concurrencyLevel > 0);
        checkArgument(expectedItems >= concurrencyLevel);

        int numSections = concurrencyLevel;
        int perSectionExpectedItems = expectedItems / numSections;
        int perSectionCapacity = (int) (perSectionExpectedItems / SetFillFactor);
        this.sections = new Section[numSections];

        for (int i = 0; i < numSections; i++) {
            sections[i] = new Section(perSectionCapacity);
        }
    }

    public long size() {
        long size = 0;
        for (Section s : sections) {
            size += s.size;
        }
        return size;
    }

    public long capacity() {
        long capacity = 0;
        for (Section s : sections) {
            capacity += s.capacity;
        }
        return capacity;
    }

    public boolean isEmpty() {
        for (Section s : sections) {
            if (s.size != 0) {
                return false;
            }
        }
        return true;
    }

    long getUsedBucketCount() {
        long usedBucketCount = 0;
        for (Section s : sections) {
            usedBucketCount += s.usedBuckets;
        }
        return usedBucketCount;
    }

    public boolean contains(long item1, long item2) {
        checkBiggerEqualZero(item1);
        long h = hash(item1, item2);
        return getSection(h).contains(item1, item2, (int) h);
    }

    public boolean add(long item1, long item2) {
        checkBiggerEqualZero(item1);
        long h = hash(item1, item2);
        return getSection(h).add(item1, item2, (int) h);
    }

    /**
     * Remove an existing entry if found
     *
     * @param item1
     * @return true if removed or false if item was not present
     */
    public boolean remove(long item1, long item2) {
        checkBiggerEqualZero(item1);
        long h = hash(item1, item2);
        return getSection(h).remove(item1, item2, (int) h);
    }

    private final Section getSection(long hash) {
        // Use 32 msb out of long to get the section
        final int sectionIdx = (int) (hash >>> 32) & (sections.length - 1);
        return sections[sectionIdx];
    }

    public void clear() {
        for (Section s : sections) {
            s.clear();
        }
    }

    public void forEach(LongPairConsumer processor) {
        for (Section s : sections) {
            s.forEach(processor);
        }
    }

    /**
     * Removes all of the elements of this collection that satisfy the given predicate.
     *
     * @param filter
     *            a predicate which returns {@code true} for elements to be removed
     * @return {@code true} if any elements were removed
     *
     * @return number of removed values
     */
    public int removeIf(LongPairPredicate filter) {
        int removedValues = 0;
        for (Section s : sections) {
            removedValues += s.removeIf(filter);
        }
        return removedValues;
    }

    /**
     * @return a new list of all keys (makes a copy)
     */
    public Set<LongPair> items() {
        Set<LongPair> items = new HashSet<>();
        forEach((item1, item2) -> items.add(new LongPair(item1, item2)));
        return items;
    }

    /**
     * @return a new list of keys with max provided numberOfItems (makes a copy)
     */
    public Set<LongPair> items(int numberOfItems) {
        Set<LongPair> items = new HashSet<>();
        for (Section s : sections) {
            s.forEach((item1, item2) -> {
                if (items.size() < numberOfItems) {
                    items.add(new LongPair(item1, item2));
                }
            });
            if (items.size() >= numberOfItems) {
                return items;
            }
        }
        return items;
    }

    // A section is a portion of the hash map that is covered by a single
    @SuppressWarnings("serial")
    private static final class Section extends StampedLock {
        // Keys and values are stored interleaved in the table array
        private volatile long[] table;

        private volatile int capacity;
        private volatile int size;
        private int usedBuckets;
        private int resizeThreshold;

        Section(int capacity) {
            this.capacity = alignToPowerOfTwo(capacity);
            this.table = new long[2 * this.capacity];
            this.size = 0;
            this.usedBuckets = 0;
            this.resizeThreshold = (int) (this.capacity * SetFillFactor);
            Arrays.fill(table, EmptyItem);
        }

        boolean contains(long item1, long item2, int hash) {
            long stamp = tryOptimisticRead();
            boolean acquiredLock = false;
            int bucket = signSafeMod(hash, capacity);

            try {
                while (true) {
                    // First try optimistic locking
                    long storedItem1 = table[bucket];
                    long storedItem2 = table[bucket + 1];

                    if (!acquiredLock && validate(stamp)) {
                        // The values we have read are consistent
                        if (item1 == storedItem1 && item2 == storedItem2) {
                            return true;
                        } else if (storedItem1 == EmptyItem) {
                            // Not found
                            return false;
                        }
                    } else {
                        // Fallback to acquiring read lock
                        if (!acquiredLock) {
                            stamp = readLock();
                            acquiredLock = true;

                            bucket = signSafeMod(hash, capacity);
                            storedItem1 = table[bucket];
                            storedItem2 = table[bucket + 1];
                        }

                        if (item1 == storedItem1 && item2 == storedItem2) {
                            return true;
                        } else if (storedItem1 == EmptyItem) {
                            // Not found
                            return false;
                        }
                    }

                    bucket = (bucket + 2) & (table.length - 1);
                }
            } finally {
                if (acquiredLock) {
                    unlockRead(stamp);
                }
            }
        }

        boolean add(long item1, long item2, long hash) {
            long stamp = writeLock();
            int bucket = signSafeMod(hash, capacity);

            // Remember where we find the first available spot
            int firstDeletedItem = -1;

            try {
                while (true) {
                    long storedItem1 = table[bucket];
                    long storedItem2 = table[bucket + 1];

                    if (item1 == storedItem1 && item2 == storedItem2) {
                        // Item was already in set
                        return false;
                    } else if (storedItem1 == EmptyItem) {
                        // Found an empty bucket. This means the key is not in the set. If we've already seen a deleted
                        // key, we should write at that position
                        if (firstDeletedItem != -1) {
                            bucket = firstDeletedItem;
                        } else {
                            ++usedBuckets;
                        }

                        table[bucket] = item1;
                        table[bucket + 1] = item2;
                        ++size;
                        return true;
                    } else if (storedItem1 == DeletedItem) {
                        // The bucket contained a different deleted key
                        if (firstDeletedItem == -1) {
                            firstDeletedItem = bucket;
                        }
                    }

                    bucket = (bucket + 2) & (table.length - 1);
                }
            } finally {
                if (usedBuckets > resizeThreshold) {
                    try {
                        rehash();
                    } finally {
                        unlockWrite(stamp);
                    }
                } else {
                    unlockWrite(stamp);
                }
            }
        }

        private boolean remove(long item1, long item2, int hash) {
            long stamp = writeLock();
            int bucket = signSafeMod(hash, capacity);

            try {
                while (true) {
                    long storedItem1 = table[bucket];
                    long storedItem2 = table[bucket + 1];
                    if (item1 == storedItem1 && item2 == storedItem2) {
                        --size;

                        cleanBucket(bucket);
                        return true;

                    } else if (storedItem1 == EmptyItem) {
                        return false;
                    }

                    bucket = (bucket + 2) & (table.length - 1);
                }
            } finally {
                unlockWrite(stamp);
            }
        }

        private int removeIf(LongPairPredicate filter) {
            Objects.requireNonNull(filter);
            int removedItems = 0;

            // Go through all the buckets for this section
            for (int bucket = 0; bucket < table.length; bucket += 2) {
                long storedItem1 = table[bucket];
                long storedItem2 = table[bucket + 1];

                if (storedItem1 != DeletedItem && storedItem1 != EmptyItem) {
                    if (filter.test(storedItem1, storedItem2)) {
                        long h = hash(storedItem1, storedItem2);
                        if (remove(storedItem1, storedItem2, (int) h)) {
                            removedItems++;
                        }
                    }
                }
            }

            return removedItems;
        }

        private void cleanBucket(int bucket) {
            int nextInArray = (bucket + 2) & (table.length - 1);
            if (table[nextInArray] == EmptyItem) {
                table[bucket] = EmptyItem;
                table[bucket + 1] = EmptyItem;
                --usedBuckets;
            } else {
                table[bucket] = DeletedItem;
                table[bucket + 1] = DeletedItem;
            }
        }

        void clear() {
            long stamp = writeLock();

            try {
                Arrays.fill(table, EmptyItem);
                this.size = 0;
                this.usedBuckets = 0;
            } finally {
                unlockWrite(stamp);
            }
        }

        public void forEach(LongPairConsumer processor) {
            long stamp = tryOptimisticRead();

            long[] table = this.table;
            boolean acquiredReadLock = false;

            try {

                // Validate no rehashing
                if (!validate(stamp)) {
                    // Fallback to read lock
                    stamp = readLock();
                    acquiredReadLock = true;
                    table = this.table;
                }

                // Go through all the buckets for this section
                for (int bucket = 0; bucket < table.length; bucket += 2) {
                    long storedItem1 = table[bucket];
                    long storedItem2 = table[bucket + 1];

                    if (!acquiredReadLock && !validate(stamp)) {
                        // Fallback to acquiring read lock
                        stamp = readLock();
                        acquiredReadLock = true;

                        storedItem1 = table[bucket];
                        storedItem2 = table[bucket + 1];
                    }

                    if (storedItem1 != DeletedItem && storedItem1 != EmptyItem) {
                        processor.accept(storedItem1, storedItem2);
                    }
                }
            } finally {
                if (acquiredReadLock) {
                    unlockRead(stamp);
                }
            }
        }

        private void rehash() {
            // Expand the hashmap
            int newCapacity = capacity * 2;
            long[] newTable = new long[2 * newCapacity];
            Arrays.fill(newTable, EmptyItem);

            // Re-hash table
            for (int i = 0; i < table.length; i += 2) {
                long storedItem1 = table[i];
                long storedItem2 = table[i + 1];
                if (storedItem1 != EmptyItem && storedItem1 != DeletedItem) {
                    insertKeyValueNoLock(newTable, newCapacity, storedItem1, storedItem2);
                }
            }

            table = newTable;
            usedBuckets = size;
            // Capacity needs to be updated after the values, so that we won't see
            // a capacity value bigger than the actual array size
            capacity = newCapacity;
            resizeThreshold = (int) (capacity * SetFillFactor);
        }

        private static void insertKeyValueNoLock(long[] table, int capacity, long item1, long item2) {
            int bucket = signSafeMod(hash(item1, item2), capacity);

            while (true) {
                long storedKey = table[bucket];

                if (storedKey == EmptyItem) {
                    // The bucket is empty, so we can use it
                    table[bucket] = item1;
                    table[bucket + 1] = item2;
                    return;
                }

                bucket = (bucket + 2) & (table.length - 1);
            }
        }
    }

    private static final long HashMixer = 0xc6a4a7935bd1e995l;
    private static final int R = 47;

    final static long hash(long key1, long key2) {
        long hash = key1 * HashMixer;
        hash ^= hash >>> R;
        hash *= HashMixer;
        hash += 31 + (key2 * HashMixer);
        hash ^= hash >>> R;
        hash *= HashMixer;
        return hash;
    }

    static final int signSafeMod(long n, int Max) {
        return (int) (n & (Max - 1)) << 1;
    }

    private static final int alignToPowerOfTwo(int n) {
        return (int) Math.pow(2, 32 - Integer.numberOfLeadingZeros(n - 1));
    }

    private static final void checkBiggerEqualZero(long n) {
        if (n < 0L) {
            throw new IllegalArgumentException("Keys and values must be >= 0");
        }
    }

    public static class LongPair implements Comparable<LongPair> {
        public final long first;
        public final long second;

        public LongPair(long first, long second) {
            this.first = first;
            this.second = second;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof LongPair) {
                LongPair other = (LongPair) obj;
                return first == other.first && second == other.second;
            }
            return false;
        }

        @Override
        public int hashCode() {
            return (int) hash(first, second);
        }

        @Override
        public int compareTo(LongPair o) {
            if (first != o.first) {
                return Long.compare(first, o.first);
            } else {
                return Long.compare(second, o.second);
            }
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        final AtomicBoolean first = new AtomicBoolean(true);
        forEach((item1, item2) -> {
            if (!first.getAndSet(false)) {
                sb.append(", ");
            }
            sb.append('[');
            sb.append(item1);
            sb.append(':');
            sb.append(item2);
            sb.append(']');
        });
        sb.append('}');
        return sb.toString();
    }
}
