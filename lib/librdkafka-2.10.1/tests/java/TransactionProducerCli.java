/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2020-2022, Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

import java.io.IOException;
import java.io.PrintWriter;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.KafkaException;

import java.lang.Integer;
import java.util.HashMap;
import java.util.Properties;


public class TransactionProducerCli {

    enum TransactionType {
        None,
        BeginAbort,
        BeginCommit,
        BeginOpen,
        ContinueAbort,
        ContinueCommit,
        ContinueOpen
    }

    enum FlushType {
        DoFlush,
        DontFlush
    }

    static Producer<byte[], byte[]> createProducer(String testid, String id, String brokerList, boolean transactional) {
        Properties producerConfig = new Properties();
        producerConfig.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, brokerList);
        producerConfig.put(ProducerConfig.CLIENT_ID_CONFIG, transactional ? "transactional-producer-" + id : "producer-" + id);
        producerConfig.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);
        if (transactional) {
            producerConfig.put(ProducerConfig.TRANSACTIONAL_ID_CONFIG, "test-transactional-id-" + testid + "-" + id);
        }
        producerConfig.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.ByteArraySerializer");
        producerConfig.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.ByteArraySerializer");
        producerConfig.put(ProducerConfig.LINGER_MS_CONFIG, "5"); // ensure batching.
        Producer<byte[], byte[]> producer = new KafkaProducer<>(producerConfig);
        if (transactional) {
            producer.initTransactions();
        }
        return producer;
    }

    static void makeTestMessages(
            Producer<byte[], byte[]> producer,
            String topic, int partition,
            int idStart, int count,
            TransactionType tt,
            FlushType flush) throws InterruptedException {
        byte[] payload = { 0x10, 0x20, 0x30, 0x40 };
        if (tt != TransactionType.None &&
            tt != TransactionType.ContinueOpen &&
            tt != TransactionType.ContinueCommit &&
            tt != TransactionType.ContinueAbort) {
            producer.beginTransaction();
        }
        for (int i = 0; i <count; ++i) {
            ProducerRecord<byte[], byte[]> r = partition != -1
                ? new ProducerRecord<byte[],byte[]>(topic, partition, new byte[] { (byte)(i + idStart) }, payload)
                : new ProducerRecord<byte[], byte[]>(topic, new byte[] { (byte)(i + idStart) }, payload);
            producer.send(r);
        }
        if (flush == FlushType.DoFlush) {
            producer.flush();
        }
        if (tt == TransactionType.BeginAbort || tt == TransactionType.ContinueAbort) {
            producer.abortTransaction();
        } else if (tt == TransactionType.BeginCommit || tt == TransactionType.ContinueCommit) {
            producer.commitTransaction();
        }
    }

    static String[] csvSplit(String input) {
        return input.split("\\s*,\\s*");
    }

    public static void main (String[] args) throws Exception {

        String bootstrapServers = args[0];

        HashMap<String, Producer<byte[], byte[]>> producers = new HashMap<String, Producer<byte[], byte[]>>();

        String topic = null;
        String testid = null;

        /* Parse commands */
        for (int i = 1 ; i < args.length ; i++) {
            String cmd[] = csvSplit(args[i]);

            System.out.println("TransactionProducerCli.java: command: '" + args[i] + "'");

            if (cmd[0].equals("sleep")) {
                Thread.sleep(Integer.decode(cmd[1]));

            } else if (cmd[0].equals("exit")) {
                System.exit(Integer.decode(cmd[1]));

            } else if (cmd[0].equals("topic")) {
                topic = cmd[1];

            } else if (cmd[0].equals("testid")) {
                testid = cmd[1];

            } else if (cmd[0].startsWith("producer")) {
                Producer<byte[], byte[]> producer = producers.get(cmd[0]);

                if (producer == null) {
                    producer = createProducer(testid, cmd[0], bootstrapServers,
                                              TransactionType.valueOf(cmd[4]) != TransactionType.None);
                    producers.put(cmd[0], producer);
                }

                makeTestMessages(producer,                        /* producer */
                                 topic,                           /* topic */
                                 Integer.decode(cmd[1]),          /* partition, or -1 for any */
                                 Integer.decode(cmd[2]),          /* idStart */
                                 Integer.decode(cmd[3]),          /* msg count */
                                 TransactionType.valueOf(cmd[4]), /* TransactionType */
                                 FlushType.valueOf(cmd[5]));      /* Flush */

            } else {
                throw new Exception("Unknown command: " + args[i]);
            }
        }

        producers.forEach((k,p) -> p.close());
    }
}
