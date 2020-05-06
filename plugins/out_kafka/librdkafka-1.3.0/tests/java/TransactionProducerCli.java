import java.io.IOException;
import java.io.PrintWriter;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.KafkaException;

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
        Yes,
        No
    }

    static Producer<byte[], byte[]> createProducer(String id, String brokerList, boolean transactional) {
        Properties producerConfig = new Properties();
        producerConfig.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, brokerList);
        producerConfig.put(ProducerConfig.CLIENT_ID_CONFIG, transactional ? "transactional-producer-" + id : "producer-" + id);
        producerConfig.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);
        if (transactional) {
            producerConfig.put(ProducerConfig.TRANSACTIONAL_ID_CONFIG, "test-transactional-id-" + id);
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
        if (flush == FlushType.Yes) {
            producer.flush();
        }
        if (tt == TransactionType.BeginAbort || tt == TransactionType.ContinueAbort) {
            producer.abortTransaction();
        } else if (tt == TransactionType.BeginCommit || tt == TransactionType.ContinueCommit) {
            producer.commitTransaction();
        }
    }


    public static void main (String[] args) throws Exception {

        String bootstrapServers = args[0];
        String topic = args[1];
        String cmd = args[2];

        Producer<byte[], byte[]> producer1 = createProducer("1", bootstrapServers, true);
        Producer<byte[], byte[]> producer2 = createProducer("2", bootstrapServers, true);
        Producer<byte[], byte[]> producer3 = createProducer("3", bootstrapServers, false);

        System.out.println("java producer cli executing command #" + cmd);

        switch (cmd) {
            // basic commit + abort.
            case "0":
                makeTestMessages(producer1, topic, -1, 0x0, 5, TransactionType.BeginCommit, FlushType.Yes);
                makeTestMessages(producer1, topic, -1, 0x10, 5, TransactionType.BeginAbort, FlushType.Yes);
                break;
            case "0.1":
                makeTestMessages(producer1, topic, -1, 0x0, 5, TransactionType.BeginCommit, FlushType.No);
                makeTestMessages(producer1, topic, -1, 0x10, 5, TransactionType.BeginAbort, FlushType.Yes);
                break;
            case "0.2":
                makeTestMessages(producer1, topic, -1, 0x10, 5, TransactionType.BeginAbort, FlushType.Yes);
                makeTestMessages(producer1, topic, -1, 0x30, 5, TransactionType.BeginCommit, FlushType.Yes);
                break;

            // mixed with non-transactional.
            case "1":
                makeTestMessages(producer3, topic, -1, 0x10, 5, TransactionType.None, FlushType.Yes);
                makeTestMessages(producer1, topic, -1, 0x50, 5, TransactionType.BeginCommit, FlushType.Yes);
                makeTestMessages(producer1, topic, -1, 0x80, 5, TransactionType.BeginAbort, FlushType.Yes);
                break;
            case "1.1":
                makeTestMessages(producer1, topic, -1, 0x30, 5, TransactionType.BeginAbort, FlushType.Yes);
                makeTestMessages(producer3, topic, -1, 0x40, 5, TransactionType.None, FlushType.Yes);
                makeTestMessages(producer1, topic, -1, 0x60, 5, TransactionType.BeginCommit, FlushType.Yes);
                break;
            case "1.2":
                makeTestMessages(producer1, topic, -1, 0x10, 5, TransactionType.BeginCommit, FlushType.Yes);
                makeTestMessages(producer1, topic, -1, 0x20, 5, TransactionType.BeginAbort, FlushType.Yes);
                makeTestMessages(producer3, topic, -1, 0x30, 5, TransactionType.None, FlushType.Yes);
                break;

            // rapid abort / committing.
            case "2":
                // note: aborted records never seem to make it to the broker when not flushed.
                makeTestMessages(producer1, topic, -1, 0x10, 1, TransactionType.BeginAbort, FlushType.No);
                makeTestMessages(producer1, topic, -1, 0x20, 1, TransactionType.BeginCommit, FlushType.No);
                makeTestMessages(producer1, topic, -1, 0x30, 1, TransactionType.BeginAbort, FlushType.No);
                makeTestMessages(producer1, topic, -1, 0x40, 1, TransactionType.BeginCommit, FlushType.No);
                makeTestMessages(producer1, topic, -1, 0x50, 1, TransactionType.BeginAbort, FlushType.No);
                makeTestMessages(producer1, topic, -1, 0x60, 1, TransactionType.BeginCommit, FlushType.No);
                makeTestMessages(producer1, topic, -1, 0x70, 1, TransactionType.BeginAbort, FlushType.No);
                makeTestMessages(producer1, topic, -1, 0x80, 1, TransactionType.BeginCommit, FlushType.No);
                makeTestMessages(producer1, topic, -1, 0x90, 1, TransactionType.BeginAbort, FlushType.No);
                makeTestMessages(producer1, topic, -1, 0xa0, 1, TransactionType.BeginCommit, FlushType.Yes);
                makeTestMessages(producer3, topic, -1, 0xb0, 1, TransactionType.None, FlushType.No);
                makeTestMessages(producer3, topic, -1, 0xc0, 1, TransactionType.None, FlushType.Yes);
                break;
            case "2.1":
                makeTestMessages(producer1, topic, -1, 0x10, 1, TransactionType.BeginAbort, FlushType.Yes);
                makeTestMessages(producer1, topic, -1, 0x20, 1, TransactionType.BeginCommit, FlushType.Yes);
                makeTestMessages(producer1, topic, -1, 0x30, 1, TransactionType.BeginAbort, FlushType.Yes);
                makeTestMessages(producer1, topic, -1, 0x40, 1, TransactionType.BeginCommit, FlushType.Yes);
                makeTestMessages(producer1, topic, -1, 0x50, 1, TransactionType.BeginAbort, FlushType.Yes);
                makeTestMessages(producer1, topic, -1, 0x60, 1, TransactionType.BeginCommit, FlushType.Yes);
                makeTestMessages(producer1, topic, -1, 0x70, 1, TransactionType.BeginAbort, FlushType.Yes);
                makeTestMessages(producer1, topic, -1, 0x80, 1, TransactionType.BeginCommit, FlushType.Yes);
                makeTestMessages(producer1, topic, -1, 0x90, 1, TransactionType.BeginAbort, FlushType.Yes);
                makeTestMessages(producer1, topic, -1, 0xa0, 1, TransactionType.BeginCommit, FlushType.Yes);
                makeTestMessages(producer3, topic, -1, 0xb0, 1, TransactionType.None, FlushType.Yes);
                makeTestMessages(producer3, topic, -1, 0xc0, 1, TransactionType.None, FlushType.Yes);
                break;

            // cross partition (simple).
            case "3":
                makeTestMessages(producer1, topic, 0, 0x10, 3, TransactionType.BeginOpen, FlushType.Yes);
                makeTestMessages(producer1, topic, 1, 0x20, 3, TransactionType.ContinueOpen, FlushType.Yes);
                makeTestMessages(producer1, topic, 0, 0x30, 3, TransactionType.ContinueCommit, FlushType.Yes);
                break;
            case "3.1":
                makeTestMessages(producer1, topic, 0, 0x55, 1, TransactionType.BeginCommit, FlushType.Yes);
                makeTestMessages(producer1, topic, 0, 0x10, 3, TransactionType.BeginOpen, FlushType.Yes);
                makeTestMessages(producer1, topic, 1, 0x20, 3, TransactionType.ContinueOpen, FlushType.Yes);
                makeTestMessages(producer1, topic, 0, 0x30, 3, TransactionType.ContinueAbort, FlushType.Yes);
                makeTestMessages(producer3, topic, 0, 0x00, 1, TransactionType.None, FlushType.Yes);
                makeTestMessages(producer1, topic, 1, 0x44, 1, TransactionType.BeginCommit, FlushType.Yes);
                break;

            // simultaneous transactions (simple).
            case "4":
                makeTestMessages(producer3, topic, 0, 0x10, 1, TransactionType.None, FlushType.Yes);
                makeTestMessages(producer1, topic, 0, 0x20, 3, TransactionType.BeginOpen, FlushType.Yes);
                makeTestMessages(producer2, topic, 0, 0x30, 3, TransactionType.BeginOpen, FlushType.Yes);
                makeTestMessages(producer1, topic, 0, 0x40, 3, TransactionType.ContinueCommit, FlushType.Yes);
                makeTestMessages(producer2, topic, 0, 0x50, 3, TransactionType.ContinueAbort, FlushType.Yes);
                break;
            case "4.1":
                makeTestMessages(producer3, topic, 0, 0x10, 1, TransactionType.None, FlushType.Yes);
                makeTestMessages(producer1, topic, 0, 0x20, 3, TransactionType.BeginOpen, FlushType.Yes);
                makeTestMessages(producer2, topic, 0, 0x30, 3, TransactionType.BeginOpen, FlushType.Yes);
                makeTestMessages(producer1, topic, 0, 0x40, 3, TransactionType.ContinueAbort, FlushType.Yes);
                makeTestMessages(producer2, topic, 0, 0x50, 3, TransactionType.ContinueCommit, FlushType.Yes);
                break;
            case "4.2":
                makeTestMessages(producer3, topic, 0, 0x10, 1, TransactionType.None, FlushType.Yes);
                makeTestMessages(producer1, topic, 0, 0x20, 3, TransactionType.BeginOpen, FlushType.Yes);
                makeTestMessages(producer2, topic, 0, 0x30, 3, TransactionType.BeginOpen, FlushType.Yes);
                makeTestMessages(producer1, topic, 0, 0x40, 3, TransactionType.ContinueCommit, FlushType.Yes);
                makeTestMessages(producer2, topic, 0, 0x50, 3, TransactionType.ContinueCommit, FlushType.Yes);
                break;
            case "4.3":
                makeTestMessages(producer3, topic, 0, 0x10, 1, TransactionType.None, FlushType.Yes);
                makeTestMessages(producer1, topic, 0, 0x20, 3, TransactionType.BeginOpen, FlushType.Yes);
                makeTestMessages(producer2, topic, 0, 0x30, 3, TransactionType.BeginOpen, FlushType.Yes);
                makeTestMessages(producer1, topic, 0, 0x40, 3, TransactionType.ContinueAbort, FlushType.Yes);
                makeTestMessages(producer2, topic, 0, 0x50, 3, TransactionType.ContinueAbort, FlushType.Yes);
                break;

            // split transaction across message set.
            case "5":
                makeTestMessages(producer1, topic, 0, 0x10, 2, TransactionType.BeginOpen, FlushType.No);
                Thread.sleep(200);
                makeTestMessages(producer1, topic, 0, 0x20, 2, TransactionType.ContinueAbort, FlushType.No);
                makeTestMessages(producer1, topic, 0, 0x30, 2, TransactionType.BeginOpen, FlushType.No);
                Thread.sleep(200);
                makeTestMessages(producer1, topic, 0, 0x40, 2, TransactionType.ContinueCommit, FlushType.No);
                makeTestMessages(producer1, topic, 0, 0x50, 2, TransactionType.BeginOpen, FlushType.No);
                Thread.sleep(200);
                makeTestMessages(producer1, topic, 0, 0x60, 2, TransactionType.ContinueAbort, FlushType.No);
                makeTestMessages(producer1, topic, 0, 0xa0, 2, TransactionType.BeginOpen, FlushType.No);
                Thread.sleep(200);
                makeTestMessages(producer1, topic, 0, 0xb0, 2, TransactionType.ContinueCommit, FlushType.No);
                makeTestMessages(producer3, topic, 0, 0x70, 1, TransactionType.None, FlushType.Yes);
                break;

            // transaction left open
            case "6":
                makeTestMessages(producer3, topic, 0, 0x10, 1, TransactionType.None, FlushType.Yes);
                makeTestMessages(producer1, topic, 0, 0x20, 3, TransactionType.BeginOpen, FlushType.Yes);
                // prevent abort control message from being written.
                System.exit(0);
                break;

            default:
                throw new Exception("not implemented");
        }

        producer1.close();
        producer2.close();
        producer3.close();
    }
}
