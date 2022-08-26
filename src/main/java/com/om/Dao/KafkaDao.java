package com.om.Dao;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import reactor.util.function.Tuple2;

import javax.annotation.PostConstruct;
import java.util.List;
import java.util.Properties;

@Repository
public class KafkaDao {
    @Value("${bootstrap.servers}")
    String bootstrapServers;

    @Value("${producer.acks}")
    String acks;

    @Value("${producer.retries}")
    String retries;

    @Value("${producer.retry.backoff.ms}")
    String retryBackoffMs;

    @Value("${producer.batch.size}")
    String batchSize;

    @Value("${producer.linger.ms}")
    String lingerMs;

    public static KafkaProducer<String, String> producer;

    @PostConstruct
    public void init() {
        initProducer();
    }

    public void sendMess(String topic, List<Tuple2<String, String>> messages) {
        for (Tuple2<String, String> message : messages) {
            ProducerRecord<String, String> mess = new ProducerRecord<>(topic, message.getT1(), message.getT2());
            producer.send(mess);
        }
    }

    public void sendMess(String topic, String key, String value) {
        ProducerRecord<String, String> mess = new ProducerRecord<String, String>(topic, key, value);
        producer.send(mess);
    }

    private void initProducer() {
        Properties props = new Properties();
        props.put("bootstrap.servers", bootstrapServers);
        props.put("acks", acks);
        props.put("retries", retries);
        props.put("retry.backoff.ms", retryBackoffMs);
        props.put("batch.size", batchSize);
        props.put("linger.ms", lingerMs);
        props.put("key.serializer", StringSerializer.class.getName());
        props.put("value.serializer", StringSerializer.class.getName());
        producer = new KafkaProducer<String, String>(props);
    }

}
