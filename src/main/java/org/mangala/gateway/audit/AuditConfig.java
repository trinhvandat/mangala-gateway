package org.mangala.gateway.audit;

import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.reactive.ReactiveKafkaProducerTemplate;
import org.springframework.kafka.support.serializer.JsonSerializer;
import reactor.kafka.sender.SenderOptions;

import java.util.HashMap;
import java.util.Map;

/**
 * Kafka producer configuration for audit events.
 * Configured for fire-and-forget, non-blocking operation.
 */
@Configuration
@ConditionalOnProperty(value = "gateway.audit.enabled", havingValue = "true")
public class AuditConfig {

    @Bean
    public ReactiveKafkaProducerTemplate<String, AuthorizationAuditEvent> auditKafkaTemplate(
            AuditConfigProperties auditConfig) {

        Map<String, Object> props = new HashMap<>();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, auditConfig.getKafkaBootstrapServers());
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);

        // Fire-and-forget settings for non-blocking operation
        props.put(ProducerConfig.ACKS_CONFIG, "0");  // Don't wait for acks
        props.put(ProducerConfig.RETRIES_CONFIG, 0);  // No retries
        props.put(ProducerConfig.BATCH_SIZE_CONFIG, auditConfig.getBatchSize());
        props.put(ProducerConfig.LINGER_MS_CONFIG, auditConfig.getLingerMs());
        props.put(ProducerConfig.BUFFER_MEMORY_CONFIG, auditConfig.getBufferMemory());

        // Prevent blocking the request thread
        props.put(ProducerConfig.MAX_BLOCK_MS_CONFIG, auditConfig.getMaxBlockMs());

        // Compression for efficiency
        props.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, "lz4");

        SenderOptions<String, AuthorizationAuditEvent> senderOptions =
                SenderOptions.create(props);

        return new ReactiveKafkaProducerTemplate<>(senderOptions);
    }
}
