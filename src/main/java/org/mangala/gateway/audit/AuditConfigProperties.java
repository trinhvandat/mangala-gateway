package org.mangala.gateway.audit;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for authorization audit logging.
 */
@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "gateway.audit")
public class AuditConfigProperties {

    /**
     * Enable/disable audit logging.
     */
    private boolean enabled = false;

    /**
     * Kafka bootstrap servers.
     */
    private String kafkaBootstrapServers = "localhost:9092";

    /**
     * Kafka producer batch size.
     */
    private int batchSize = 16384;

    /**
     * Kafka producer linger time in milliseconds.
     */
    private int lingerMs = 10;

    /**
     * Kafka producer buffer memory.
     */
    private long bufferMemory = 33554432; // 32MB

    /**
     * Whether to audit allowed requests.
     */
    private boolean auditAllowedRequests = true;

    /**
     * Whether to audit denied requests.
     */
    private boolean auditDeniedRequests = true;

    /**
     * Whether to audit requests with no matching policy.
     */
    private boolean auditNoPolicyRequests = true;

    /**
     * Maximum time to block when buffer is full (ms).
     * Low value prevents blocking the request.
     */
    private int maxBlockMs = 100;
}
