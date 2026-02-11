package org.mangala.gateway.audit;

import lombok.extern.slf4j.Slf4j;
import org.mangala.security.SecurityConstants;
import org.mangala.security.model.AuthorizationResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.reactive.ReactiveKafkaProducerTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Publishes authorization audit events to Kafka.
 * Non-blocking, fire-and-forget operation that never affects request latency.
 */
@Slf4j
@Component
public class AuthorizationAuditPublisher {

    private final ReactiveKafkaProducerTemplate<String, AuthorizationAuditEvent> kafkaTemplate;
    private final AuditConfigProperties auditConfig;

    // Metrics
    private final AtomicLong publishedCount = new AtomicLong(0);
    private final AtomicLong failedCount = new AtomicLong(0);

    @Autowired(required = false)
    public AuthorizationAuditPublisher(
            ReactiveKafkaProducerTemplate<String, AuthorizationAuditEvent> kafkaTemplate,
            AuditConfigProperties auditConfig) {
        this.kafkaTemplate = kafkaTemplate;
        this.auditConfig = auditConfig;
    }

    /**
     * Constructor when Kafka is disabled.
     */
    public AuthorizationAuditPublisher(AuditConfigProperties auditConfig) {
        this.kafkaTemplate = null;
        this.auditConfig = auditConfig;
    }

    /**
     * Publish audit event asynchronously - fire and forget.
     * Non-blocking, errors are logged but never propagated.
     */
    public void publishAsync(AuthorizationAuditEvent event) {
        if (!shouldPublish(event)) {
            return;
        }

        if (kafkaTemplate == null) {
            log.trace("Kafka not configured, skipping audit event");
            return;
        }

        kafkaTemplate.send(
                        SecurityConstants.TOPIC_AUTHORIZATION_AUDIT,
                        event.getRequestId(),  // Use requestId as key for ordering
                        event
                )
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(result -> {
                    publishedCount.incrementAndGet();
                    if (log.isTraceEnabled()) {
                        log.trace("Audit event published: requestId={}, decision={}",
                                event.getRequestId(), event.getDecision());
                    }
                })
                .doOnError(e -> {
                    failedCount.incrementAndGet();
                    log.warn("Failed to publish audit event: requestId={}, error={}",
                            event.getRequestId(), e.getMessage());
                })
                .subscribe();  // Fire and forget
    }

    /**
     * Publish with Mono return for testing or when chaining is needed.
     */
    public Mono<Void> publish(AuthorizationAuditEvent event) {
        if (!shouldPublish(event)) {
            return Mono.empty();
        }

        if (kafkaTemplate == null) {
            return Mono.empty();
        }

        return kafkaTemplate.send(
                        SecurityConstants.TOPIC_AUTHORIZATION_AUDIT,
                        event.getRequestId(),
                        event
                )
                .doOnSuccess(result -> publishedCount.incrementAndGet())
                .doOnError(e -> {
                    failedCount.incrementAndGet();
                    log.warn("Failed to publish audit event", e);
                })
                .then();
    }

    /**
     * Check if this event should be published based on configuration.
     */
    private boolean shouldPublish(AuthorizationAuditEvent event) {
        if (!auditConfig.isEnabled()) {
            return false;
        }

        if (event == null || event.getDecision() == null) {
            return false;
        }

        return switch (event.getDecision()) {
            case ALLOW -> auditConfig.isAuditAllowedRequests();
            case DENY -> auditConfig.isAuditDeniedRequests();
            case NO_POLICY -> auditConfig.isAuditNoPolicyRequests();
        };
    }

    /**
     * Check if audit publishing is enabled.
     */
    public boolean isEnabled() {
        return auditConfig.isEnabled() && kafkaTemplate != null;
    }

    /**
     * Get count of successfully published events.
     */
    public long getPublishedCount() {
        return publishedCount.get();
    }

    /**
     * Get count of failed publish attempts.
     */
    public long getFailedCount() {
        return failedCount.get();
    }

    /**
     * Reset metrics counters.
     */
    public void resetMetrics() {
        publishedCount.set(0);
        failedCount.set(0);
    }
}
