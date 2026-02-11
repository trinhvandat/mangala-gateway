package org.mangala.gateway.policy;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for policy cache and loading.
 */
@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "gateway.policy")
public class PolicyConfigProperties {

    /**
     * Auth Service URL for loading policies.
     */
    private String authServiceUrl = "http://localhost:8080";

    /**
     * Timeout for initial policy load at startup (seconds).
     */
    private long initialLoadTimeoutSeconds = 30;

    /**
     * Interval to check policy version for updates (seconds).
     */
    private long versionCheckIntervalSeconds = 60;

    /**
     * Whether to fail startup if initial policy load fails.
     */
    private boolean failOnLoadError = true;

    /**
     * Redis channel for policy update broadcasts.
     */
    private String redisChannel = "policy:updates";

    /**
     * Kafka topic for policy update broadcasts (if using Kafka).
     */
    private String kafkaTopic = "policy-updates";

    /**
     * Whether to use Kafka for policy updates (false = use Redis).
     */
    private boolean useKafka = false;

    /**
     * Whether policy cache health affects gateway health.
     */
    private boolean includeInHealthCheck = true;

    /**
     * Default behavior when no policy rule matches.
     * DENY = block request (secure default)
     * ALLOW = allow request (permissive, for development)
     */
    private NoMatchBehavior noMatchBehavior = NoMatchBehavior.DENY;

    public enum NoMatchBehavior {
        DENY,
        ALLOW
    }
}
