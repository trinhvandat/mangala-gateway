package org.mangala.gateway.policy;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

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

    /**
     * Policy API mTLS client configuration for gateway -> auth-service.
     */
    private MtlsConfig mtls = new MtlsConfig();

    /**
     * Enforce mTLS settings when running in non-dev profiles.
     */
    private ProfileGuardConfig profileGuard = new ProfileGuardConfig();

    public enum NoMatchBehavior {
        DENY,
        ALLOW
    }

    @Getter
    @Setter
    public static class MtlsConfig {
        /**
         * Enable mTLS client certificate for policy API calls.
         */
        private boolean enabled = false;

        /**
         * Path to client key store (PKCS12/JKS).
         */
        private String keyStorePath;

        /**
         * Key store password.
         */
        private String keyStorePassword;

        /**
         * Key store type.
         */
        private String keyStoreType = "PKCS12";

        /**
         * Path to trust store with auth-service CA/server cert.
         */
        private String trustStorePath;

        /**
         * Trust store password.
         */
        private String trustStorePassword;

        /**
         * Trust store type.
         */
        private String trustStoreType = "PKCS12";
    }

    @Getter
    @Setter
    public static class ProfileGuardConfig {
        /**
         * Enforce mTLS on non-dev profiles.
         */
        private boolean enforceMtlsInNonDev = true;

        /**
         * Profiles considered development-like and excluded from strict enforcement.
         */
        private List<String> devProfiles = List.of("dev", "local", "test");
    }
}
