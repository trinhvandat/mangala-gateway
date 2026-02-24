package org.mangala.gateway.health;

import lombok.RequiredArgsConstructor;
import org.mangala.gateway.policy.PolicyCache;
import org.mangala.gateway.policy.PolicyConfigProperties;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

/**
 * Health indicator for policy cache status.
 */
@Component
@RequiredArgsConstructor
public class PolicyCacheHealthIndicator implements HealthIndicator {

    private final PolicyCache policyCache;
    private final PolicyConfigProperties policyConfig;

    private static final long STALE_THRESHOLD_MS = 300_000; // 5 minutes

    @Override
    public Health health() {
        if (!policyConfig.isIncludeInHealthCheck()) {
            return Health.up()
                    .withDetail("status", "Not included in health check")
                    .build();
        }

        if (!policyCache.isHealthy()) {
            return Health.down()
                    .withDetail("status", "Policy cache is not healthy")
                    .withDetail("totalRules", policyCache.getTotalRules())
                    .withDetail("version", policyCache.getVersion().get())
                    .build();
        }

        long staleDuration = System.currentTimeMillis() - policyCache.getLastLoadTimestamp();
        boolean isStale = staleDuration > STALE_THRESHOLD_MS;

        Health.Builder builder = isStale ? Health.status("DEGRADED") : Health.up();

        return builder
                .withDetail("status", isStale ? "Cache may be stale" : "Healthy")
                .withDetail("totalRules", policyCache.getTotalRules())
                .withDetail("version", policyCache.getVersion().get())
                .withDetail("lastLoadTime", Instant.ofEpochMilli(policyCache.getLastLoadTimestamp()).toString())
                .withDetail("staleDuration", Duration.ofMillis(staleDuration).toString())
                .build();
    }
}
