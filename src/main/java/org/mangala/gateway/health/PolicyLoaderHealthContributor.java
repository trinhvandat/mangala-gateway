package org.mangala.gateway.health;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * Health indicator for PolicyLoader circuit breaker.
 * Reports circuit breaker state and metrics to /actuator/health endpoint.
 */
@Component("policyLoaderHealth")
@RequiredArgsConstructor
public class PolicyLoaderHealthContributor implements HealthIndicator {

    private final CircuitBreaker policyLoaderCircuitBreaker;

    @Override
    public Health health() {
        CircuitBreaker.State state = policyLoaderCircuitBreaker.getState();
        CircuitBreaker.Metrics metrics = policyLoaderCircuitBreaker.getMetrics();

        Health.Builder builder = switch (state) {
            case CLOSED -> Health.up();
            case HALF_OPEN -> Health.status("DEGRADED");
            case OPEN, DISABLED, FORCED_OPEN -> Health.down();
            case METRICS_ONLY -> Health.unknown();
        };

        return builder
                .withDetail("circuitBreakerState", state.name())
                .withDetail("failureRate", String.format("%.2f%%", metrics.getFailureRate()))
                .withDetail("slowCallRate", String.format("%.2f%%", metrics.getSlowCallRate()))
                .withDetail("successfulCalls", metrics.getNumberOfSuccessfulCalls())
                .withDetail("failedCalls", metrics.getNumberOfFailedCalls())
                .withDetail("notPermittedCalls", metrics.getNumberOfNotPermittedCalls())
                .withDetail("bufferedCalls", metrics.getNumberOfBufferedCalls())
                .build();
    }
}
