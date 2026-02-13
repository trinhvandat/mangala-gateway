package org.mangala.gateway.policy;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.timelimiter.TimeLimiter;
import io.github.resilience4j.timelimiter.TimeLimiterConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * Circuit breaker configuration for PolicyLoader.
 * Protects Auth Service calls during policy loading.
 */
@Slf4j
@Configuration
public class PolicyLoaderCircuitBreakerConfig {

    public static final String POLICY_LOADER_CB = "policyLoaderCircuitBreaker";
    public static final String POLICY_LOADER_TL = "policyLoaderTimeLimiter";

    @Bean
    public CircuitBreaker policyLoaderCircuitBreaker(CircuitBreakerRegistry circuitBreakerRegistry) {
        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
                .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
                .slidingWindowSize(5)
                .minimumNumberOfCalls(3)
                .failureRateThreshold(60)
                .waitDurationInOpenState(Duration.ofSeconds(30))
                .permittedNumberOfCallsInHalfOpenState(2)
                .automaticTransitionFromOpenToHalfOpenEnabled(true)
                .recordExceptions(Exception.class)
                .build();

        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(POLICY_LOADER_CB, config);

        // Register event handlers for monitoring
        circuitBreaker.getEventPublisher()
                .onStateTransition(event ->
                        log.info("Policy loader circuit breaker state changed: {} -> {}",
                                event.getStateTransition().getFromState(),
                                event.getStateTransition().getToState()))
                .onError(event ->
                        log.warn("Policy loader circuit breaker recorded error: {}",
                                event.getThrowable().getMessage()))
                .onSuccess(event -> {
                    if (log.isDebugEnabled()) {
                        log.debug("Policy loader call succeeded in {}ms",
                                event.getElapsedDuration().toMillis());
                    }
                })
                .onCallNotPermitted(event ->
                        log.warn("Policy loader call not permitted - circuit breaker is OPEN"));

        return circuitBreaker;
    }

    @Bean
    public TimeLimiter policyLoaderTimeLimiter() {
        TimeLimiterConfig config = TimeLimiterConfig.custom()
                .timeoutDuration(Duration.ofSeconds(10))
                .cancelRunningFuture(true)
                .build();

        return TimeLimiter.of(POLICY_LOADER_TL, config);
    }
}
