package org.mangala.gateway.policy;

import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.reactor.circuitbreaker.operator.CircuitBreakerOperator;
import io.github.resilience4j.reactor.timelimiter.TimeLimiterOperator;
import io.github.resilience4j.timelimiter.TimeLimiter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.mangala.security.model.ApiPermissionDTO;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Loads policy rules from Auth Service at gateway startup.
 * Protected by circuit breaker for resilience.
 * Also provides methods for manual reload.
 */
@Slf4j
@Component
@Order(1)
@RequiredArgsConstructor
public class PolicyLoader implements ApplicationRunner {

    private final PolicyCache policyCache;
    private final PolicyConfigProperties policyConfig;
    private final AuthPolicyApiClient authPolicyApiClient;
    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final CircuitBreaker policyLoaderCircuitBreaker;
    private final TimeLimiter policyLoaderTimeLimiter;
    private final AtomicBoolean loadInProgress = new AtomicBoolean(false);

    private static final String POLICY_VERSION_KEY = "policy:version";

    @Override
    public void run(ApplicationArguments args) {
        log.info("Starting policy loader...");
        loadPolicies()
                .doOnSuccess(v -> log.info("Initial policy load completed successfully"))
                .doOnError(e -> log.error("Initial policy load failed", e))
                .block(Duration.ofSeconds(policyConfig.getInitialLoadTimeoutSeconds()));
    }

    /**
     * Load all policies from Auth Service with circuit breaker protection.
     */
    public Mono<Void> loadPolicies() {
        if (!loadInProgress.compareAndSet(false, true)) {
            log.info("Policy load already in progress, skipping duplicate trigger");
            return Mono.empty();
        }

        log.info("Loading policies from Auth Service: {}", policyConfig.getAuthServiceUrl());

        return authPolicyApiClient.fetchPolicies()
                // Apply time limiter first, then circuit breaker
                .transformDeferred(TimeLimiterOperator.of(policyLoaderTimeLimiter))
                .transformDeferred(CircuitBreakerOperator.of(policyLoaderCircuitBreaker))
                // Retry with backoff (only for retryable errors)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1))
                        .maxBackoff(Duration.ofSeconds(10))
                        .filter(this::isRetryableError)
                        .doBeforeRetry(signal -> log.warn("Retrying policy load, attempt: {}",
                                signal.totalRetries() + 1)))
                .flatMap(this::loadPoliciesAndVersion)
                // Fallback when circuit breaker is open or call fails
                .onErrorResume(this::handleLoadError)
                .doFinally(signal -> loadInProgress.set(false))
                .then();
    }

    /**
     * Reload policies if version has changed.
     */
    public Mono<Boolean> reloadIfVersionChanged() {
        return fetchRemoteVersion()
                .flatMap(remoteVersion -> {
                    long currentVersion = policyCache.getVersion().get();
                    if (remoteVersion > currentVersion) {
                        log.info("Policy version changed: {} -> {}. Reloading...", currentVersion, remoteVersion);
                        return loadPolicies().thenReturn(true);
                    }
                    return Mono.just(false);
                })
                .onErrorResume(e -> {
                    log.warn("Failed to check policy version", e);
                    return Mono.just(false);
                });
    }

    /**
     * Force reload policies regardless of version.
     */
    public Mono<Void> forceReload() {
        log.info("Force reloading policies...");
        return loadPolicies();
    }

    /**
     * Get circuit breaker state for health checks.
     */
    public CircuitBreaker.State getCircuitBreakerState() {
        return policyLoaderCircuitBreaker.getState();
    }

    /**
     * Check if circuit breaker is allowing calls.
     */
    public boolean isCircuitBreakerHealthy() {
        CircuitBreaker.State state = policyLoaderCircuitBreaker.getState();
        return state == CircuitBreaker.State.CLOSED ||
                state == CircuitBreaker.State.HALF_OPEN;
    }

    /**
     * Determine if an error is retryable.
     * Circuit breaker open errors should not be retried.
     */
    private boolean isRetryableError(Throwable t) {
        // Don't retry if circuit breaker is open
        if (t instanceof CallNotPermittedException) {
            log.debug("Circuit breaker is open, not retrying");
            return false;
        }
        // Retry on network/timeout errors
        return true;
    }

    /**
     * Fallback handler - continues with cached policies if available.
     */
    private Mono<Void> handleLoadError(Throwable error) {
        if (error instanceof CallNotPermittedException) {
            log.warn("Policy load blocked by circuit breaker - using cached policies");
        } else {
            log.error("Policy load failed: {}", error.getMessage());
        }

        // If we have cached policies, continue using them
        if (policyCache.getTotalRules() > 0) {
            log.info("Fallback: continuing with {} cached policies", policyCache.getTotalRules());
            return Mono.empty();
        }

        // No cached policies and load failed - mark unhealthy
        log.error("No cached policies available and load failed - marking cache unhealthy");
        policyCache.markUnhealthy();
        return Mono.empty();
    }

    private Mono<Void> loadPoliciesAndVersion(List<ApiPermissionDTO> permissions) {
        return fetchRemoteVersion()
                .doOnNext(version -> {
                    policyCache.loadFromDatabase(permissions);
                    policyCache.setVersion(version);
                    log.info("Loaded {} policies, version: {}", permissions.size(), version);
                })
                .then();
    }

    private Mono<Long> fetchRemoteVersion() {
        // Try Redis first
        return redisTemplate.opsForValue()
                .get(POLICY_VERSION_KEY)
                .map(Long::parseLong)
                .switchIfEmpty(fetchVersionFromAuthService())
                .onErrorResume(e -> {
                    log.warn("Failed to fetch version from Redis, trying Auth Service", e);
                    return fetchVersionFromAuthService();
                });
    }

    private Mono<Long> fetchVersionFromAuthService() {
        return authPolicyApiClient.fetchPolicyVersion()
                // Apply circuit breaker to version fetch as well
                .transformDeferred(CircuitBreakerOperator.of(policyLoaderCircuitBreaker))
                .doOnNext(v -> {
                    // Update Redis with latest version
                    redisTemplate.opsForValue()
                            .set(POLICY_VERSION_KEY, v.toString(), Duration.ofMinutes(5))
                            .subscribe();
                })
                .onErrorReturn(1L);
    }
}
