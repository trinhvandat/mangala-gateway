package org.mangala.gateway.policy;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Periodically checks policy version as a fallback mechanism.
 * This ensures policies are eventually consistent even if broadcasts are missed.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PolicyVersionChecker {

    private final PolicyLoader policyLoader;
    private final PolicyCache policyCache;

    /**
     * Check for policy updates every 60 seconds.
     * This is a fallback in case broadcast messages are missed.
     */
    @Scheduled(fixedDelayString = "${gateway.policy.version-check-interval-seconds:60}000")
    public void checkForUpdates() {
        if (!policyCache.isHealthy()) {
            log.warn("Policy cache unhealthy, attempting reload...");
            policyLoader.forceReload()
                    .doOnSuccess(v -> log.info("Policy cache recovered"))
                    .doOnError(e -> log.error("Policy cache recovery failed", e))
                    .subscribe();
            return;
        }

        // Check if cache is stale (not updated in 5 minutes)
        long staleDuration = System.currentTimeMillis() - policyCache.getLastLoadTimestamp();
        if (staleDuration > 300_000) { // 5 minutes
            log.warn("Policy cache may be stale (last load: {}ms ago). Checking version...", staleDuration);
        }

        policyLoader.reloadIfVersionChanged()
                .subscribe(reloaded -> {
                    if (reloaded) {
                        log.info("Policy cache updated via version check");
                    }
                });
    }
}
