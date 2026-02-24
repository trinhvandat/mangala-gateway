package org.mangala.gateway.policy;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.mangala.security.model.ApiPermissionDTO;
import org.mangala.security.model.PolicyRule;
import org.mangala.security.util.PermissionMatcher;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * In-memory cache for policy rules.
 * Loaded from database at startup and refreshed on policy update events.
 *
 * Thread-safe implementation using ConcurrentHashMap and CopyOnWriteArrayList.
 */
@Slf4j
@Component
public class PolicyCache {

    // Exact match cache: "METHOD:path" -> PolicyRule
    private final ConcurrentHashMap<String, PolicyRule> exactMatchRules = new ConcurrentHashMap<>();

    // Pattern match rules (for wildcards and path variables)
    private final CopyOnWriteArrayList<PolicyRule> patternRules = new CopyOnWriteArrayList<>();

    // Current policy version
    @Getter
    private final AtomicLong version = new AtomicLong(0);

    // Cache health status
    @Getter
    private volatile boolean healthy = false;

    private volatile long lastLoadTimestamp = 0;

    /**
     * Load policies from database into cache.
     * This performs an atomic swap to avoid inconsistent reads during reload.
     *
     * @param permissions List of API permissions from database
     */
    public synchronized void loadFromDatabase(List<ApiPermissionDTO> permissions) {
        log.info("Loading {} policy rules into cache...", permissions.size());
        long startTime = System.currentTimeMillis();

        // Group by method:path to consolidate permissions
        Map<String, PolicyRule> newExactRules = new HashMap<>();
        List<PolicyRule> newPatternRules = new ArrayList<>();

        // Group permissions by endpoint
        Map<String, List<ApiPermissionDTO>> groupedByEndpoint = permissions.stream()
                .filter(ApiPermissionDTO::isActive)
                .collect(Collectors.groupingBy(p -> p.getHttpMethod() + ":" + p.getPathPattern()));

        for (Map.Entry<String, List<ApiPermissionDTO>> entry : groupedByEndpoint.entrySet()) {
            List<ApiPermissionDTO> perms = entry.getValue();
            ApiPermissionDTO first = perms.get(0);

            // Collect all required permissions for this endpoint
            Set<String> requiredPermissions = perms.stream()
                    .map(ApiPermissionDTO::getPermissionCode)
                    .collect(Collectors.toSet());

            // Compile path pattern
            Pattern compiledPattern = PermissionMatcher.compilePathPattern(first.getPathPattern());

            PolicyRule rule = PolicyRule.builder()
                    .id(first.getId())
                    .httpMethod(first.getHttpMethod())
                    .pathPattern(first.getPathPattern())
                    .requiredPermissions(requiredPermissions)
                    .conditionExpr(first.getConditionExpr())
                    .serviceName(first.getServiceName())
                    .priority(first.getPriority())
                    .compiledPattern(compiledPattern)
                    .build();

            // Categorize as exact match or pattern match
            if (isExactMatchPattern(first.getPathPattern())) {
                newExactRules.put(entry.getKey(), rule);
            } else {
                newPatternRules.add(rule);
            }
        }

        // Sort pattern rules by priority (higher first) and specificity
        newPatternRules.sort((a, b) -> {
            int priorityCompare = Integer.compare(b.getPriority(), a.getPriority());
            if (priorityCompare != 0) return priorityCompare;
            // More specific patterns (longer) come first
            return Integer.compare(b.getPathPattern().length(), a.getPathPattern().length());
        });

        // Atomic swap
        exactMatchRules.clear();
        exactMatchRules.putAll(newExactRules);

        patternRules.clear();
        patternRules.addAll(newPatternRules);

        lastLoadTimestamp = System.currentTimeMillis();
        healthy = true;

        log.info("Policy cache loaded successfully. Exact rules: {}, Pattern rules: {}. Time: {}ms",
                exactMatchRules.size(), patternRules.size(), System.currentTimeMillis() - startTime);
    }

    /**
     * Find matching policy rule for a request.
     *
     * @param method HTTP method
     * @param path   Request path (should be normalized)
     * @return Optional containing matching PolicyRule
     */
    public Optional<PolicyRule> findMatchingRule(String method, String path) {
        if (!healthy) {
            log.warn("Policy cache is not healthy, returning empty");
            return Optional.empty();
        }

        // 1. Try exact match with specific method
        String exactKey = method + ":" + path;
        PolicyRule exactRule = exactMatchRules.get(exactKey);
        if (exactRule != null) {
            return Optional.of(exactRule);
        }

        // 2. Try exact match with wildcard method
        String wildcardKey = "*:" + path;
        PolicyRule wildcardRule = exactMatchRules.get(wildcardKey);
        if (wildcardRule != null) {
            return Optional.of(wildcardRule);
        }

        // 3. Try pattern matching (already sorted by priority)
        for (PolicyRule rule : patternRules) {
            if (matchesRule(rule, method, path)) {
                return Optional.of(rule);
            }
        }

        return Optional.empty();
    }

    /**
     * Find all matching rules for a request (for audit/debug purposes).
     *
     * @param method HTTP method
     * @param path   Request path
     * @return List of all matching rules
     */
    public List<PolicyRule> findAllMatchingRules(String method, String path) {
        List<PolicyRule> matches = new ArrayList<>();

        // Check exact matches
        String exactKey = method + ":" + path;
        PolicyRule exactRule = exactMatchRules.get(exactKey);
        if (exactRule != null) {
            matches.add(exactRule);
        }

        String wildcardKey = "*:" + path;
        PolicyRule wildcardRule = exactMatchRules.get(wildcardKey);
        if (wildcardRule != null) {
            matches.add(wildcardRule);
        }

        // Check pattern matches
        for (PolicyRule rule : patternRules) {
            if (matchesRule(rule, method, path)) {
                matches.add(rule);
            }
        }

        return matches;
    }

    /**
     * Update policy version.
     *
     * @param newVersion New version number
     */
    public void setVersion(long newVersion) {
        version.set(newVersion);
    }

    /**
     * Get last successful load timestamp.
     */
    public long getLastLoadTimestamp() {
        return lastLoadTimestamp;
    }

    /**
     * Get total number of cached rules.
     */
    public int getTotalRules() {
        return exactMatchRules.size() + patternRules.size();
    }

    /**
     * Mark cache as unhealthy (e.g., on load failure).
     */
    public void markUnhealthy() {
        this.healthy = false;
    }

    /**
     * Clear all cached rules.
     */
    public synchronized void clear() {
        exactMatchRules.clear();
        patternRules.clear();
        healthy = false;
        log.info("Policy cache cleared");
    }

    private boolean isExactMatchPattern(String pathPattern) {
        // Exact match if no wildcards or path variables
        return !pathPattern.contains("*") &&
                !pathPattern.contains("{") &&
                !pathPattern.contains("}");
    }

    private boolean matchesRule(PolicyRule rule, String method, String path) {
        // Check method
        if (!PermissionMatcher.matchesMethod(rule.getHttpMethod(), method)) {
            return false;
        }

        // Check path pattern
        return PermissionMatcher.matchesPath(rule.getCompiledPattern(), path);
    }
}
