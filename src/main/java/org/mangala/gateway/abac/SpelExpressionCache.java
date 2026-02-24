package org.mangala.gateway.abac;

import lombok.extern.slf4j.Slf4j;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Cache for compiled SpEL expressions.
 * Thread-safe implementation using ConcurrentHashMap.
 */
@Slf4j
@Component
public class SpelExpressionCache {

    private final SpelExpressionParser parser = new SpelExpressionParser();
    private final ConcurrentHashMap<String, Expression> cache = new ConcurrentHashMap<>();
    private final SpelSecurityConfig securityConfig;

    private final AtomicLong cacheHits = new AtomicLong(0);
    private final AtomicLong cacheMisses = new AtomicLong(0);

    public SpelExpressionCache(SpelSecurityConfig securityConfig) {
        this.securityConfig = securityConfig;
    }

    /**
     * Get a compiled expression from cache or parse and cache it.
     *
     * @param expressionString The SpEL expression string
     * @return Compiled Expression
     */
    public Expression getOrParse(String expressionString) {
        Expression cached = cache.get(expressionString);
        if (cached != null) {
            cacheHits.incrementAndGet();
            return cached;
        }

        cacheMisses.incrementAndGet();

        // Evict if cache is full (simple eviction - remove ~10% of entries)
        if (cache.size() >= securityConfig.getMaxCacheSize()) {
            evictOldEntries();
        }

        Expression expression = parser.parseExpression(expressionString);
        cache.put(expressionString, expression);

        if (log.isDebugEnabled()) {
            log.debug("Cached new expression: {}", expressionString);
        }

        return expression;
    }

    /**
     * Clear all cached expressions.
     */
    public void clear() {
        cache.clear();
        cacheHits.set(0);
        cacheMisses.set(0);
        log.info("Expression cache cleared");
    }

    /**
     * Get current cache size.
     */
    public int size() {
        return cache.size();
    }

    /**
     * Get cache hit ratio.
     */
    public double getHitRatio() {
        long total = cacheHits.get() + cacheMisses.get();
        return total > 0 ? (double) cacheHits.get() / total : 0.0;
    }

    /**
     * Get cache statistics.
     */
    public CacheStats getStats() {
        return new CacheStats(
                cache.size(),
                cacheHits.get(),
                cacheMisses.get(),
                getHitRatio()
        );
    }

    private void evictOldEntries() {
        int toRemove = securityConfig.getMaxCacheSize() / 10;
        int removed = 0;

        for (String key : cache.keySet()) {
            if (removed >= toRemove) break;
            cache.remove(key);
            removed++;
        }

        log.debug("Evicted {} expressions from cache", removed);
    }

    public record CacheStats(int size, long hits, long misses, double hitRatio) {}
}
