package org.mangala.gateway.abac;

import lombok.extern.slf4j.Slf4j;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.*;
import java.util.regex.Pattern;

/**
 * Secure SpEL condition evaluator for ABAC expressions.
 *
 * Features:
 * - Expression validation against blocked patterns
 * - Method call whitelisting
 * - Evaluation timeout
 * - Expression caching
 *
 * Example expressions:
 * - #userId == #pathVar['walletId']
 * - #roles.contains('ADMIN')
 * - #attributes['tier'] == 'premium'
 * - #userId == #pathVar['userId'] and #roles.contains('MANAGER')
 */
@Slf4j
@Component
public class SpelConditionEvaluator {

    private final SpelExpressionCache expressionCache;
    private final SpelSecurityConfig securityConfig;

    // Thread pool for timeout enforcement
    private final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "spel-evaluator");
        t.setDaemon(true);
        return t;
    });

    // Pre-compiled blocked patterns
    private List<Pattern> blockedPatterns;

    public SpelConditionEvaluator(SpelExpressionCache expressionCache, SpelSecurityConfig securityConfig) {
        this.expressionCache = expressionCache;
        this.securityConfig = securityConfig;
        this.blockedPatterns = securityConfig.getBlockedPatterns().stream()
                .map(p -> Pattern.compile(p, Pattern.CASE_INSENSITIVE))
                .toList();
    }

    /**
     * Evaluate a SpEL condition expression.
     *
     * @param expression The SpEL expression (e.g., "#userId == #pathVar['walletId']")
     * @param context    The evaluation context with all variables
     * @return true if condition is met, false otherwise
     * @throws ConditionEvaluationException if expression is invalid or blocked
     */
    public boolean evaluate(String expression, AbacEvaluationContext context) {
        if (!securityConfig.isEnabled()) {
            log.debug("ABAC SpEL evaluation disabled, returning true");
            return true;
        }

        if (expression == null || expression.isBlank()) {
            return true;  // No condition = passes
        }

        // Security validations
        validateExpression(expression);

        try {
            Expression spelExpr = expressionCache.getOrParse(expression);
            EvaluationContext evalContext = createEvaluationContext(context);

            // Evaluate with timeout
            Future<Boolean> future = executor.submit(() -> {
                Boolean result = spelExpr.getValue(evalContext, Boolean.class);
                return result != null ? result : false;
            });

            boolean result = future.get(securityConfig.getEvaluationTimeoutMs(), TimeUnit.MILLISECONDS);

            if (log.isDebugEnabled()) {
                log.debug("SpEL evaluation: '{}' = {}", expression, result);
            }

            return result;

        } catch (TimeoutException e) {
            log.warn("SpEL evaluation timed out for expression: {}", expression);
            throw new ConditionEvaluationException("Expression evaluation timed out");

        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            log.warn("SpEL evaluation failed for expression '{}': {}", expression, cause.getMessage());
            throw new ConditionEvaluationException("Expression evaluation failed: " + cause.getMessage(), cause);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ConditionEvaluationException("Expression evaluation interrupted");

        } catch (Exception e) {
            log.warn("SpEL evaluation error for expression '{}': {}", expression, e.getMessage());
            throw new ConditionEvaluationException("Expression evaluation error: " + e.getMessage(), e);
        }
    }

    /**
     * Evaluate safely, returning false on any error (fail-closed).
     */
    public boolean evaluateSafe(String expression, AbacEvaluationContext context) {
        try {
            return evaluate(expression, context);
        } catch (Exception e) {
            log.warn("Safe evaluation failed, returning false: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Validate expression before parsing.
     */
    private void validateExpression(String expression) {
        // Length check
        if (expression.length() > securityConfig.getMaxExpressionLength()) {
            throw new ConditionEvaluationException(
                    "Expression exceeds maximum length of " + securityConfig.getMaxExpressionLength());
        }

        // Check for blocked patterns
        for (Pattern pattern : blockedPatterns) {
            if (pattern.matcher(expression).find()) {
                log.warn("Blocked expression pattern detected: {}", expression);
                throw new ConditionEvaluationException(
                        "Expression contains blocked pattern");
            }
        }
    }

    /**
     * Create a restricted evaluation context.
     */
    private EvaluationContext createEvaluationContext(AbacEvaluationContext context) {
        StandardEvaluationContext evalContext = new StandardEvaluationContext();

        // Set allowed variables
        evalContext.setVariable("userId", context.getUserId());
        evalContext.setVariable("email", context.getEmail());
        evalContext.setVariable("roles", context.getRoles());
        evalContext.setVariable("permissions", context.getPermissions());
        evalContext.setVariable("attributes", context.getAttributes());
        evalContext.setVariable("pathVar", context.getPathVariables());
        evalContext.setVariable("httpMethod", context.getHttpMethod());
        evalContext.setVariable("path", context.getPath());
        evalContext.setVariable("queryParams", context.getQueryParams());

        // Use restricted method resolver
        evalContext.setMethodResolvers(
                List.of(new RestrictedMethodResolver(securityConfig.getAllowedMethods()))
        );

        return evalContext;
    }

    /**
     * Get expression cache statistics.
     */
    public SpelExpressionCache.CacheStats getCacheStats() {
        return expressionCache.getStats();
    }

    /**
     * Clear the expression cache.
     */
    public void clearCache() {
        expressionCache.clear();
    }
}
