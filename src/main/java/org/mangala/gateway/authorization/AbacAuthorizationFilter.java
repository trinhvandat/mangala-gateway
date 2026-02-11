package org.mangala.gateway.authorization;

import lombok.extern.slf4j.Slf4j;
import org.mangala.gateway.abac.AbacEvaluationContext;
import org.mangala.gateway.abac.SpelConditionEvaluator;
import org.mangala.gateway.audit.AuthorizationAuditEvent;
import org.mangala.gateway.audit.AuthorizationAuditPublisher;
import org.mangala.gateway.config.GatewayConfigProperties;
import org.mangala.gateway.policy.PolicyCache;
import org.mangala.gateway.policy.PolicyConfigProperties;
import org.mangala.security.SecurityConstants;
import org.mangala.security.model.AuthorizationResult;
import org.mangala.security.model.PolicyRule;
import org.mangala.security.util.PathNormalizer;
import org.mangala.security.util.PermissionMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.util.*;

/**
 * ABAC Authorization Filter that enforces permission-based access control.
 *
 * This filter:
 * 1. Extracts user permissions from JWT (via SecurityContext)
 * 2. Matches request path to policy rules (from in-memory cache)
 * 3. Checks if user has required permissions
 * 4. Evaluates ABAC conditions if present (using SpEL)
 * 5. Publishes audit events to Kafka
 * 6. Returns 403 if unauthorized
 */
@Slf4j
@Component
public class AbacAuthorizationFilter implements WebFilter, Ordered {

    private final PolicyCache policyCache;
    private final PolicyConfigProperties policyConfig;
    private final GatewayConfigProperties gatewayConfig;
    private final SpelConditionEvaluator spelConditionEvaluator;
    private final AuthorizationAuditPublisher auditPublisher;

    @Autowired
    public AbacAuthorizationFilter(
            PolicyCache policyCache,
            PolicyConfigProperties policyConfig,
            GatewayConfigProperties gatewayConfig,
            SpelConditionEvaluator spelConditionEvaluator,
            @Autowired(required = false) AuthorizationAuditPublisher auditPublisher) {
        this.policyCache = policyCache;
        this.policyConfig = policyConfig;
        this.gatewayConfig = gatewayConfig;
        this.spelConditionEvaluator = spelConditionEvaluator;
        this.auditPublisher = auditPublisher;
    }

    @Override
    public int getOrder() {
        // Run after authentication filter
        return Ordered.LOWEST_PRECEDENCE - 10;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = PathNormalizer.normalize(request.getPath().value());
        String method = request.getMethod().name();

        // Skip public paths
        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }

        // Skip if policy cache is not healthy
        if (!policyCache.isHealthy()) {
            log.error("Policy cache unhealthy, denying all requests");
            return respondServiceUnavailable(exchange);
        }

        // Check path for security issues
        if (!PathNormalizer.isValidPath(path)) {
            log.warn("Invalid path detected: {}", request.getPath().value());
            return respondBadRequest(exchange, "Invalid request path");
        }

        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication())
                .flatMap(auth -> authorize(auth, method, path, exchange))
                .switchIfEmpty(Mono.defer(() -> {
                    // No authentication context - check if endpoint requires auth
                    return authorizeUnauthenticated(method, path, exchange, chain);
                }))
                .flatMap(result -> {
                    if (result.isAllowed()) {
                        return chain.filter(enrichRequest(exchange, result));
                    } else {
                        return respondForbidden(exchange, result);
                    }
                });
    }

    private Mono<AuthorizationResult> authorize(Authentication auth, String method, String path, ServerWebExchange exchange) {
        long startTime = System.currentTimeMillis();

        if (auth == null || !auth.isAuthenticated()) {
            AuthorizationResult result = AuthorizationResult.deny("Not authenticated", Collections.emptySet());
            publishAuditEvent(exchange, null, path, result, null, null, null, null);
            return Mono.just(result);
        }

        // Extract user details
        String userId = (String) auth.getPrincipal();
        Map<String, Object> details = extractAuthDetails(auth);
        Set<String> userPermissions = extractPermissions(auth);
        Set<String> userRoles = extractRoles(details);
        String email = (String) details.getOrDefault("email", null);

        // Find matching policy rule
        Optional<PolicyRule> ruleOpt = policyCache.findMatchingRule(method, path);

        if (ruleOpt.isEmpty()) {
            // No policy rule found
            AuthorizationResult result = handleNoMatchingRuleSync(method, path, startTime);
            publishAuditEvent(exchange, auth, path, result, userPermissions, userRoles, null, null);
            return Mono.just(result);
        }

        PolicyRule rule = ruleOpt.get();
        Set<String> requiredPermissions = rule.getRequiredPermissions();

        // Check if user has any of the required permissions
        boolean hasPermission = PermissionMatcher.hasAnyPermission(userPermissions, requiredPermissions);

        if (!hasPermission) {
            log.info("Authorization denied for {} {}. Required: {}, User has: {}",
                    method, path, requiredPermissions, userPermissions);

            AuthorizationResult result = AuthorizationResult.deny(
                    "Insufficient permissions",
                    requiredPermissions
            );
            result.setEvaluationTimeMs(System.currentTimeMillis() - startTime);
            publishAuditEvent(exchange, auth, path, result, userPermissions, userRoles, rule.getConditionExpr(), null);
            return Mono.just(result);
        }

        // Evaluate ABAC conditions if present
        Boolean conditionResult = null;
        if (rule.getConditionExpr() != null && !rule.getConditionExpr().isEmpty()) {
            conditionResult = evaluateCondition(rule, auth, exchange);
            if (!conditionResult) {
                log.info("ABAC condition failed for {} {}: {}", method, path, rule.getConditionExpr());
                AuthorizationResult result = AuthorizationResult.deny(
                        "Access condition not met",
                        requiredPermissions
                );
                result.setEvaluationTimeMs(System.currentTimeMillis() - startTime);
                publishAuditEvent(exchange, auth, path, result, userPermissions, userRoles, rule.getConditionExpr(), conditionResult);
                return Mono.just(result);
            }
        }

        AuthorizationResult result = AuthorizationResult.allow(rule.getCacheKey());
        result.setEvaluationTimeMs(System.currentTimeMillis() - startTime);
        publishAuditEvent(exchange, auth, path, result, userPermissions, userRoles, rule.getConditionExpr(), conditionResult);
        return Mono.just(result);
    }

    private Mono<AuthorizationResult> authorizeUnauthenticated(String method, String path,
                                                                ServerWebExchange exchange,
                                                                WebFilterChain chain) {
        // Check if this endpoint has any policy rules
        Optional<PolicyRule> ruleOpt = policyCache.findMatchingRule(method, path);

        AuthorizationResult result;
        if (ruleOpt.isEmpty()) {
            // No policy = use default behavior
            if (policyConfig.getNoMatchBehavior() == PolicyConfigProperties.NoMatchBehavior.ALLOW) {
                result = AuthorizationResult.allow("no-policy-allow");
            } else {
                result = AuthorizationResult.noPolicy(path);
            }
        } else {
            // Has policy but no auth = deny
            result = AuthorizationResult.deny("Authentication required", ruleOpt.get().getRequiredPermissions());
        }

        publishAuditEvent(exchange, null, path, result, null, null, null, null);
        return Mono.just(result);
    }

    private AuthorizationResult handleNoMatchingRuleSync(String method, String path, long startTime) {
        AuthorizationResult result;
        if (policyConfig.getNoMatchBehavior() == PolicyConfigProperties.NoMatchBehavior.ALLOW) {
            log.debug("No policy rule for {} {}, allowing (permissive mode)", method, path);
            result = AuthorizationResult.allow("no-policy-allow");
        } else {
            log.warn("No policy rule found for {} {}. Denying request.", method, path);
            result = AuthorizationResult.noPolicy(path);
        }
        result.setEvaluationTimeMs(System.currentTimeMillis() - startTime);
        return result;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> extractAuthDetails(Authentication auth) {
        if (auth.getDetails() instanceof Map) {
            return (Map<String, Object>) auth.getDetails();
        }
        return Collections.emptyMap();
    }

    @SuppressWarnings("unchecked")
    private Set<String> extractPermissions(Authentication auth) {
        Set<String> permissions = new HashSet<>();

        // Try to get permissions from authentication details
        Map<String, Object> details = extractAuthDetails(auth);
        Object perms = details.get("permissions");
        if (perms instanceof Collection) {
            ((Collection<?>) perms).forEach(p -> permissions.add(p.toString()));
        }

        // Also extract from authorities (roles)
        auth.getAuthorities().forEach(a -> {
            String authority = a.getAuthority();
            // If authority looks like a permission (contains :), add it
            if (authority.contains(":")) {
                permissions.add(authority);
            }
        });

        return permissions;
    }

    @SuppressWarnings("unchecked")
    private Set<String> extractRoles(Map<String, Object> details) {
        Object roles = details.get("roles");
        if (roles instanceof Set) {
            return (Set<String>) roles;
        } else if (roles instanceof Collection) {
            Set<String> roleSet = new HashSet<>();
            ((Collection<?>) roles).forEach(r -> roleSet.add(r.toString()));
            return roleSet;
        }
        return Collections.emptySet();
    }

    /**
     * Evaluate ABAC condition using SpEL.
     */
    @SuppressWarnings("unchecked")
    private boolean evaluateCondition(PolicyRule rule, Authentication auth, ServerWebExchange exchange) {
        try {
            ServerHttpRequest request = exchange.getRequest();

            // Extract user details from authentication
            String userId = (String) auth.getPrincipal();
            Map<String, Object> details = extractAuthDetails(auth);

            String email = (String) details.getOrDefault("email", null);
            Set<String> roles = extractRoles(details);
            Set<String> permissions = details.get("permissions") instanceof Set
                    ? (Set<String>) details.get("permissions")
                    : Collections.emptySet();
            Map<String, Object> attributes = details.get("attributes") instanceof Map
                    ? (Map<String, Object>) details.get("attributes")
                    : Collections.emptyMap();

            // Extract path variables from URL
            Map<String, String> pathVariables = PathNormalizer.extractPathVariables(
                    rule.getPathPattern(),
                    request.getPath().value()
            );

            // Extract query parameters
            Map<String, String> queryParams = new HashMap<>();
            request.getQueryParams().forEach((key, values) -> {
                if (!values.isEmpty()) {
                    queryParams.put(key, values.get(0));
                }
            });

            // Build evaluation context
            AbacEvaluationContext context = AbacEvaluationContext.of(
                    userId,
                    email,
                    roles,
                    permissions,
                    attributes,
                    pathVariables,
                    request.getMethod().name(),
                    request.getPath().value(),
                    queryParams
            );

            // Evaluate using SpEL (fail-closed: returns false on any error)
            return spelConditionEvaluator.evaluateSafe(rule.getConditionExpr(), context);

        } catch (Exception e) {
            log.warn("Error preparing ABAC evaluation context: {}", e.getMessage());
            return false; // Fail closed
        }
    }

    /**
     * Publish authorization audit event asynchronously.
     */
    private void publishAuditEvent(
            ServerWebExchange exchange,
            Authentication auth,
            String normalizedPath,
            AuthorizationResult result,
            Set<String> userPermissions,
            Set<String> userRoles,
            String conditionExpr,
            Boolean conditionResult) {

        if (auditPublisher == null || !auditPublisher.isEnabled()) {
            return;
        }

        try {
            ServerHttpRequest request = exchange.getRequest();

            String requestId = request.getHeaders().getFirst(SecurityConstants.HEADER_REQUEST_ID);
            String correlationId = request.getHeaders().getFirst(SecurityConstants.HEADER_CORRELATION_ID);
            String userId = auth != null ? (String) auth.getPrincipal() : null;
            String email = null;

            if (auth != null) {
                Map<String, Object> details = extractAuthDetails(auth);
                email = (String) details.getOrDefault("email", null);
            }

            String clientIp = extractClientIp(request);
            String userAgent = request.getHeaders().getFirst("User-Agent");

            AuthorizationAuditEvent event = AuthorizationAuditEvent.from(
                    requestId,
                    correlationId,
                    userId,
                    email,
                    request.getMethod().name(),
                    request.getPath().value(),
                    normalizedPath,
                    result,
                    userPermissions,
                    userRoles,
                    conditionExpr,
                    conditionResult,
                    clientIp,
                    userAgent
            );

            auditPublisher.publishAsync(event);

        } catch (Exception e) {
            log.warn("Failed to publish audit event: {}", e.getMessage());
        }
    }

    private String extractClientIp(ServerHttpRequest request) {
        // Check forwarded headers first
        String forwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            // Take first IP if multiple
            return forwardedFor.split(",")[0].trim();
        }

        String realIp = request.getHeaders().getFirst("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp;
        }

        // Fallback to remote address
        InetSocketAddress remoteAddress = request.getRemoteAddress();
        if (remoteAddress != null && remoteAddress.getAddress() != null) {
            return remoteAddress.getAddress().getHostAddress();
        }

        return "unknown";
    }

    private boolean isPublicPath(String path) {
        return gatewayConfig.getPublicPaths().stream()
                .anyMatch(pattern -> matchesPublicPath(pattern, path));
    }

    private boolean matchesPublicPath(String pattern, String path) {
        if (pattern.endsWith("/**")) {
            String prefix = pattern.substring(0, pattern.length() - 3);
            return path.startsWith(prefix);
        } else if (pattern.endsWith("/*")) {
            String prefix = pattern.substring(0, pattern.length() - 2);
            return path.startsWith(prefix) && !path.substring(prefix.length()).contains("/");
        }
        return pattern.equals(path);
    }

    private ServerWebExchange enrichRequest(ServerWebExchange exchange, AuthorizationResult result) {
        // Add authorization metadata to headers for downstream services
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-Authorization-Rule", result.getMatchedRule() != null ? result.getMatchedRule() : "none")
                .build();

        return exchange.mutate().request(mutatedRequest).build();
    }

    private Mono<Void> respondForbidden(ServerWebExchange exchange, AuthorizationResult result) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().add(
                SecurityConstants.HEADER_FORBIDDEN_REASON,
                result.getReason() != null ? result.getReason() : "Access denied"
        );
        return exchange.getResponse().setComplete();
    }

    private Mono<Void> respondServiceUnavailable(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
        exchange.getResponse().getHeaders().add("Retry-After", "30");
        return exchange.getResponse().setComplete();
    }

    private Mono<Void> respondBadRequest(ServerWebExchange exchange, String reason) {
        exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
        exchange.getResponse().getHeaders().add(SecurityConstants.HEADER_FORBIDDEN_REASON, reason);
        return exchange.getResponse().setComplete();
    }
}
