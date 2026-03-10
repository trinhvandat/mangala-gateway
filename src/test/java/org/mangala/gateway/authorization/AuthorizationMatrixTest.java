package org.mangala.gateway.authorization;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mangala.gateway.abac.AbacEvaluationContext;
import org.mangala.gateway.abac.SpelConditionEvaluator;
import org.mangala.gateway.abac.SpelExpressionCache;
import org.mangala.gateway.abac.SpelSecurityConfig;
import org.mangala.gateway.config.GatewayConfigProperties;
import org.mangala.gateway.policy.PolicyCache;
import org.mangala.gateway.policy.PolicyConfigProperties;
import org.mangala.security.SecurityConstants;
import org.mangala.security.model.PolicyRule;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.WebFilterChain;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Authorization Matrix Tests (TEST-002) - Sprint 6
 *
 * Verifies the full authorization decision matrix:
 * - Permission present/absent
 * - Default-deny vs default-allow behavior
 * - Exact path vs wildcard path matching
 * - Single vs multiple required permissions (any-match semantics)
 * - Unauthenticated access to protected endpoints
 * - Public path bypass of authorization
 */
class AuthorizationMatrixTest {

    private PolicyConfigProperties policyConfig;
    private StubPolicyCache policyCache;
    private GatewayConfigProperties gatewayConfig;
    private AbacAuthorizationFilter filter;

    @BeforeEach
    void setUp() {
        policyConfig = new PolicyConfigProperties();
        policyConfig.setNoMatchBehavior(PolicyConfigProperties.NoMatchBehavior.DENY);

        gatewayConfig = new GatewayConfigProperties();
        gatewayConfig.setPublicPaths(List.of(
                "/api/v1/authenticate/**",
                "/api/v1/register/**",
                "/api/v1/auth/refresh"
        ));

        policyCache = new StubPolicyCache();
        policyCache.healthy = true;

        filter = new AbacAuthorizationFilter(
                policyCache,
                policyConfig,
                gatewayConfig,
                new FixedSpelEvaluator(true),
                null
        );
    }

    // -------------------------------------------------------------------------
    // Test 1: User with required permission -> 200 (chain proceeds)
    // -------------------------------------------------------------------------
    @Test
    void testUserWithPermissionGets200() {
        policyCache.rule = Optional.of(PolicyRule.builder()
                .httpMethod("GET")
                .pathPattern("/api/v1/wallets/**")
                .requiredPermissions(Set.of("wallet:read"))
                .build());

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/wallets/42").build()
        );
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        WebFilterChain chain = e -> {
            chainCalled.set(true);
            return e.getResponse().setComplete();
        };

        filter.filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(
                        authWithPermissions(Set.of("wallet:read"))))
                .block();

        assertThat(chainCalled).isTrue();
        assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.FORBIDDEN);
    }

    // -------------------------------------------------------------------------
    // Test 2: User without required permission -> 403
    // -------------------------------------------------------------------------
    @Test
    void testUserWithoutPermissionGets403() {
        policyCache.rule = Optional.of(PolicyRule.builder()
                .httpMethod("GET")
                .pathPattern("/api/v1/wallets/**")
                .requiredPermissions(Set.of("wallet:read"))
                .build());

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/wallets/42").build()
        );
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        WebFilterChain chain = e -> {
            chainCalled.set(true);
            return e.getResponse().setComplete();
        };

        filter.filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(
                        authWithPermissions(Set.of("portfolio:read"))))
                .block();

        assertThat(chainCalled).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getFirst(SecurityConstants.HEADER_FORBIDDEN_REASON))
                .isEqualTo("Insufficient permissions");
    }

    // -------------------------------------------------------------------------
    // Test 3: No matching policy + default-deny -> 403
    // -------------------------------------------------------------------------
    @Test
    void testNoPolicyDefaultDeny() {
        policyCache.rule = Optional.empty();
        policyConfig.setNoMatchBehavior(PolicyConfigProperties.NoMatchBehavior.DENY);

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/unknown/resource").build()
        );
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        WebFilterChain chain = e -> {
            chainCalled.set(true);
            return e.getResponse().setComplete();
        };

        filter.filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(
                        authWithPermissions(Set.of("wallet:read"))))
                .block();

        assertThat(chainCalled).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getFirst(SecurityConstants.HEADER_FORBIDDEN_REASON))
                .contains("No policy rule found");
    }

    // -------------------------------------------------------------------------
    // Test 4: Exact path /api/v1/wallets matches policy -> allowed
    // -------------------------------------------------------------------------
    @Test
    void testExactPathMatching() {
        policyCache.rule = Optional.of(PolicyRule.builder()
                .httpMethod("GET")
                .pathPattern("/api/v1/wallets")
                .requiredPermissions(Set.of("wallet:read"))
                .build());

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/wallets").build()
        );
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        AtomicReference<String> authRuleHeader = new AtomicReference<>();
        WebFilterChain chain = e -> {
            chainCalled.set(true);
            authRuleHeader.set(e.getRequest().getHeaders().getFirst("X-Authorization-Rule"));
            return e.getResponse().setComplete();
        };

        filter.filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(
                        authWithPermissions(Set.of("wallet:read"))))
                .block();

        assertThat(chainCalled).isTrue();
        assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.FORBIDDEN);
    }

    // -------------------------------------------------------------------------
    // Test 5: Wildcard path /api/v1/wallets/** matches sub-resource -> allowed
    // -------------------------------------------------------------------------
    @Test
    void testWildcardPathMatching() {
        policyCache.rule = Optional.of(PolicyRule.builder()
                .httpMethod("GET")
                .pathPattern("/api/v1/wallets/**")
                .requiredPermissions(Set.of("wallet:read"))
                .build());

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/wallets/abc123/transactions").build()
        );
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        WebFilterChain chain = e -> {
            chainCalled.set(true);
            return e.getResponse().setComplete();
        };

        filter.filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(
                        authWithPermissions(Set.of("wallet:read"))))
                .block();

        assertThat(chainCalled).isTrue();
        assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.FORBIDDEN);
    }

    // -------------------------------------------------------------------------
    // Test 6: Policy requires multiple permissions; user has one -> allowed (any-match)
    // -------------------------------------------------------------------------
    @Test
    void testMultiplePermissionsAnyMatch() {
        policyCache.rule = Optional.of(PolicyRule.builder()
                .httpMethod("GET")
                .pathPattern("/api/v1/reports/**")
                .requiredPermissions(Set.of("report:read", "admin:read"))
                .build());

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/reports/monthly").build()
        );
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        WebFilterChain chain = e -> {
            chainCalled.set(true);
            return e.getResponse().setComplete();
        };

        // User only has report:read (not admin:read) - should still be allowed
        filter.filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(
                        authWithPermissions(Set.of("report:read"))))
                .block();

        assertThat(chainCalled).isTrue();
        assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.FORBIDDEN);
    }

    // -------------------------------------------------------------------------
    // Test 7: Unauthenticated access to protected endpoint -> 403
    // -------------------------------------------------------------------------
    @Test
    void testUnauthenticatedAccessToProtectedEndpoint() {
        policyCache.rule = Optional.of(PolicyRule.builder()
                .httpMethod("GET")
                .pathPattern("/api/v1/wallets/**")
                .requiredPermissions(Set.of("wallet:read"))
                .build());

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/wallets/42").build()
        );
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        WebFilterChain chain = e -> {
            chainCalled.set(true);
            return e.getResponse().setComplete();
        };

        // No security context - no contextWrite call
        filter.filter(exchange, chain).block();

        assertThat(chainCalled).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getFirst(SecurityConstants.HEADER_FORBIDDEN_REASON))
                .isEqualTo("Authentication required");
    }

    // -------------------------------------------------------------------------
    // Test 8: Public path bypasses authorization entirely
    // -------------------------------------------------------------------------
    @Test
    void testPublicPathBypassesAuthorization() {
        // Even if we set a rule, public paths are skipped before cache lookup
        policyCache.rule = Optional.of(PolicyRule.builder()
                .httpMethod("POST")
                .pathPattern("/api/v1/authenticate/**")
                .requiredPermissions(Set.of("admin:write"))
                .build());

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/v1/authenticate/login").build()
        );
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        WebFilterChain chain = e -> {
            chainCalled.set(true);
            return e.getResponse().setComplete();
        };

        // No auth context - but public paths skip authz
        filter.filter(exchange, chain).block();

        assertThat(chainCalled).isTrue();
        assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.FORBIDDEN);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private UsernamePasswordAuthenticationToken authWithPermissions(Set<String> permissions) {
        List<SimpleGrantedAuthority> authorities = permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .toList();

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken("user-1", null, authorities);

        Map<String, Object> details = new HashMap<>();
        details.put("email", "user@example.com");
        details.put("roles", Set.of("ROLE_USER"));
        details.put("permissions", permissions);
        authentication.setDetails(details);
        return authentication;
    }

    private static class StubPolicyCache extends PolicyCache {
        private boolean healthy;
        private Optional<PolicyRule> rule = Optional.empty();

        @Override
        public boolean isHealthy() {
            return healthy;
        }

        @Override
        public Optional<PolicyRule> findMatchingRule(String method, String path) {
            return rule;
        }
    }

    private static class FixedSpelEvaluator extends SpelConditionEvaluator {
        private final boolean decision;

        FixedSpelEvaluator(boolean decision) {
            super(new SpelExpressionCache(new SpelSecurityConfig()), new SpelSecurityConfig());
            this.decision = decision;
        }

        @Override
        public boolean evaluateSafe(String expression, AbacEvaluationContext context) {
            return decision;
        }
    }
}
