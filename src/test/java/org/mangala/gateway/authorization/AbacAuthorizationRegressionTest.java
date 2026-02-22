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
import org.springframework.http.server.reactive.ServerHttpRequest;
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

class AbacAuthorizationRegressionTest {

    private PolicyConfigProperties policyConfig;
    private StubPolicyCache policyCache;
    private AbacAuthorizationFilter filter;

    @BeforeEach
    void setUp() {
        policyConfig = new PolicyConfigProperties();
        policyConfig.setNoMatchBehavior(PolicyConfigProperties.NoMatchBehavior.DENY);

        GatewayConfigProperties gatewayConfig = new GatewayConfigProperties();
        gatewayConfig.setPublicPaths(List.of("/api/v1/authenticate/**", "/api/v1/register/**", "/api/v1/auth/refresh"));

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

    @Test
    void shouldReturn403WhenPermissionIsMissing() {
        policyCache.rule = Optional.of(PolicyRule.builder()
                .httpMethod("GET")
                .pathPattern("/api/v1/wallets/**")
                .requiredPermissions(Set.of("wallet:read"))
                .build());

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/wallets/1").build()
        );
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        WebFilterChain chain = e -> {
            chainCalled.set(true);
            return e.getResponse().setComplete();
        };

        filter.filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authWithPermissions(Set.of("portfolio:read"))))
                .block();

        assertThat(chainCalled).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getFirst(SecurityConstants.HEADER_FORBIDDEN_REASON))
                .isEqualTo("Insufficient permissions");
    }

    @Test
    void shouldReturn403WhenAbacConditionFails() {
        policyCache.rule = Optional.of(PolicyRule.builder()
                .httpMethod("GET")
                .pathPattern("/api/v1/wallets/**")
                .requiredPermissions(Set.of("wallet:read"))
                .conditionExpr("user.id == path.ownerId")
                .build());

        filter = new AbacAuthorizationFilter(
                policyCache,
                policyConfig,
                baseGatewayConfig(),
                new FixedSpelEvaluator(false),
                null
        );

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/wallets/1").build()
        );

        filter.filter(exchange, e -> e.getResponse().setComplete())
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authWithPermissions(Set.of("wallet:read"))))
                .block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getFirst(SecurityConstants.HEADER_FORBIDDEN_REASON))
                .isEqualTo("Access condition not met");
    }

    @Test
    void shouldReturn403WhenNoPolicyAndDenyMode() {
        policyCache.rule = Optional.empty();
        policyConfig.setNoMatchBehavior(PolicyConfigProperties.NoMatchBehavior.DENY);

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/unknown/resource").build()
        );

        filter.filter(exchange, e -> e.getResponse().setComplete())
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authWithPermissions(Set.of("wallet:read"))))
                .block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getFirst(SecurityConstants.HEADER_FORBIDDEN_REASON))
                .contains("No policy rule found");
    }

    @Test
    void shouldPassThroughWhenNoPolicyAndAllowMode() {
        policyCache.rule = Optional.empty();
        policyConfig.setNoMatchBehavior(PolicyConfigProperties.NoMatchBehavior.ALLOW);

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/unknown/resource").build()
        );

        AtomicBoolean chainCalled = new AtomicBoolean(false);
        AtomicReference<String> authorizationRule = new AtomicReference<>();
        WebFilterChain chain = e -> {
            chainCalled.set(true);
            authorizationRule.set(e.getRequest().getHeaders().getFirst("X-Authorization-Rule"));
            return e.getResponse().setComplete();
        };

        filter.filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authWithPermissions(Set.of("wallet:read"))))
                .block();

        assertThat(chainCalled).isTrue();
        assertThat(authorizationRule.get()).isEqualTo("no-policy-allow");
    }

    @Test
    void shouldReturn403WhenUnauthenticatedAndNoPolicyInDenyMode() {
        policyCache.rule = Optional.empty();
        policyConfig.setNoMatchBehavior(PolicyConfigProperties.NoMatchBehavior.DENY);

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/unknown/resource").build()
        );

        filter.filter(exchange, e -> e.getResponse().setComplete()).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getFirst(SecurityConstants.HEADER_FORBIDDEN_REASON))
                .contains("No policy rule found");
    }

    @Test
    void shouldPassThroughWhenUnauthenticatedAndNoPolicyInAllowMode() {
        policyCache.rule = Optional.empty();
        policyConfig.setNoMatchBehavior(PolicyConfigProperties.NoMatchBehavior.ALLOW);

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/unknown/resource").build()
        );

        AtomicBoolean chainCalled = new AtomicBoolean(false);
        AtomicReference<String> authorizationRule = new AtomicReference<>();
        WebFilterChain chain = e -> {
            chainCalled.set(true);
            authorizationRule.set(e.getRequest().getHeaders().getFirst("X-Authorization-Rule"));
            return e.getResponse().setComplete();
        };

        filter.filter(exchange, chain).block();

        assertThat(chainCalled).isTrue();
        assertThat(authorizationRule.get()).isEqualTo("no-policy-allow");
    }

    private GatewayConfigProperties baseGatewayConfig() {
        GatewayConfigProperties gatewayConfig = new GatewayConfigProperties();
        gatewayConfig.setPublicPaths(List.of("/api/v1/authenticate/**", "/api/v1/register/**", "/api/v1/auth/refresh"));
        return gatewayConfig;
    }

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
