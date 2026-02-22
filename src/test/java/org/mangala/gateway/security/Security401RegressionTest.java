package org.mangala.gateway.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mangala.gateway.config.GatewayConfigProperties;
import org.mangala.gateway.config.SecurityConfig;
import org.mangala.gateway.filter.JwtAuthenticationFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.web.server.WebFilterChain;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

class Security401RegressionTest {

    private static final String TEST_SECRET = "test-secret-key-for-regression-suite-32-bytes!";
    private static final String TEST_ISSUER = "mangala";

    private WebFilterChainProxy securityProxy;

    @BeforeEach
    void setUp() {
        GatewayConfigProperties properties = new GatewayConfigProperties();
        properties.getJwt().setSecret(TEST_SECRET);
        properties.getJwt().setIssuer(TEST_ISSUER);
        properties.setPublicPaths(List.of(
                "/api/v1/register/**",
                "/api/v1/authenticate/**",
                "/api/v1/auth/refresh",
                "/actuator/health",
                "/actuator/info",
                "/fallback/**",
                "/internal/**"
        ));

        ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(properties, objectMapper);
        SecurityConfig securityConfig = new SecurityConfig(jwtAuthenticationFilter, properties, objectMapper);
        this.securityProxy = new WebFilterChainProxy(
                List.of(securityConfig.securityWebFilterChain(ServerHttpSecurity.http()))
        );
    }

    @Test
    void protectedEndpointShouldReturn401WhenTokenMissing() {
        ExecutionResult result = execute("/api/v1/wallets/test", null);
        assertThat(result.status()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(result.body()).contains("\"code\":\"GATEWAY_UNAUTHORIZED\"");
        assertThat(result.body()).contains("\"message\":\"Authentication required\"");
    }

    @Test
    void protectedEndpointShouldReturn401WhenTokenMalformed() {
        ExecutionResult result = execute("/api/v1/wallets/test", "Bearer not-a-valid-jwt");
        assertThat(result.status()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(result.body()).contains("\"code\":\"GATEWAY_UNAUTHORIZED\"");
        assertThat(result.body()).contains("\"message\":\"Invalid JWT token\"");
    }

    @Test
    void protectedEndpointShouldReturn401WhenTokenExpired() {
        String expiredToken = buildToken(Date.from(Instant.now().minusSeconds(60)));
        ExecutionResult result = execute("/api/v1/wallets/test", "Bearer " + expiredToken);
        assertThat(result.status()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(result.body()).contains("\"code\":\"GATEWAY_UNAUTHORIZED\"");
        assertThat(result.body()).contains("\"message\":\"JWT token expired\"");
    }

    @Test
    void publicAuthenticateEndpointShouldPassWithoutToken() {
        ExecutionResult result = execute("/api/v1/authenticate/ping", null);
        assertThat(result.terminalChainCalled()).isTrue();
        assertThat(result.status()).isNotEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(result.status()).isNotEqualTo(HttpStatus.FORBIDDEN.value());
    }

    private ExecutionResult execute(String path, String authorizationHeader) {
        MockServerHttpRequest.BaseBuilder<?> requestBuilder = MockServerHttpRequest.get(path);
        if (authorizationHeader != null) {
            requestBuilder.header(HttpHeaders.AUTHORIZATION, authorizationHeader);
        }

        MockServerWebExchange exchange = MockServerWebExchange.from(requestBuilder.build());
        AtomicBoolean terminalCalled = new AtomicBoolean(false);

        WebFilterChain terminalChain = ex -> {
            terminalCalled.set(true);
            return ex.getResponse().setComplete();
        };

        securityProxy.filter(exchange, terminalChain).block();
        int status = exchange.getResponse().getStatusCode() != null
                ? exchange.getResponse().getStatusCode().value()
                : 200;
        String body = exchange.getResponse().getBodyAsString().blockOptional().orElse("");
        return new ExecutionResult(status, terminalCalled.get(), body);
    }

    private String buildToken(Date expiration) {
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
                .subject("user-1")
                .issuer(TEST_ISSUER)
                .expiration(expiration)
                .claim("email", "user@example.com")
                .signWith(key)
                .compact();
    }

    private record ExecutionResult(int status, boolean terminalChainCalled, String body) {
    }
}
