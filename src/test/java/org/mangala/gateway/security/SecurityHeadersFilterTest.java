package org.mangala.gateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityHeadersFilterTest {

    @Test
    void shouldAddConfiguredHeadersBeforeCommit() {
        SecurityHeadersProperties properties = new SecurityHeadersProperties();
        properties.setHstsEnabled(true);
        properties.setCsp("default-src 'none'");
        properties.setReferrerPolicy("strict-origin-when-cross-origin");
        properties.setPermissionsPolicy("camera=(), microphone=()");

        SecurityHeadersFilter filter = new SecurityHeadersFilter(properties);
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/wallets").build());

        GatewayFilterChain chain = this::completeResponse;

        filter.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getHeaders().getFirst("Strict-Transport-Security"))
                .isEqualTo("max-age=31536000; includeSubDomains");
        assertThat(exchange.getResponse().getHeaders().getFirst("Content-Security-Policy"))
                .isEqualTo("default-src 'none'");
        assertThat(exchange.getResponse().getHeaders().getFirst("Referrer-Policy"))
                .isEqualTo("strict-origin-when-cross-origin");
        assertThat(exchange.getResponse().getHeaders().getFirst("Permissions-Policy"))
                .isEqualTo("camera=(), microphone=()");
    }

    private Mono<Void> completeResponse(ServerWebExchange exchange) {
        return exchange.getResponse().setComplete();
    }
}
