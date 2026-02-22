package org.mangala.gateway.security;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class SecurityHeadersFilter implements GlobalFilter, Ordered {

    private static final String STRICT_TRANSPORT_SECURITY = "Strict-Transport-Security";
    private static final String CONTENT_SECURITY_POLICY = "Content-Security-Policy";
    private static final String REFERRER_POLICY = "Referrer-Policy";
    private static final String PERMISSIONS_POLICY = "Permissions-Policy";

    private static final String HSTS_VALUE = "max-age=31536000; includeSubDomains";

    private final SecurityHeadersProperties properties;

    public SecurityHeadersFilter(SecurityHeadersProperties properties) {
        this.properties = properties;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        exchange.getResponse().beforeCommit(() -> {
            HttpHeaders headers = exchange.getResponse().getHeaders();

            if (properties.isHstsEnabled()) {
                setIfMissing(headers, STRICT_TRANSPORT_SECURITY, HSTS_VALUE);
            }

            if (StringUtils.hasText(properties.getCsp())) {
                setIfMissing(headers, CONTENT_SECURITY_POLICY, properties.getCsp());
            }

            if (StringUtils.hasText(properties.getReferrerPolicy())) {
                setIfMissing(headers, REFERRER_POLICY, properties.getReferrerPolicy());
            }

            if (StringUtils.hasText(properties.getPermissionsPolicy())) {
                setIfMissing(headers, PERMISSIONS_POLICY, properties.getPermissionsPolicy());
            }

            return Mono.empty();
        });

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }

    private void setIfMissing(HttpHeaders headers, String name, String value) {
        if (!headers.containsKey(name)) {
            headers.set(name, value);
        }
    }
}
