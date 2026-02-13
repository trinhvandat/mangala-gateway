package org.mangala.gateway.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Configuration
public class RateLimiterConfig {

    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange -> {
            String clientIp = Objects.requireNonNull(exchange.getRequest().getRemoteAddress())
                    .getAddress()
                    .getHostAddress();
            return Mono.just(clientIp);
        };
    }

    @Bean
    public KeyResolver userKeyResolver() {
        return exchange -> {
            String userId = exchange.getRequest().getHeaders().getFirst("X-User-Id");
            if (userId != null && !userId.isEmpty()) {
                return Mono.just(userId);
            }
            String clientIp = Objects.requireNonNull(exchange.getRequest().getRemoteAddress())
                    .getAddress()
                    .getHostAddress();
            return Mono.just(clientIp);
        };
    }

    @Bean
    @Primary
    public KeyResolver compositeKeyResolver() {
        return exchange -> {
            String clientIp = Objects.requireNonNull(exchange.getRequest().getRemoteAddress())
                    .getAddress()
                    .getHostAddress();
            String userId = exchange.getRequest().getHeaders().getFirst("X-User-Id");
            String userPart = (userId != null && !userId.isEmpty()) ? userId : "anonymous";

            // Compose key as "ip:user" with requested order: ip first, user second.
            return Mono.just(clientIp + ":" + userPart);
        };
    }
}
