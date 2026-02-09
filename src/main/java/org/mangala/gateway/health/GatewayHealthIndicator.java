package org.mangala.gateway.health;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.ReactiveHealthIndicator;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class GatewayHealthIndicator implements ReactiveHealthIndicator {

    private final RouteLocator routeLocator;

    @Override
    public Mono<Health> health() {
        return routeLocator.getRoutes()
                .count()
                .map(count -> Health.up()
                        .withDetail("routes", count)
                        .withDetail("status", "Gateway is operational")
                        .build())
                .onErrorResume(ex -> Mono.just(Health.down()
                        .withDetail("error", ex.getMessage())
                        .build()));
    }
}
