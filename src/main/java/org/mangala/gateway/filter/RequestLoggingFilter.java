package org.mangala.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@Component
public class RequestLoggingFilter implements GlobalFilter, Ordered {

    private static final String REQUEST_ID_HEADER = "X-Request-Id";
    private static final String CORRELATION_ID_HEADER = "X-Correlation-Id";
    private static final String START_TIME_ATTR = "startTime";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // Generate or use existing request ID
        String requestId = request.getHeaders().getFirst(REQUEST_ID_HEADER);
        if (requestId == null || requestId.isEmpty()) {
            requestId = UUID.randomUUID().toString();
        }

        // Generate or use existing correlation ID
        String correlationId = request.getHeaders().getFirst(CORRELATION_ID_HEADER);
        if (correlationId == null || correlationId.isEmpty()) {
            correlationId = UUID.randomUUID().toString();
        }

        final String finalRequestId = requestId;
        final String finalCorrelationId = correlationId;

        // Add headers to request for downstream services
        ServerHttpRequest mutatedRequest = request.mutate()
                .header(REQUEST_ID_HEADER, requestId)
                .header(CORRELATION_ID_HEADER, correlationId)
                .build();

        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(mutatedRequest)
                .build();

        // Store start time for response time calculation
        mutatedExchange.getAttributes().put(START_TIME_ATTR, System.currentTimeMillis());

        log.info("[{}] Incoming request: {} {} from {}",
                finalRequestId,
                request.getMethod(),
                request.getPath(),
                request.getRemoteAddress());

        return chain.filter(mutatedExchange)
                .then(Mono.fromRunnable(() -> {
                    Long startTime = mutatedExchange.getAttribute(START_TIME_ATTR);
                    ServerHttpResponse response = mutatedExchange.getResponse();

                    // Add tracing headers to response
                    response.getHeaders().add(REQUEST_ID_HEADER, finalRequestId);
                    response.getHeaders().add(CORRELATION_ID_HEADER, finalCorrelationId);

                    long duration = startTime != null ? System.currentTimeMillis() - startTime : 0;

                    log.info("[{}] Response: {} {} - Status: {} - Duration: {}ms",
                            finalRequestId,
                            request.getMethod(),
                            request.getPath(),
                            response.getStatusCode(),
                            duration);
                }));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
