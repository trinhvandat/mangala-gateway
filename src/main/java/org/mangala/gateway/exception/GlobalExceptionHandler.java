package org.mangala.gateway.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeoutException;

@Slf4j
@Order(-2)
@Component
@RequiredArgsConstructor
public class GlobalExceptionHandler implements ErrorWebExceptionHandler {

    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        ServerHttpResponse response = exchange.getResponse();
        if (response.isCommitted()) {
            log.error("Response already committed, cannot render error payload", ex);
            return Mono.error(ex);
        }

        String path = exchange.getRequest().getPath().value();
        String requestId = exchange.getRequest().getHeaders().getFirst("X-Request-Id");

        HttpStatus status;
        String code;
        String message;

        if (ex instanceof ResponseStatusException rse) {
            status = HttpStatus.valueOf(rse.getStatusCode().value());
            code = "GATEWAY_" + status.name();
            message = rse.getReason() != null ? rse.getReason() : status.getReasonPhrase();
        } else if (ex instanceof ConnectException) {
            status = HttpStatus.SERVICE_UNAVAILABLE;
            code = "SERVICE_UNAVAILABLE";
            message = "Downstream service is unavailable";
            log.error("[{}] Service unavailable for path {}: {}", requestId, path, ex.getMessage());
        } else if (ex instanceof TimeoutException) {
            status = HttpStatus.GATEWAY_TIMEOUT;
            code = "GATEWAY_TIMEOUT";
            message = "Request timed out";
            log.error("[{}] Timeout for path {}: {}", requestId, path, ex.getMessage());
        } else if (ex.getCause() instanceof ConnectException) {
            status = HttpStatus.SERVICE_UNAVAILABLE;
            code = "SERVICE_UNAVAILABLE";
            message = "Downstream service is unavailable";
            log.error("[{}] Service unavailable for path {}: {}", requestId, path, ex.getMessage());
        } else {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
            code = "INTERNAL_ERROR";
            message = "An unexpected error occurred";
            log.error("[{}] Unexpected error for path {}: ", requestId, path, ex);
        }

        GatewayErrorResponse errorResponse = GatewayErrorResponse.of(code, message, path, requestId);

        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(errorResponse);
            DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Mono.just(buffer));
        } catch (JsonProcessingException e) {
            log.error("Error serializing error response", e);
            byte[] fallback = "{\"code\":\"INTERNAL_ERROR\",\"message\":\"Error processing request\"}"
                    .getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = response.bufferFactory().wrap(fallback);
            return response.writeWith(Mono.just(buffer));
        }
    }
}
