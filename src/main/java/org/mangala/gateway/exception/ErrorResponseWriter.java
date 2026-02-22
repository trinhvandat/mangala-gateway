package org.mangala.gateway.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

public final class ErrorResponseWriter {

    private ErrorResponseWriter() {
    }

    public static Mono<Void> writeJson(
            ServerWebExchange exchange,
            HttpStatus status,
            String code,
            String message,
            ObjectMapper objectMapper) {

        ServerHttpResponse response = exchange.getResponse();
        String path = exchange.getRequest().getPath().value();
        String requestId = exchange.getRequest().getHeaders().getFirst("X-Request-Id");

        GatewayErrorResponse payload = GatewayErrorResponse.of(code, message, path, requestId);

        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(payload);
            DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Mono.just(buffer));
        } catch (JsonProcessingException e) {
            byte[] fallback = "{\"code\":\"INTERNAL_ERROR\",\"message\":\"Error processing request\"}"
                    .getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = response.bufferFactory().wrap(fallback);
            return response.writeWith(Mono.just(buffer));
        }
    }
}
