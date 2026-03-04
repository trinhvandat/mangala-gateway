package org.mangala.gateway.health;

import lombok.extern.slf4j.Slf4j;
import org.mangala.gateway.exception.GatewayErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequestMapping("/fallback")
public class FallbackController {

    @RequestMapping(method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.PATCH})
    public Mono<ResponseEntity<GatewayErrorResponse>> defaultFallback(
            @RequestHeader(value = "X-Request-Id", required = false) String requestId) {
        log.warn("[{}] Circuit breaker fallback triggered", requestId);
        return Mono.just(ResponseEntity
                .status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(GatewayErrorResponse.of(
                        "SERVICE_UNAVAILABLE",
                        "Service is temporarily unavailable. Please try again later.",
                        "/fallback",
                        requestId
                )));
    }

    @RequestMapping(value = "/auth", method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.PATCH})
    public Mono<ResponseEntity<GatewayErrorResponse>> authFallback(
            @RequestHeader(value = "X-Request-Id", required = false) String requestId) {
        log.warn("[{}] Auth service circuit breaker fallback triggered", requestId);
        return Mono.just(ResponseEntity
                .status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(GatewayErrorResponse.of(
                        "AUTH_SERVICE_UNAVAILABLE",
                        "Authentication service is temporarily unavailable. Please try again later.",
                        "/fallback/auth",
                        requestId
                )));
    }

    @RequestMapping(value = "/wallet", method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.PATCH})
    public Mono<ResponseEntity<GatewayErrorResponse>> walletFallback(
            @RequestHeader(value = "X-Request-Id", required = false) String requestId) {
        log.warn("[{}] Wallet service circuit breaker fallback triggered", requestId);
        return Mono.just(ResponseEntity
                .status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(GatewayErrorResponse.of(
                        "WALLET_SERVICE_UNAVAILABLE",
                        "Wallet service is temporarily unavailable. Please try again later.",
                        "/fallback/wallet",
                        requestId
                )));
    }

    @RequestMapping(value = "/portfolio", method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.PATCH})
    public Mono<ResponseEntity<GatewayErrorResponse>> portfolioFallback(
            @RequestHeader(value = "X-Request-Id", required = false) String requestId) {
        log.warn("[{}] Portfolio service circuit breaker fallback triggered", requestId);
        return Mono.just(ResponseEntity
                .status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(GatewayErrorResponse.of(
                        "PORTFOLIO_SERVICE_UNAVAILABLE",
                        "Portfolio service is temporarily unavailable. Please try again later.",
                        "/fallback/portfolio",
                        requestId
                )));
    }

    @RequestMapping(value = "/transaction", method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.PATCH})
    public Mono<ResponseEntity<GatewayErrorResponse>> transactionFallback(
            @RequestHeader(value = "X-Request-Id", required = false) String requestId) {
        log.warn("[{}] Transaction service circuit breaker fallback triggered", requestId);
        return Mono.just(ResponseEntity
                .status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(GatewayErrorResponse.of(
                        "TRANSACTION_SERVICE_UNAVAILABLE",
                        "Transaction service is temporarily unavailable. Please try again later.",
                        "/fallback/transaction",
                        requestId
                )));
    }
}
