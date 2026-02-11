package org.mangala.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.mangala.gateway.config.GatewayConfigProperties;
import org.mangala.security.SecurityConstants;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter, Ordered {

    private final GatewayConfigProperties gatewayConfigProperties;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    public int getOrder() {
        // Run before AbacAuthorizationFilter
        return Ordered.LOWEST_PRECEDENCE - 20;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();

        // Skip authentication for public paths
        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (!StringUtils.hasText(authHeader) || !authHeader.startsWith(SecurityConstants.BEARER_PREFIX)) {
            return chain.filter(exchange);
        }

        String token = authHeader.substring(SecurityConstants.BEARER_PREFIX.length());

        try {
            Claims claims = validateToken(token);
            String userId = claims.getSubject();
            String email = claims.get(SecurityConstants.CLAIM_EMAIL, String.class);

            @SuppressWarnings("unchecked")
            List<String> roles = claims.get(SecurityConstants.CLAIM_ROLES, List.class);

            @SuppressWarnings("unchecked")
            List<String> permissions = claims.get(SecurityConstants.CLAIM_PERMISSIONS, List.class);

            // Add user info to request headers for downstream services
            ServerHttpRequest.Builder requestBuilder = request.mutate()
                    .header(SecurityConstants.HEADER_USER_ID, userId)
                    .header(SecurityConstants.HEADER_USER_EMAIL, email != null ? email : "")
                    .header(SecurityConstants.HEADER_USER_ROLES, roles != null ? String.join(",", roles) : "");

            // Add permissions header if present
            if (permissions != null && !permissions.isEmpty()) {
                requestBuilder.header(SecurityConstants.HEADER_USER_PERMISSIONS, String.join(",", permissions));
            }

            ServerHttpRequest mutatedRequest = requestBuilder.build();

            ServerWebExchange mutatedExchange = exchange.mutate()
                    .request(mutatedRequest)
                    .build();

            // Create authentication object with both roles and permissions as authorities
            List<GrantedAuthority> authorities = new ArrayList<>();

            // Add roles as authorities
            if (roles != null) {
                roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .forEach(authorities::add);
            }

            // Add permissions as authorities (for AbacAuthorizationFilter)
            if (permissions != null) {
                permissions.stream()
                        .map(SimpleGrantedAuthority::new)
                        .forEach(authorities::add);
            }

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userId, null, authorities);

            // Store permissions in authentication details for AbacAuthorizationFilter
            Map<String, Object> details = new HashMap<>();
            details.put("email", email);
            details.put("roles", roles != null ? new HashSet<>(roles) : Collections.emptySet());
            details.put("permissions", permissions != null ? new HashSet<>(permissions) : Collections.emptySet());
            authentication.setDetails(details);

            return chain.filter(mutatedExchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        } catch (ExpiredJwtException e) {
            log.warn("JWT token expired for path: {}", path);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        } catch (JwtException e) {
            log.warn("Invalid JWT token for path: {}: {}", path, e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    private boolean isPublicPath(String path) {
        return gatewayConfigProperties.getPublicPaths().stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, path));
    }

    private Claims validateToken(String token) {
        SecretKey key = Keys.hmacShaKeyFor(
                gatewayConfigProperties.getJwt().getSecret().getBytes(StandardCharsets.UTF_8)
        );

        return Jwts.parser()
                .verifyWith(key)
                .requireIssuer(gatewayConfigProperties.getJwt().getIssuer())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
