package org.mangala.gateway.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@ConfigurationProperties(prefix = "gateway")
public class GatewayConfigProperties {

    private JwtConfig jwt = new JwtConfig();
    private RateLimitConfig rateLimit = new RateLimitConfig();
    private CorsConfig cors = new CorsConfig();
    private List<String> publicPaths = new ArrayList<>();

    @Getter
    @Setter
    public static class JwtConfig {
        private String secret;
        private String issuer = "mangala";
        private long accessTokenExpiration = 900000; // 15 minutes
        private long refreshTokenExpiration = 604800000; // 7 days
    }

    @Getter
    @Setter
    public static class RateLimitConfig {
        private boolean enabled = true;
        private int defaultReplenishRate = 10;
        private int defaultBurstCapacity = 20;
        private int requestedTokens = 1;
    }

    @Getter
    @Setter
    public static class CorsConfig {
        private List<String> allowedOrigins = new ArrayList<>();
        private List<String> allowedMethods = List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH");
        private List<String> allowedHeaders = List.of("*");
        private List<String> exposedHeaders = List.of("X-Request-Id", "X-Correlation-Id");
        private boolean allowCredentials = true;
        private long maxAge = 3600;
    }
}
