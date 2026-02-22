package org.mangala.gateway.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(SecurityHeadersProperties.class)
@ConditionalOnProperty(prefix = "gateway.security.headers", name = "enabled", havingValue = "true")
public class SecurityHeadersAutoConfiguration {

    @Bean
    public SecurityHeadersFilter securityHeadersFilter(SecurityHeadersProperties properties) {
        return new SecurityHeadersFilter(properties);
    }
}
