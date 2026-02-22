package org.mangala.gateway.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "gateway.security.headers")
public class SecurityHeadersProperties {

    /**
     * Master switch for security headers baseline.
     */
    private boolean enabled = false;

    /**
     * Add Strict-Transport-Security when true.
     */
    private boolean hstsEnabled = false;

    /**
     * Value for Content-Security-Policy header.
     */
    private String csp = "";

    /**
     * Value for Referrer-Policy header.
     */
    private String referrerPolicy = "";

    /**
     * Value for Permissions-Policy header.
     */
    private String permissionsPolicy = "";
}
