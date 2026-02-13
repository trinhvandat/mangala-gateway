package org.mangala.gateway.abac;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Security configuration for SpEL expression evaluation.
 * Controls what expressions are allowed and their execution limits.
 */
@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "gateway.abac.spel")
public class SpelSecurityConfig {

    /**
     * Enable/disable ABAC condition evaluation.
     * When disabled, all conditions return true (pass).
     */
    private boolean enabled = true;

    /**
     * Maximum allowed expression length.
     */
    private int maxExpressionLength = 500;

    /**
     * Expression evaluation timeout in milliseconds.
     */
    private long evaluationTimeoutMs = 100;

    /**
     * Maximum cache size for compiled expressions.
     */
    private int maxCacheSize = 1000;

    /**
     * Allowed top-level variable names accessible in expressions.
     */
    private Set<String> allowedVariables = Set.of(
            "userId",
            "email",
            "roles",
            "permissions",
            "attributes",
            "pathVar",
            "httpMethod",
            "path",
            "queryParams"
    );

    /**
     * Allowed method calls on objects.
     * Restrict to safe methods only.
     */
    private Set<String> allowedMethods = Set.of(
            "contains",
            "containsKey",
            "containsValue",
            "equals",
            "equalsIgnoreCase",
            "isEmpty",
            "size",
            "get",
            "startsWith",
            "endsWith",
            "toLowerCase",
            "toUpperCase",
            "matches",
            "toString",
            "length"
    );

    /**
     * Blocked patterns in expressions (regex).
     * These patterns indicate potential security risks.
     */
    private Set<String> blockedPatterns = Set.of(
            "T\\s*\\(",           // Type references T(...)
            "new\\s+",            // Object instantiation
            "getClass",           // Reflection
            "forName",            // Class loading
            "invoke",             // Method invocation via reflection
            "Runtime",            // Runtime access
            "ProcessBuilder",     // Process execution
            "System\\.",          // System access
            "exec",               // Execution
            "\\$\\{",             // Property placeholder
            "#\\{",               // SpEL in SpEL
            "java\\.lang",        // Java lang classes
            "java\\.io",          // Java IO classes
            "java\\.net",         // Java net classes
            "java\\.util\\.concurrent", // Concurrent utilities
            "Thread",             // Thread manipulation
            "Class\\.",           // Class methods
            "ClassLoader"         // ClassLoader access
    );
}
