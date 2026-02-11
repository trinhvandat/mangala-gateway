package org.mangala.gateway.abac;

import lombok.Builder;
import lombok.Getter;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * Immutable context for ABAC condition evaluation.
 * All values are available as SpEL variables.
 */
@Getter
@Builder
public class AbacEvaluationContext {

    // User attributes from JWT
    private final String userId;
    private final String email;
    private final Set<String> roles;
    private final Set<String> permissions;
    private final Map<String, Object> attributes;

    // Request context
    private final Map<String, String> pathVariables;  // pathVar['walletId'], etc.
    private final String httpMethod;
    private final String path;
    private final Map<String, String> queryParams;

    /**
     * Create context with defaults for null values.
     */
    public static AbacEvaluationContext of(
            String userId,
            String email,
            Set<String> roles,
            Set<String> permissions,
            Map<String, Object> attributes,
            Map<String, String> pathVariables,
            String httpMethod,
            String path,
            Map<String, String> queryParams) {

        return AbacEvaluationContext.builder()
                .userId(userId)
                .email(email)
                .roles(roles != null ? roles : Collections.emptySet())
                .permissions(permissions != null ? permissions : Collections.emptySet())
                .attributes(attributes != null ? attributes : Collections.emptyMap())
                .pathVariables(pathVariables != null ? pathVariables : Collections.emptyMap())
                .httpMethod(httpMethod)
                .path(path)
                .queryParams(queryParams != null ? queryParams : Collections.emptyMap())
                .build();
    }
}
