package org.mangala.gateway.audit;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.mangala.security.model.AuthorizationResult;

import java.time.Instant;
import java.util.Set;

/**
 * Audit event for authorization decisions.
 * Published to Kafka for security auditing and compliance.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizationAuditEvent {

    /**
     * Unique request identifier for correlation.
     */
    private String requestId;

    /**
     * Correlation ID for distributed tracing.
     */
    private String correlationId;

    /**
     * User ID from JWT subject.
     */
    private String userId;

    /**
     * User email.
     */
    private String email;

    /**
     * HTTP method (GET, POST, etc.)
     */
    private String httpMethod;

    /**
     * Original request path.
     */
    private String path;

    /**
     * Normalized path (lowercase, decoded).
     */
    private String normalizedPath;

    /**
     * Authorization decision: ALLOW, DENY, or NO_POLICY.
     */
    private AuthorizationResult.Decision decision;

    /**
     * Reason for denial (if denied).
     */
    private String reason;

    /**
     * Permissions required by the policy rule.
     */
    private Set<String> requiredPermissions;

    /**
     * Permissions the user has.
     */
    private Set<String> userPermissions;

    /**
     * User roles.
     */
    private Set<String> userRoles;

    /**
     * Matched policy rule identifier.
     */
    private String matchedRule;

    /**
     * ABAC condition expression (if any).
     */
    private String conditionExpr;

    /**
     * Result of ABAC condition evaluation.
     */
    private Boolean conditionResult;

    /**
     * Time taken to evaluate authorization (ms).
     */
    private long evaluationTimeMs;

    /**
     * Event timestamp.
     */
    private Instant timestamp;

    /**
     * Client IP address.
     */
    private String clientIp;

    /**
     * User-Agent header.
     */
    private String userAgent;

    /**
     * Service name (gateway).
     */
    private String serviceName;

    /**
     * Create event from authorization result and request context.
     */
    public static AuthorizationAuditEvent from(
            String requestId,
            String correlationId,
            String userId,
            String email,
            String httpMethod,
            String path,
            String normalizedPath,
            AuthorizationResult result,
            Set<String> userPermissions,
            Set<String> userRoles,
            String conditionExpr,
            Boolean conditionResult,
            String clientIp,
            String userAgent) {

        return AuthorizationAuditEvent.builder()
                .requestId(requestId)
                .correlationId(correlationId)
                .userId(userId)
                .email(email)
                .httpMethod(httpMethod)
                .path(path)
                .normalizedPath(normalizedPath)
                .decision(result.getDecision())
                .reason(result.getReason())
                .requiredPermissions(result.getRequiredPermissions())
                .userPermissions(userPermissions)
                .userRoles(userRoles)
                .matchedRule(result.getMatchedRule())
                .conditionExpr(conditionExpr)
                .conditionResult(conditionResult)
                .evaluationTimeMs(result.getEvaluationTimeMs())
                .timestamp(Instant.now())
                .clientIp(clientIp)
                .userAgent(userAgent)
                .serviceName("mangala-gateway")
                .build();
    }
}
