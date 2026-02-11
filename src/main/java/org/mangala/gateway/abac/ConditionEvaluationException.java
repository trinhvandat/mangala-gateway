package org.mangala.gateway.abac;

/**
 * Exception thrown when ABAC condition evaluation fails.
 */
public class ConditionEvaluationException extends RuntimeException {

    public ConditionEvaluationException(String message) {
        super(message);
    }

    public ConditionEvaluationException(String message, Throwable cause) {
        super(message, cause);
    }
}
