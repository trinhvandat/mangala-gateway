package org.mangala.gateway.abac;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.expression.AccessException;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.MethodExecutor;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.spel.support.ReflectiveMethodResolver;

import java.util.List;
import java.util.Set;

/**
 * A method resolver that only allows whitelisted methods.
 * Prevents calling dangerous methods like getClass(), forName(), exec(), etc.
 */
public class RestrictedMethodResolver implements MethodResolver {

    private final Set<String> allowedMethods;
    private final ReflectiveMethodResolver delegate = new ReflectiveMethodResolver();

    public RestrictedMethodResolver(Set<String> allowedMethods) {
        this.allowedMethods = allowedMethods;
    }

    @Override
    public MethodExecutor resolve(EvaluationContext context, Object targetObject,
                                  String name, List<TypeDescriptor> argumentTypes) throws AccessException {

        // Check if method is in whitelist
        if (!allowedMethods.contains(name)) {
            throw new AccessException(
                    String.format("Method '%s' is not allowed in ABAC expressions. Allowed: %s",
                            name, allowedMethods));
        }

        // Delegate to default resolver for allowed methods
        return delegate.resolve(context, targetObject, name, argumentTypes);
    }
}
