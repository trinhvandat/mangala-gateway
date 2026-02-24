package org.mangala.gateway.policy;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@RequiredArgsConstructor
public class PolicyApiSecurityProfileGuard implements ApplicationRunner {

    private final PolicyConfigProperties policyConfig;
    private final Environment environment;

    @Override
    public void run(ApplicationArguments args) {
        if (!isNonDevProfileActive()) {
            return;
        }

        if (!policyConfig.getProfileGuard().isEnforceMtlsInNonDev()) {
            log.warn("Policy API non-dev mTLS enforcement is disabled by configuration");
            return;
        }

        if (!policyConfig.getMtls().isEnabled()) {
            throw new IllegalStateException(
                    "Policy API mTLS must be enabled in non-dev profiles (gateway.policy.mtls.enabled=true)");
        }

        validateMtlsMaterial(policyConfig.getMtls());
    }

    private boolean isNonDevProfileActive() {
        Set<String> activeProfiles = Arrays.stream(environment.getActiveProfiles())
                .collect(Collectors.toSet());
        if (activeProfiles.isEmpty()) {
            return false;
        }

        Set<String> devProfiles = policyConfig.getProfileGuard().getDevProfiles().stream()
                .map(String::trim)
                .collect(Collectors.toSet());

        return activeProfiles.stream().anyMatch(profile -> !devProfiles.contains(profile));
    }

    private void validateMtlsMaterial(PolicyConfigProperties.MtlsConfig mtls) {
        if (!StringUtils.hasText(mtls.getKeyStorePath())) {
            throw new IllegalStateException("gateway.policy.mtls.key-store-path is required in non-dev profiles");
        }
        if (!StringUtils.hasText(mtls.getKeyStorePassword())) {
            throw new IllegalStateException("gateway.policy.mtls.key-store-password is required in non-dev profiles");
        }
        if (!StringUtils.hasText(mtls.getTrustStorePath())) {
            throw new IllegalStateException("gateway.policy.mtls.trust-store-path is required in non-dev profiles");
        }
        if (!StringUtils.hasText(mtls.getTrustStorePassword())) {
            throw new IllegalStateException("gateway.policy.mtls.trust-store-password is required in non-dev profiles");
        }
    }
}
