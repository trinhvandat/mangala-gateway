package org.mangala.gateway.policy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyApiSecurityProfileGuardTest {

    @Test
    void shouldFailWhenNonDevProfileAndMtlsDisabled() {
        PolicyConfigProperties config = new PolicyConfigProperties();
        config.getMtls().setEnabled(false);

        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");

        PolicyApiSecurityProfileGuard guard = new PolicyApiSecurityProfileGuard(config, env);

        assertThatThrownBy(() -> guard.run(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("mTLS must be enabled");
    }

    @Test
    void shouldFailWhenNonDevProfileAndMtlsEnabledButMissingStores() {
        PolicyConfigProperties config = new PolicyConfigProperties();
        config.getMtls().setEnabled(true);
        config.getMtls().setKeyStorePath("/tmp/client.p12");
        config.getMtls().setKeyStorePassword("secret");

        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("staging");

        PolicyApiSecurityProfileGuard guard = new PolicyApiSecurityProfileGuard(config, env);

        assertThatThrownBy(() -> guard.run(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("trust-store-path");
    }

    @Test
    void shouldPassWhenDevProfileAndMtlsDisabled() {
        PolicyConfigProperties config = new PolicyConfigProperties();
        config.getMtls().setEnabled(false);

        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("dev");

        PolicyApiSecurityProfileGuard guard = new PolicyApiSecurityProfileGuard(config, env);

        assertThatCode(() -> guard.run(null)).doesNotThrowAnyException();
    }

    @Test
    void shouldPassWhenNonDevProfileAndMtlsFullyConfigured() {
        PolicyConfigProperties config = new PolicyConfigProperties();
        config.getMtls().setEnabled(true);
        config.getMtls().setKeyStorePath("/tmp/client.p12");
        config.getMtls().setKeyStorePassword("secret");
        config.getMtls().setTrustStorePath("/tmp/trust.p12");
        config.getMtls().setTrustStorePassword("secret");

        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");

        PolicyApiSecurityProfileGuard guard = new PolicyApiSecurityProfileGuard(config, env);

        assertThatCode(() -> guard.run(null)).doesNotThrowAnyException();
    }
}
