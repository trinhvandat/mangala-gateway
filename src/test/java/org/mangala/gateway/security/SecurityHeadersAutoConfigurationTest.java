package org.mangala.gateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityHeadersAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SecurityHeadersAutoConfiguration.class));

    @Test
    void shouldNotCreateFilterWhenDisabledByDefault() {
        contextRunner.run(context -> assertThat(context).doesNotHaveBean(SecurityHeadersFilter.class));
    }

    @Test
    void shouldCreateFilterWhenEnabled() {
        contextRunner
                .withPropertyValues("gateway.security.headers.enabled=true")
                .run(context -> assertThat(context).hasSingleBean(SecurityHeadersFilter.class));
    }
}
