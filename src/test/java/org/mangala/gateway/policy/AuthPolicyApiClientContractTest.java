package org.mangala.gateway.policy;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mangala.security.model.ApiPermissionDTO;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AuthPolicyApiClientContractTest {

    private MockWebServer mockWebServer;
    private AuthPolicyApiClient client;

    @BeforeEach
    void setUp() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();

        PolicyConfigProperties policyConfig = new PolicyConfigProperties();
        policyConfig.setAuthServiceUrl(mockWebServer.url("/").toString());

        client = new AuthPolicyApiClient(WebClient.builder(), policyConfig);
    }

    @AfterEach
    void tearDown() throws IOException {
        mockWebServer.shutdown();
    }

    @Test
    void shouldParsePoliciesContract() {
        mockWebServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .setBody("""
                        [
                          {
                            "id": "rule-1",
                            "httpMethod": "GET",
                            "pathPattern": "/api/v1/wallets",
                            "permissionCode": "wallet:read",
                            "conditionExpr": null,
                            "serviceName": "wallet-service",
                            "priority": 10,
                            "active": true
                          }
                        ]
                        """));

        StepVerifier.create(client.fetchPolicies())
                .assertNext(policies -> {
                    assertThat(policies).hasSize(1);
                    ApiPermissionDTO policy = policies.getFirst();
                    assertThat(policy.getId()).isEqualTo("rule-1");
                    assertThat(policy.getHttpMethod()).isEqualTo("GET");
                    assertThat(policy.getPathPattern()).isEqualTo("/api/v1/wallets");
                    assertThat(policy.getPermissionCode()).isEqualTo("wallet:read");
                    assertThat(policy.getPriority()).isEqualTo(10);
                    assertThat(policy.isActive()).isTrue();
                })
                .verifyComplete();
    }

    @Test
    void shouldParsePolicyVersionContractAsJsonNumber() {
        mockWebServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .setBody("42"));

        StepVerifier.create(client.fetchPolicyVersion())
                .expectNext(42L)
                .verifyComplete();
    }

    @Test
    void shouldFailOnPolicyEndpointServerError() {
        mockWebServer.enqueue(new MockResponse()
                .setResponseCode(500)
                .setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .setBody("{\"error\":\"internal\"}"));

        StepVerifier.create(client.fetchPolicies())
                .expectErrorSatisfies(error -> assertThat(error).isInstanceOf(WebClientResponseException.class))
                .verify();
    }

    @Test
    void shouldFailWhenVersionPayloadIsNotJsonNumber() {
        mockWebServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .setBody("\"not-a-number\""));

        StepVerifier.create(client.fetchPolicyVersion())
                .expectError()
                .verify();
    }

    @Test
    void shouldFailWhenPoliciesPayloadWrongContentType() {
        mockWebServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", MediaType.TEXT_PLAIN_VALUE)
                .setBody("not-json"));

        StepVerifier.create(client.fetchPolicies())
                .expectError()
                .verify();
    }
}
