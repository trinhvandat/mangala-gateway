package org.mangala.gateway.policy;

import lombok.RequiredArgsConstructor;
import org.mangala.security.model.ApiPermissionDTO;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@RequiredArgsConstructor
public class AuthPolicyApiClient {

    private final WebClient.Builder webClientBuilder;
    private final PolicyConfigProperties policyConfig;

    public Mono<List<ApiPermissionDTO>> fetchPolicies() {
        return createClient()
                .get()
                .uri("/v1/internal/policies")
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToFlux(ApiPermissionDTO.class)
                .collectList();
    }

    public Mono<Long> fetchPolicyVersion() {
        return createClient()
                .get()
                .uri("/v1/internal/policies/version")
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(Long.class);
    }

    private WebClient createClient() {
        return webClientBuilder
                .baseUrl(policyConfig.getAuthServiceUrl())
                .build();
    }
}
