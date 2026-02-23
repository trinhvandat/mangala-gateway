package org.mangala.gateway.policy;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;

@Slf4j
@Configuration
public class PolicyApiMtlsWebClientConfig {

    @Bean
    @Qualifier("policyApiWebClientBuilder")
    public WebClient.Builder policyApiWebClientBuilder(PolicyConfigProperties policyConfig) {
        if (!policyConfig.getMtls().isEnabled()) {
            return WebClient.builder();
        }

        try {
            SslContext sslContext = buildSslContext(policyConfig.getMtls());
            HttpClient httpClient = HttpClient.create().secure(ssl -> ssl.sslContext(sslContext));
            return WebClient.builder().clientConnector(new ReactorClientHttpConnector(httpClient));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize mTLS WebClient for policy API", e);
        }
    }

    private SslContext buildSslContext(PolicyConfigProperties.MtlsConfig mtls) throws Exception {
        KeyStore keyStore = loadStore(mtls.getKeyStoreType(), mtls.getKeyStorePath(), mtls.getKeyStorePassword());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, mtls.getKeyStorePassword().toCharArray());

        KeyStore trustStore = loadStore(mtls.getTrustStoreType(), mtls.getTrustStorePath(), mtls.getTrustStorePassword());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        return SslContextBuilder.forClient()
                .keyManager(kmf)
                .trustManager(tmf)
                .build();
    }

    private KeyStore loadStore(String type, String path, String password) throws Exception {
        KeyStore store = KeyStore.getInstance(type);
        try (InputStream input = new FileInputStream(path)) {
            store.load(input, password.toCharArray());
        }
        return store;
    }
}
