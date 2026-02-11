package org.mangala.gateway.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.mangala.security.model.PolicyUpdateEvent;
import org.springframework.data.redis.connection.ReactiveSubscription;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.stereotype.Component;
import reactor.core.Disposable;

/**
 * Listens for policy update events via Redis Pub/Sub.
 * When an update is received, triggers policy cache reload.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PolicyUpdateListener {

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final PolicyLoader policyLoader;
    private final PolicyCache policyCache;
    private final PolicyConfigProperties policyConfig;
    private final ObjectMapper objectMapper;

    private Disposable subscription;

    @PostConstruct
    public void subscribe() {
        if (policyConfig.isUseKafka()) {
            log.info("Using Kafka for policy updates, Redis listener disabled");
            return;
        }

        String channel = policyConfig.getRedisChannel();
        log.info("Subscribing to policy updates on Redis channel: {}", channel);

        subscription = redisTemplate.listenTo(ChannelTopic.of(channel))
                .map(ReactiveSubscription.Message::getMessage)
                .doOnNext(this::handleUpdate)
                .doOnError(e -> log.error("Error in policy update listener", e))
                .retry()
                .subscribe();
    }

    @PreDestroy
    public void unsubscribe() {
        if (subscription != null && !subscription.isDisposed()) {
            subscription.dispose();
            log.info("Unsubscribed from policy updates");
        }
    }

    private void handleUpdate(String message) {
        try {
            PolicyUpdateEvent event = objectMapper.readValue(message, PolicyUpdateEvent.class);
            log.info("Received policy update event. Version: {}, Type: {}",
                    event.getVersion(), event.getUpdateType());

            long currentVersion = policyCache.getVersion().get();

            if (event.getVersion() > currentVersion) {
                log.info("New policy version detected: {} -> {}. Reloading...",
                        currentVersion, event.getVersion());

                policyLoader.loadPolicies()
                        .doOnSuccess(v -> log.info("Policy reload completed after broadcast"))
                        .doOnError(e -> log.error("Policy reload failed after broadcast", e))
                        .subscribe();
            } else {
                log.debug("Ignoring policy update. Current: {}, Event: {}",
                        currentVersion, event.getVersion());
            }

        } catch (Exception e) {
            log.error("Failed to parse policy update message: {}", message, e);
        }
    }
}
