package org.mangala.gateway.exception;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GatewayErrorResponse {

    private String code;
    private String message;
    private String path;
    private String requestId;
    private Instant timestamp;
    private Object details;

    public static GatewayErrorResponse of(String code, String message, String path, String requestId) {
        return GatewayErrorResponse.builder()
                .code(code)
                .message(message)
                .path(path)
                .requestId(requestId)
                .timestamp(Instant.now())
                .build();
    }
}
