# Mangala Gateway

API Gateway for Mangala Wallet Platform - providing unified entry point for all microservices with security, rate limiting, and circuit breaker patterns.

## Architecture

```
                         ┌─────────────────────────────────────┐
                         │          Mangala Gateway            │
                         │           (Port 8000)               │
                         ├─────────────────────────────────────┤
Client Request ──────────►│  • JWT Validation                   │
                         │  • Rate Limiting (Redis)            │
                         │  • Request Logging/Tracing          │
                         │  • Circuit Breaker (Resilience4j)   │
                         │  • CORS Handling                    │
                         └──────────┬──────────────────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         │                          │                          │
         ▼                          ▼                          ▼
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│ Auth Service    │      │ Wallet Service  │      │ Portfolio Svc   │
│ (Port 8080)     │      │ (Port 8081)     │      │ (Port 8082)     │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

## Features

- **Spring Cloud Gateway** - Reactive, non-blocking API gateway
- **JWT Authentication** - Token validation and user context propagation
- **Rate Limiting** - Redis-backed rate limiting per IP/user
- **Circuit Breaker** - Resilience4j circuit breaker with fallback responses
- **Request Tracing** - Request ID and correlation ID for distributed tracing
- **CORS** - Configurable cross-origin resource sharing
- **Health Checks** - Actuator endpoints for monitoring

## Tech Stack

| Component | Version |
|-----------|---------|
| Java | 21 |
| Spring Boot | 3.4.2 |
| Spring Cloud | 2024.0.0 |
| Spring Cloud Gateway | 4.2.x |
| Resilience4j | 2.2.0 |
| JJWT | 0.12.6 |

## Quick Start

### Prerequisites

- Java 21
- Maven 3.9+
- Redis (for rate limiting)
- Docker (optional)

### Local Development

1. **Start Redis**
```bash
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

2. **Set environment variables**
```bash
export JWT_SECRET=your-256-bit-secret-key-for-jwt-signing-replace-in-production
export AUTH_SERVICE_URL=http://localhost:8080
```

3. **Run the gateway**
```bash
mvn spring-boot:run
```

### Docker

```bash
# Build image
docker build -t mangala-gateway:latest .

# Run container
docker run -d \
  --name mangala-gateway \
  -p 8000:8000 \
  -e JWT_SECRET=your-secret-key \
  -e REDIS_HOST=redis \
  -e AUTH_SERVICE_URL=http://auth-service:8080 \
  mangala-gateway:latest
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_PORT` | 8000 | Gateway server port |
| `JWT_SECRET` | - | Secret key for JWT validation (required) |
| `JWT_ISSUER` | mangala | Expected JWT issuer |
| `REDIS_HOST` | localhost | Redis host for rate limiting |
| `REDIS_PORT` | 6379 | Redis port |
| `AUTH_SERVICE_URL` | http://localhost:8080 | Authentication service URL |
| `WALLET_SERVICE_URL` | http://localhost:8081 | Wallet service URL |
| `PORTFOLIO_SERVICE_URL` | http://localhost:8082 | Portfolio service URL |
| `TRANSACTION_SERVICE_URL` | http://localhost:8083 | Transaction service URL |
| `RATE_LIMIT_REPLENISH` | 10 | Rate limit replenish rate per second |
| `RATE_LIMIT_BURST` | 20 | Rate limit burst capacity |
| `CORS_ALLOWED_ORIGINS` | http://localhost:3000,http://localhost:5173 | Allowed CORS origins |
| `SECURITY_HEADERS_ENABLED` | false | Master toggle for production security headers baseline |
| `SECURITY_HSTS_ENABLED` | false | Enable Strict-Transport-Security response header |
| `SECURITY_CSP` | (empty) | Value for Content-Security-Policy header |
| `SECURITY_REFERRER_POLICY` | (empty) | Value for Referrer-Policy header |
| `SECURITY_PERMISSIONS_POLICY` | (empty) | Value for Permissions-Policy header |

## API Routes

| Path Pattern | Service | Description |
|-------------|---------|-------------|
| `/api/v1/auth/**` | auth-service | Authentication endpoints |
| `/api/v1/register/**` | auth-service | Registration (public) |
| `/api/v1/authenticate/**` | auth-service | Authentication (public) |
| `/api/v1/wallets/**` | wallet-service | Wallet management |
| `/api/v1/addresses/**` | wallet-service | Address management |
| `/api/v1/portfolios/**` | portfolio-service | Portfolio tracking |
| `/api/v1/holdings/**` | portfolio-service | Holdings management |
| `/api/v1/transactions/**` | transaction-service | Transaction history |

## Public Endpoints (No Auth Required)

- `POST /api/v1/register/**` - User registration
- `POST /api/v1/authenticate/**` - User authentication
- `POST /api/v1/auth/refresh` - Token refresh
- `GET /actuator/health` - Health check
- `GET /actuator/info` - Service info

## Headers

### Request Headers (Added by Gateway)

| Header | Description |
|--------|-------------|
| `X-Request-Id` | Unique request identifier |
| `X-Correlation-Id` | Correlation ID for distributed tracing |
| `X-User-Id` | Authenticated user ID (from JWT) |
| `X-User-Email` | Authenticated user email (from JWT) |
| `X-User-Roles` | User roles (comma-separated) |

### Response Headers

| Header | Description |
|--------|-------------|
| `X-Request-Id` | Echo of request ID |
| `X-Correlation-Id` | Echo of correlation ID |

## Monitoring

### Actuator Endpoints

| Endpoint | Description |
|----------|-------------|
| `/actuator/health` | Health status |
| `/actuator/info` | Application info |
| `/actuator/metrics` | Metrics data |
| `/actuator/prometheus` | Prometheus metrics |
| `/actuator/gateway/routes` | Registered routes |

### Prometheus Metrics

The gateway exposes Prometheus metrics at `/actuator/prometheus` including:
- Request count and latency
- Circuit breaker state
- Rate limiter metrics

## Error Responses

All errors return a consistent JSON structure:

```json
{
  "code": "SERVICE_UNAVAILABLE",
  "message": "Service is temporarily unavailable",
  "path": "/api/v1/wallets",
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-02-09T10:30:00Z"
}
```

### Security Decision Matrix (Contract)

| Scenario | Status | Contract |
|----------|--------|----------|
| Missing token on protected endpoint | 401 | JSON body with `code=GATEWAY_UNAUTHORIZED`, `message=Authentication required` |
| Invalid JWT on protected endpoint | 401 | JSON body with `code=GATEWAY_UNAUTHORIZED`, `message=Invalid JWT token` |
| Expired JWT on protected endpoint | 401 | JSON body with `code=GATEWAY_UNAUTHORIZED`, `message=JWT token expired` |
| Authenticated but insufficient permission | 403 | Header `X-Forbidden-Reason=Insufficient permissions` |
| Authenticated, ABAC condition failed | 403 | Header `X-Forbidden-Reason=Access condition not met` |
| No policy match + `gateway.policy.no-match-behavior=DENY` | 403 | Header `X-Forbidden-Reason` contains no-policy reason |
| No policy match + `gateway.policy.no-match-behavior=ALLOW` | Pass-through | Header `X-Authorization-Rule=no-policy-allow` |

Notes:
- Public paths (`/api/v1/register/**`, `/api/v1/authenticate/**`, `/api/v1/auth/refresh`) bypass auth.
- For protected routes, Spring Security authn may return 401 before ABAC logic runs when token is missing.

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `SERVICE_UNAVAILABLE` | 503 | Downstream service unavailable |
| `GATEWAY_TIMEOUT` | 504 | Request timed out |
| `GATEWAY_UNAUTHORIZED` | 401 | Invalid or missing JWT |
| `INTERNAL_ERROR` | 500 | Unexpected error |
| `AUTH_SERVICE_UNAVAILABLE` | 503 | Auth service circuit open |
| `WALLET_SERVICE_UNAVAILABLE` | 503 | Wallet service circuit open |

## Circuit Breaker

Circuit breaker configuration per service:

| Parameter | Value |
|-----------|-------|
| Sliding window size | 10 |
| Minimum calls | 5 |
| Failure rate threshold | 50% |
| Wait duration (open state) | 10s |
| Permitted calls (half-open) | 3 |

## Project Structure

```
mangala-gateway/
├── src/main/java/org/mangala/gateway/
│   ├── GatewayApplication.java
│   ├── config/
│   │   ├── GatewayConfigProperties.java
│   │   ├── RateLimiterConfig.java
│   │   └── SecurityConfig.java
│   ├── filter/
│   │   ├── JwtAuthenticationFilter.java
│   │   └── RequestLoggingFilter.java
│   ├── exception/
│   │   ├── GatewayErrorResponse.java
│   │   └── GlobalExceptionHandler.java
│   └── health/
│       ├── FallbackController.java
│       └── GatewayHealthIndicator.java
├── src/main/resources/
│   └── application.yml
├── Dockerfile
├── pom.xml
└── README.md
```

## Context Pack

Use these files to bootstrap quickly in new sessions:

- `AGENTS.md`
- `docs/context-map.yaml`
- `docs/adr/`
- `scripts/check-context-sync.sh`

Run consistency check:

```bash
./scripts/check-context-sync.sh
```

## License

MIT License - See LICENSE file for details.
