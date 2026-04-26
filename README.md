# hf-ml-platform.auth

![CI](https://github.com/mohamed-ahmed-58059/hf-ml-platform.auth/actions/workflows/ci.yml/badge.svg)

Identity service for the HuggingFace ML Platform. Issues RS256 JWTs,
manages user sessions and rotating refresh tokens, mints
service-to-service tokens, and manages user-owned API keys.

## Capabilities

| | Notes |
|---|---|
| **Signup / login** | Email + password, bcrypt cost 12 |
| **JWT issuance** | RS256, 15-minute access tokens; public key served at `/v1/auth/public-key` |
| **Refresh tokens** | 7-day, rotating, single-use, SHA-256 hashed in DB, 5-second grace period for concurrent requests; reuse detection revokes the entire session |
| **Sessions** | Capped at 10 per user, oldest-evicted on overflow |
| **API keys** | SHA-256 hashed, per-user cap of 10, raw key returned exactly once at creation; lookups match the hash the rate limiter computes |
| **Service auth** | Client credentials grant via `/internal/v1/auth/token` (internal path, not reachable from the public listener) |
| **Cookies** | HttpOnly, Secure, SameSite=Strict; refresh cookie path-restricted to `/v1/auth/refresh` |
| **Cleanup** | Hourly scheduled job deletes expired refresh tokens (1-day retention) and sessions (7-day retention) |

## API

Full machine-readable spec: [`openapi.yaml`](./openapi.yaml). Paste it
into [editor.swagger.io](https://editor.swagger.io/) for a rendered
view.

## Tech stack

- Java 21 + Spring Boot 3.5
- Spring Security (stateless)
- Spring Data JPA + HikariCP
- jjwt 0.12.6 (RS256)
- Postgres
- Maven

## Configuration

Provided at runtime via environment variables and Secrets Manager.

| Variable | Source |
|---|---|
| `POSTGRES_HOST` | SSM `/hf-ml-platform/rds/endpoint` |
| `POSTGRES_DB` | Static (`hf_platform`) |
| `POSTGRES_USER`, `POSTGRES_PASSWORD` | Secrets Manager `hf-ml-platform/rds` |
| `RSA_PRIVATE_KEY` | Secrets Manager `hf-ml-platform/auth/rsa-private-key` |
| `SNS_TOPIC_ARN` | Cache invalidation publish target |

Tunables in `src/main/resources/application.yml`:

| Property | Default |
|---|---|
| `app.jwt.access-token-expiry-seconds` | `900` |
| `app.refresh-token.expiry-days` | `7` |
| `app.session.max-per-user` | `10` |
| `app.api-key.max-per-user` | `10` |
| `app.reuse-grace-period-seconds` | `5` |
