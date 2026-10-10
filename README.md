# Bastion – Zero-Trust API Security Gateway

**Bastion** is a high-performance Zero-Trust API Security Gateway and lightweight Web Application Firewall written in Go.

It sits in front of your backend services and provides:

- **JWT Authentication** (access + refresh tokens)
- **Multi-dimensional Rate Limiting** (Redis-backed)
- **Runtime WAF** protections (SQLi, XSS, Path Traversal, common injection patterns)
- **Security Headers** (CSP, HSTS, X-Frame-Options, etc.)
- **Structured Security Event Logging** (ready to feed into SIEM tools like SentinelLite)
- **Request ID tracing**
- Fully containerized & production-oriented design

Built as a serious portfolio project demonstrating Application Security, API Security, Detection Engineering integration, and secure system design.

---

## Architecture

```
Client → Bastion Gateway → Upstream Service
           │
           ├── JWT Validation
           ├── Rate Limiting (Redis)
           ├── WAF Inspection
           ├── Security Headers
           └── Structured Security Logs → SIEM
```

## Features

| Feature                    | Status |
|---------------------------|--------|
| JWT Access + Refresh      | ✅     |
| Redis Rate Limiting       | ✅     |
| WAF (SQLi / XSS / LFI)    | ✅     |
| Security Headers          | ✅     |
| Structured Security Logs  | ✅     |
| Request ID Tracing        | ✅     |
| Graceful Shutdown         | ✅     |
| Docker Support            | ✅     |
| Config via YAML           | ✅     |

## Quick Start

### Prerequisites
- Go 1.22+
- Redis (optional – rate limiting fails open if Redis is down)

### Run locally

```bash
# Start Redis (optional but recommended)
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Run Bastion
go run cmd/bastion/main.go configs/config.yaml
```

### Demo Credentials
```
Username: admin
Password: bastion-demo-2026
```

### Example Flow

```bash
# 1. Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"bastion-demo-2026"}'

# 2. Call protected endpoint
curl http://localhost:8080/api/protected \
  -H "Authorization: Bearer <access_token>"

# 3. Test WAF (should be blocked)
curl "http://localhost:8080/api/protected?q=1' OR 1=1--" \
  -H "Authorization: Bearer <access_token>"
```

## Project Structure

```
bastion/
├── cmd/bastion/main.go          # Entry point
├── configs/config.yaml          # Configuration
├── internal/
│   ├── auth/                    # JWT token service
│   ├── config/                  # Config loading
│   ├── handlers/                # HTTP handlers
│   ├── logger/                  # Structured + Security logging
│   ├── middleware/              # JWT, RateLimit, WAF, Headers
│   ├── ratelimit/               # Redis rate limiter
│   └── waf/                     # WAF engine
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Security Design Decisions

- **Fail-open on Redis** for rate limiting (can be changed to fail-closed)
- Constant-time token validation via standard JWT library
- Body size limits to prevent DoS
- Non-root Docker image recommended
- All security events emitted as structured JSON (perfect for SIEM ingestion)
- Security headers applied globally

## Integration with SentinelLite

Bastion emits structured security events (`waf_block`, `rate_limit`, `auth_failure`) in JSON.
These can be shipped directly into **SentinelLite** (or any SIEM) for correlation and alerting.

## License

MIT

---

Built by [Mohit Bhandari](https://github.com/mohit-bhandari45) – 2026
