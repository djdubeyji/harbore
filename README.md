# Harbore — Web Application & API Security Scanner

Enterprise-grade security scanning platform. Scans 1000+ APIs in parallel using isolated Docker containers.

## Architecture

```
Browser → API Gateway (JWT/RBAC) → Orchestrator → Redis Queue → Worker Containers (N parallel)
                                                                       ↓
                                                   Findings → PostgreSQL + Object Store
                                                                       ↓
                                                              AI Enrichment → Report Engine
```

## Quick Start

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env with your secrets

# 2. Build images
make build

# 3. Start the full stack
make up

# 4. Open in browser
open http://localhost:8080/health

# Default credentials: admin@harbore.local / admin123
# CHANGE IMMEDIATELY in production
```

## API Usage

### Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@harbore.local","password":"admin123"}'
```

### Create and start a scan
```bash
TOKEN="your-jwt-token"

# Create scan
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "your-project-uuid",
    "name": "API Security Scan",
    "target_type": "url_list",
    "config": {
      "targets": [
        "https://api.example.com/v1/users",
        "https://api.example.com/v1/payments"
      ],
      "auth": {
        "bearer": "your-api-token"
      }
    },
    "modules": ["asset", "cert", "vuln", "pci", "auth", "fuzzer"],
    "container_limit": 10,
    "max_retries": 3
  }'

# Start the scan
curl -X POST http://localhost:8080/api/v1/scans/{scan-id}/start \
  -H "Authorization: Bearer $TOKEN"
```

### WebSocket live updates
```javascript
const ws = new WebSocket('ws://localhost:8080/ws/scans/{scan-id}');
ws.onmessage = (e) => console.log(JSON.parse(e.data));
```

## Modules

| Module     | Description                                    | Weight |
|------------|------------------------------------------------|--------|
| asset      | Port scan (Nmap), DNS, HTTP fingerprinting     | 2      |
| cert       | TLS/SSL analysis, cipher suites, expiry        | 1      |
| crawler    | OpenAPI/GraphQL discovery, endpoint mapping    | 2      |
| vuln       | OWASP Top 10, Nuclei (optional)                | 5      |
| auth       | IDOR, JWT, OAuth, privilege escalation         | 5      |
| pci        | PCI DSS v4.0, cardholder data, CDE checks      | 4      |
| fuzzer     | Type confusion, SQLi, XSS, SSTI, SSRF          | 10     |
| passive    | HAR analysis, PII detection, secret scanning   | 1      |
| compliance | HIPAA/SOC2/NIST framework mapping              | 2      |

## Supported Input Types

- `openapi` — OpenAPI 3.x / Swagger 2.x spec file
- `postman` — Postman collection JSON
- `graphql` — GraphQL schema
- `soap` — WSDL file
- `url_list` — Plain list of URLs
- `har` — Browser HAR capture
- `mcp` — MCP server manifest
- `single_url` — Single URL

## Container Limits

Set `container_limit` per scan to control parallelism:
- `1–5` — safe for testing / limited cloud resources
- `10` — default production setting
- `50+` — large-scale scans (ensure host has resources)

## Environment Variables

See `.env.example` for all variables. Required minimums:
- `POSTGRES_PASSWORD` — PostgreSQL password
- `REDIS_PASSWORD` — Redis password
- `JWT_SECRET` — Min 64 chars, randomly generated
- `WORKER_TOKEN` — Min 32 chars, randomly generated

Generate secrets:
```bash
openssl rand -hex 64  # for JWT_SECRET
openssl rand -hex 32  # for WORKER_TOKEN
```

## Project Structure

```
harbore/
├── orchestrator/          # Main Go service (API + job scheduling)
│   ├── api/               # HTTP handlers and middleware
│   ├── config/            # Environment config
│   ├── container/         # Docker SDK integration
│   ├── db/                # PostgreSQL queries
│   ├── models/            # Shared types
│   ├── queue/             # Redis job queue
│   ├── scheduler/         # Parallelism + retry logic
│   └── websocket/         # Live scan event hub
├── worker/                # Scanner service (runs in containers)
│   └── modules/           # Individual scan modules
│       ├── asset/         # Nmap + DNS + HTTP fingerprinting
│       ├── auth/          # JWT + IDOR + OAuth
│       ├── cert/          # TLS/SSL analysis
│       ├── compliance/    # HIPAA/SOC2/NIST mapping
│       ├── crawler/       # API endpoint discovery
│       ├── fuzzer/        # Active payload fuzzing
│       ├── passive/       # HAR analysis + PII detection
│       ├── pci/           # PCI DSS v4.0
│       └── vuln/          # OWASP Top 10 + Nuclei
├── migrations/            # PostgreSQL schema
└── docker-compose.yml
```

## Make Commands

```bash
make build          # Build all Docker images
make up             # Start full stack
make down           # Stop all services
make logs           # Tail orchestrator logs
make test           # Run all tests
make db-shell       # PostgreSQL shell
make clean          # Remove all containers + volumes
```
