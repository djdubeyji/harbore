.PHONY: all build up down restart logs clean test fmt lint

# Support both Docker Compose v2 (docker compose) and v1 (docker-compose)
COMPOSE := $(shell docker compose version > /dev/null 2>&1 && echo "docker compose" || echo "docker-compose")
GO      := go

# ─── Bootstrap ───────────────────────────────────────────────────────────────
.env:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		PPW=$$(openssl rand -hex 16); \
		RPW=$$(openssl rand -hex 16); \
		JWT=$$(openssl rand -hex 32); \
		WTK=$$(openssl rand -hex 16); \
		sed -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$$PPW|" \
		    -e "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=$$RPW|" \
		    -e "s|^JWT_SECRET=.*|JWT_SECRET=$$JWT|" \
		    -e "s|^WORKER_TOKEN=.*|WORKER_TOKEN=$$WTK|" \
		    .env > .env.tmp && mv .env.tmp .env; \
		echo "✓ Created .env with generated secrets"; \
	fi

# ─── Docker ──────────────────────────────────────────────────────────────────
build: .env
	$(COMPOSE) build --parallel

up: .env
	$(COMPOSE) up -d
	@printf "  → waiting for database"
	@until $(COMPOSE) exec -T postgres pg_isready -U harbore >/dev/null 2>&1; do printf "."; sleep 1; done; echo ""
	@$(COMPOSE) exec -T postgres psql -U harbore -d harbore -f /docker-entrypoint-initdb.d/002_patch.sql >/dev/null 2>&1 || true
	@echo "  ✓ schema up to date"
	@echo ""
	@echo "  ✓ Harbore is starting"
	@echo "  → UI:          http://localhost:3000"
	@echo "  → API:         http://localhost:8080"
	@echo "  → Default:     admin@harbore.local / password"
	@echo ""

migrate:
	@until $(COMPOSE) exec -T postgres pg_isready -U harbore >/dev/null 2>&1; do sleep 1; done
	$(COMPOSE) exec -T postgres psql -U harbore -d harbore -f /docker-entrypoint-initdb.d/002_patch.sql
	@echo "Schema patch applied (no data lost)"

up-logs: .env
	$(COMPOSE) up

down:
	$(COMPOSE) down

restart:
	$(COMPOSE) restart orchestrator

restart-all:
	$(COMPOSE) restart

logs:
	$(COMPOSE) logs -f orchestrator

logs-all:
	$(COMPOSE) logs -f

logs-ai:
	$(COMPOSE) logs -f ai

logs-report:
	$(COMPOSE) logs -f report

clean:
	$(COMPOSE) down -v --remove-orphans
	@docker image rm -f harbore-orchestrator harbore-worker harbore-ai harbore-report harbore-frontend 2>/dev/null || true
	@echo "Clean complete"

ps:
	$(COMPOSE) ps

# ─── Frontend dev (hot reload) ────────────────────────────────────────────────
frontend-dev:
	cd frontend && npm run dev

frontend-install:
	cd frontend && npm install

frontend-build:
	cd frontend && npm run build

# ─── Go ──────────────────────────────────────────────────────────────────────
dev-orchestrator:
	cd orchestrator && $(GO) run main.go

dev-worker:
	cd worker && $(GO) run main.go

deps:
	cd orchestrator && $(GO) mod tidy && $(GO) mod download
	cd worker && $(GO) mod tidy && $(GO) mod download

test:
	cd orchestrator && $(GO) test ./... -v -race -timeout 60s
	cd worker && $(GO) test ./... -v -race -timeout 60s

fmt:
	cd orchestrator && $(GO) fmt ./...
	cd worker && $(GO) fmt ./...

vet:
	cd orchestrator && $(GO) vet ./...
	cd worker && $(GO) vet ./...

# ─── Python ──────────────────────────────────────────────────────────────────
dev-ai:
	cd ai && pip install -r requirements.txt && python main.py

dev-report:
	cd report && pip install -r requirements.txt && python main.py

# ─── Database ────────────────────────────────────────────────────────────────
db-shell:
	$(COMPOSE) exec postgres psql -U harbore -d harbore

db-reset:
	$(COMPOSE) exec postgres psql -U harbore -d harbore -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	$(COMPOSE) exec postgres psql -U harbore -d harbore -f /docker-entrypoint-initdb.d/001_init.up.sql
	@echo "Database reset complete"

# ─── Help ────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "Harbore — Make Commands"
	@echo "───────────────────────────────────────"
	@echo "  make build          Build all Docker images (parallel)"
	@echo "  make up             Start full stack (detached)"
	@echo "  make up-logs        Start full stack with logs"
	@echo "  make down           Stop all services"
	@echo "  make logs           Tail orchestrator logs"
	@echo "  make logs-all       Tail all service logs"
	@echo "  make clean          Remove containers, volumes, images"
	@echo "  make db-shell       Open PostgreSQL shell"
	@echo "  make db-reset       Reset database (destructive!)"
	@echo "  make frontend-dev   Start frontend hot-reload dev server"
	@echo "  make test           Run all Go tests"
	@echo "  make fmt            Format all Go code"
	@echo ""
