FROM golang:1.27-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# No go.sum is committed (generated on the fly), so build in module-mutating mode.
# Without this, `go build` runs in the default -mod=readonly and fails with
# "missing go.sum entry" at the build step.
ENV GOFLAGS=-mod=mod

COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o /harbore-worker ./main.go

# ─── Final image ──────────────────────────────────────────────────────────────
FROM alpine:3.19

# Install security tools
RUN apk add --no-cache \
    ca-certificates \
    nmap \
    nmap-scripts \
    tzdata \
    wget \
    curl \
    bash

# Install Nuclei
ARG NUCLEI_VERSION=3.2.9
RUN wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
        -O /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei \
    || echo "Nuclei download skipped (no network during build)"

WORKDIR /app

COPY --from=builder /harbore-worker /app/harbore-worker

RUN addgroup -S harbore && adduser -S -G harbore harbore

# Nuclei templates directory (populated at runtime or via volume)
RUN mkdir -p /nuclei-templates && chown harbore:harbore /nuclei-templates

# Nmap scripts permissions
RUN chmod +x /usr/bin/nmap || true

USER harbore

ENV ORCHESTRATOR_URL=http://orchestrator:8080
ENV REDIS_ADDR=redis:6379

ENTRYPOINT ["/app/harbore-worker"]
