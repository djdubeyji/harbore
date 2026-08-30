FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# No go.sum is committed (generated on the fly), so build in module-mutating mode.
# Without this, `go build` runs in the default -mod=readonly and fails with
# "missing go.sum entry" at the build step.
ENV GOFLAGS=-mod=mod

COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o /harbore-orchestrator ./main.go

# ─── Final image ──────────────────────────────────────────────────────────────
FROM alpine:3.24

RUN apk add --no-cache ca-certificates wget tzdata

WORKDIR /app

COPY --from=builder /harbore-orchestrator /app/harbore-orchestrator

RUN addgroup -S harbore && adduser -S -G harbore harbore
RUN chown harbore:harbore /app/harbore-orchestrator

USER harbore

EXPOSE 8080

ENTRYPOINT ["/app/harbore-orchestrator"]
