# syntax=docker/dockerfile:1.6

# ---- Builder ----
FROM golang:1.22-alpine AS builder
WORKDIR /build

# 缓存依赖
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/oneauth-server ./cmd/server

# ---- Runtime ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 10001 oneauth

WORKDIR /app
COPY --from=builder /out/oneauth-server /app/oneauth-server
COPY config/config.yaml /app/config/config.yaml

# keys 目录运行时挂载或自动生成
RUN mkdir -p /app/keys && chown -R oneauth:oneauth /app

USER oneauth
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/oneauth-server"]
CMD ["-config", "/app/config/config.yaml"]
