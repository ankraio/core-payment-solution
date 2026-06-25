# Static (CGO-off) image containing the collector and every emulator binary.
# Each compose service runs the same image and selects its binary via `command`.
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/collector ./cmd/collector && \
    go build -trimpath -ldflags="-s -w" -o /out/ssh-emu ./cmd/ssh-emu && \
    go build -trimpath -ldflags="-s -w" -o /out/tomcat-emu ./cmd/tomcat-emu && \
    go build -trimpath -ldflags="-s -w" -o /out/jdwp-emu ./cmd/jdwp-emu && \
    go build -trimpath -ldflags="-s -w" -o /out/payments-api-emu ./cmd/payments-api-emu && \
    go build -trimpath -ldflags="-s -w" -o /out/admin-portal-emu ./cmd/admin-portal-emu && \
    go build -trimpath -ldflags="-s -w" -o /out/redis-emu ./cmd/redis-emu && \
    go build -trimpath -ldflags="-s -w" -o /out/k8s-emu ./cmd/k8s-emu && \
    go build -trimpath -ldflags="-s -w" -o /out/ajp-emu ./cmd/ajp-emu && \
    go build -trimpath -ldflags="-s -w" -o /out/kubelet-emu ./cmd/kubelet-emu && \
    go build -trimpath -ldflags="-s -w" -o /out/etcd-emu ./cmd/etcd-emu

FROM alpine:3.20
RUN adduser -D -u 10001 sentinel && mkdir -p /var/lib/honeypot && chown sentinel /var/lib/honeypot
COPY --from=builder /out/ /app/
COPY config/ /app/config/
USER sentinel
ENV HONEYPOT_CONFIG=/app/config/honeypot.yaml
WORKDIR /app
ENTRYPOINT []
