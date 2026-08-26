# syntax=docker/dockerfile:1

# Build the UI first: it is embedded into the binary, so the Go stage needs it
# present before it compiles.
FROM node:20-alpine AS web
WORKDIR /src/web
# Copy manifests alone first so a source-only change does not re-run npm ci.
COPY web/package.json web/package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.25-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The web build writes into cmd/orbisd/web/dist, which the embed directive
# picks up. Copying it after the source copy means it is not clobbered.
COPY --from=web /src/cmd/orbisd/web/dist ./cmd/orbisd/web/dist
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /orbisd ./cmd/orbisd

FROM alpine:3.20
# nftables and iproute2 are the ruleset and routing tools Orbis shells out to.
# conntrack-tools lets it tear down established connections when blocking one.
# tcpdump backs the packet-capture export; libcap lets a non-root process keep
# the raw-socket capability if the operator chooses to drop privileges.
RUN apk add --no-cache \
      nftables iproute2 conntrack-tools tcpdump \
      ca-certificates tzdata libcap curl bind-tools \
    && addgroup -S orbis && adduser -S -G orbis orbis

COPY --from=build /orbisd /usr/local/bin/orbisd

# Config and state are volumes: a container that loses its blocklists, CA and
# flow history on every image update is not something anyone would run twice.
RUN mkdir -p /etc/orbis /var/lib/orbis && chown -R orbis:orbis /var/lib/orbis
VOLUME ["/etc/orbis", "/var/lib/orbis"]

EXPOSE 8080/tcp 53/udp 53/tcp 853/tcp 8443/tcp 3128/tcp 3129/tcp 51820/udp

# A container that answers the API is not necessarily filtering anything, but
# an unreachable API definitely means something is wrong.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/api/auth/status >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/orbisd"]
CMD ["-config", "/etc/orbis/orbis.yaml"]
