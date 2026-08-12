# Build CPA plugin .so (c-shared) matching Debian bookworm / linux amd64 CPA runtime.
FROM golang:1.26-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY cpa-plugin/go/go.mod cpa-plugin/go/go.sum ./
RUN go mod download
COPY cpa-plugin/go/ ./

ARG VERSION=1.1.29
RUN test -n "$VERSION" \
  && grep -Eq "pluginVersion[[:space:]]*= \"${VERSION}\"" main.go \
  && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go test ./... \
  && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -buildvcs=false -buildmode=c-shared -trimpath \
       -o /out/grok2api-egress-v${VERSION}.so . \
  && cp /out/grok2api-egress-v${VERSION}.h /out/ 2>/dev/null || true \
  && ls -la /out

FROM scratch AS artifact
COPY --from=builder /out/ /