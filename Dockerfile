# syntax=docker/dockerfile:1
FROM golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build
ARG VERSION=dev
WORKDIR /src
# Optional: behind a TLS-inspecting proxy, pass its CA with
# --secret id=proxy_ca,src=/path/ca.pem. It is used only to download modules
# and never enters the image.
COPY go.mod go.sum ./
RUN --mount=type=secret,id=proxy_ca \
    --mount=type=cache,id=edgegateway-mod,target=/go/pkg/mod \
    if test -f /run/secrets/proxy_ca; then export SSL_CERT_FILE=/run/secrets/proxy_ca; fi; go mod download
COPY . .
RUN --mount=type=cache,id=edgegateway-mod,target=/go/pkg/mod \
    --mount=type=cache,id=edgegateway-build,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /edgegateway ./cmd/edgegateway
FROM scratch
LABEL org.opencontainers.image.source="https://github.com/1a11/clearintervals-edge"
COPY --from=build /edgegateway /edgegateway
USER 65532:65532
EXPOSE 8429/tcp
ENTRYPOINT ["/edgegateway"]
