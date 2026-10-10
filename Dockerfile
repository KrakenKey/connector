FROM golang:1.26-alpine AS build
WORKDIR /src
# Every module builds from its own go.mod; go.work is for local development.
ENV CGO_ENABLED=0 GOOS=linux GOWORK=off
COPY go.mod go.sum ./
COPY plugins/aws-acm/go.mod plugins/aws-acm/go.sum plugins/aws-acm/
COPY plugins/azure-appgateway/go.mod plugins/azure-appgateway/go.sum plugins/azure-appgateway/
COPY plugins/azure-keyvault/go.mod plugins/azure-keyvault/go.sum plugins/azure-keyvault/
RUN go mod download \
    && for dir in plugins/*/; do (cd "$dir" && go mod download); done
COPY . .
ARG VERSION=dev
RUN go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/krakenkey-connector \
    ./cmd/krakenkey-connector
# The plugins in this repository, laid out as the system plugin directory
# with a plugins.lock written from the binaries just built. Their version
# directory is the connector's version (VERSION).
RUN set -eu; \
    umask 022; \
    out=/out/usr/lib/krakenkey-connector/plugins; \
    for dir in plugins/*/; do \
      name=$(basename "$dir"); \
      bin=krakenkey-connector-plugin-$name; \
      (cd "$dir" && go build -trimpath -ldflags="-s -w" -o "$out/$name/${VERSION}/$bin" "./cmd/$bin"); \
    done; \
    cd "$out"; \
    sha256sum -- */*/krakenkey-connector-plugin-* > plugins.lock; \
    chmod 0644 plugins.lock

# Alpine rather than distroless so exec targets and then.exec hooks have a
# shell available.
FROM alpine:3.24
RUN apk add --no-cache ca-certificates \
    && adduser -D -H -u 10001 connector \
    && mkdir -p /var/lib/krakenkey-connector /etc/krakenkey-connector \
    && chown connector:connector /var/lib/krakenkey-connector \
    && chmod 700 /var/lib/krakenkey-connector
COPY --from=build /out/krakenkey-connector /usr/local/bin/krakenkey-connector
COPY --from=build --chown=0:0 /out/usr/lib/krakenkey-connector /usr/lib/krakenkey-connector
USER connector
VOLUME /var/lib/krakenkey-connector
ENTRYPOINT ["/usr/local/bin/krakenkey-connector"]
CMD ["run", "--config", "/etc/krakenkey-connector/config.yaml"]
