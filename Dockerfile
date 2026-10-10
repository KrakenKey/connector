FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/krakenkey-connector \
    ./cmd/krakenkey-connector

# Alpine rather than distroless so exec targets and then.exec hooks have a
# shell available.
FROM alpine:3.24
RUN apk add --no-cache ca-certificates \
    && adduser -D -H -u 10001 connector \
    && mkdir -p /var/lib/krakenkey-connector /etc/krakenkey-connector \
    && chown connector:connector /var/lib/krakenkey-connector \
    && chmod 700 /var/lib/krakenkey-connector
COPY --from=build /out/krakenkey-connector /usr/local/bin/krakenkey-connector
USER connector
VOLUME /var/lib/krakenkey-connector
ENTRYPOINT ["/usr/local/bin/krakenkey-connector"]
CMD ["run", "--config", "/etc/krakenkey-connector/config.yaml"]
