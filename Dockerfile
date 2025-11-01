FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

ARG TARGETOS
ARG TARGETARCH

WORKDIR /build

COPY src/go.mod src/go.sum ./

RUN go mod download

COPY src/ .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-w -s" -o rudor .

FROM alpine:latest

LABEL org.opencontainers.image.title="Rudor"
LABEL org.opencontainers.image.description="Lightweight SBOM generator with CVE scanning"
LABEL org.opencontainers.image.source="https://github.com/iron-kite/rudor"
LABEL org.opencontainers.image.licenses="See LICENSE file"

RUN apk --no-cache add ca-certificates && \
    addgroup -g 1000 rudor && \
    adduser -D -u 1000 -G rudor rudor

WORKDIR /app

COPY --from=builder /build/rudor /app/rudor

RUN chown rudor:rudor /app/rudor

USER rudor

ENTRYPOINT ["/app/rudor"]

CMD ["--help"]