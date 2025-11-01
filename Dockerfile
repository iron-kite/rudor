FROM alpine:latest

ARG TARGETARCH

LABEL org.opencontainers.image.title="Rudor"
LABEL org.opencontainers.image.description="Lightweight SBOM generator with CVE scanning"
LABEL org.opencontainers.image.source="https://github.com/iron-kite/rudor"
LABEL org.opencontainers.image.licenses="See LICENSE file"

RUN apk --no-cache add ca-certificates && \
    addgroup -g 1000 rudor && \
    adduser -D -u 1000 -G rudor rudor

WORKDIR /app

COPY build/rudor-linux-${TARGETARCH} /app/rudor

RUN chown rudor:rudor /app/rudor && chmod +x /app/rudor

USER rudor

ENTRYPOINT ["/app/rudor"]

CMD ["--help"]
