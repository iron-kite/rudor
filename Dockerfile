FROM gcr.io/distroless/static-debian12

ARG TARGETARCH

LABEL org.opencontainers.image.title="Rudor"
LABEL org.opencontainers.image.description="Lightweight SBOM generator with CVE scanning"
LABEL org.opencontainers.image.source="https://github.com/iron-kite/rudor"
LABEL org.opencontainers.image.licenses="See LICENSE file"

WORKDIR /app

COPY --chown=nonroot:nonroot dist/rudor_${TARGETARCH}_*/rudor /app/rudor

USER nonroot:nonroot

ENTRYPOINT ["/app/rudor"]

CMD ["--help"]
