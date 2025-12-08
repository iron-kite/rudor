FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

RUN groupadd -r nonroot && useradd -r -g nonroot nonroot

COPY --chown=nonroot:nonroot rudor /app/rudor

USER nonroot:nonroot

ENTRYPOINT ["/app/rudor"]

CMD ["--help"]
