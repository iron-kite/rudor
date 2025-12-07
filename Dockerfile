FROM debian:bookworm-slim

WORKDIR /app

RUN groupadd -r nonroot && useradd -r -g nonroot nonroot

COPY --chown=nonroot:nonroot rudor /app/rudor

USER nonroot:nonroot

ENTRYPOINT ["/app/rudor"]

CMD ["--help"]
