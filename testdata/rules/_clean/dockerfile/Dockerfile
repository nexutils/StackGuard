# syntax=docker/dockerfile:1
FROM golang:1.25@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS build
WORKDIR /src
COPY . .
RUN go build -o /app ./cmd/app

FROM debian:12.5-slim@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates=20230311 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app /app
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + || true
LABEL org.opencontainers.image.title="demo" \
      org.opencontainers.image.description="demo service" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.authors="team@example.com" \
      org.opencontainers.image.source="https://example.com/repo" \
      org.opencontainers.image.revision="abc1234" \
      org.opencontainers.image.base.name="debian:12.5-slim"
ENV APP_ENV=production PORT=8080
EXPOSE 8080
STOPSIGNAL SIGTERM
USER 10001
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/app", "healthcheck"]
ENTRYPOINT ["/sbin/tini", "--", "/app"]
