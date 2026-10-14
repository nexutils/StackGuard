# syntax=docker/dockerfile:1
ARG GO_VERSION=1.22
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux
ENV LEGACY value with spaces
RUN <<EOF
go mod download
go build -o /out/app ./cmd/app
EOF

FROM build AS test
RUN go test ./...

FROM gcr.io/distroless/static:nonroot@sha256:deadbeef
COPY --from=build /out/app /app
EXPOSE 8080 9090/udp
USER nonroot:nonroot
HEALTHCHECK --interval=30s \
  CMD ["/app", "health"]
ENTRYPOINT ["/app"]
