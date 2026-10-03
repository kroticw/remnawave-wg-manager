# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/remnawave-wg-manager ./cmd/remnawave-wg-manager

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
LABEL org.opencontainers.image.source="https://github.com/kroticw/remnawave-wg-manager" \
      org.opencontainers.image.description="WireGuard peer management for Remnawave" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/remnawave-wg-manager /remnawave-wg-manager
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD ["/remnawave-wg-manager", "healthcheck"]
ENTRYPOINT ["/remnawave-wg-manager"]
