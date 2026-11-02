FROM golang:1.25.4-alpine AS gost-build
WORKDIR /src/go-gost
COPY go-gost/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -o /node/gost-managed-linux-amd64 . && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o /node/gost-managed-linux-arm64 .

FROM golang:1.26.10-alpine AS agent-build
WORKDIR /src/node-agent
COPY node-agent/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -o /node/flux-agent-linux-amd64 ./cmd/flux-agent && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o /node/flux-agent-linux-arm64 ./cmd/flux-agent

FROM golang:1.26.10-alpine AS node-package
RUN apk add --no-cache python3
COPY --from=gost-build /node/ /node-release/
COPY --from=agent-build /node/ /node-release/
COPY node-agent/packaging/ /packaging/
RUN python3 /packaging/finalize-release.py --directory /node-release

FROM golang:1.26.10-alpine AS build
WORKDIR /src
COPY panel-go/go.mod panel-go/go.sum ./
RUN go mod download
COPY panel-go/ ./
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o /flux-panel ./cmd/panel
FROM scratch
COPY --from=build --chmod=0555 /flux-panel /flux-panel
COPY --chmod=0755 gost.sql /database/gost.sql
COPY --chmod=0755 database/migrations /database/migrations
COPY --from=node-package --chmod=0755 /node-release /node-release
USER 65532:65532
ENV PANEL_LISTEN=0.0.0.0:6365 PANEL_SCHEMA_DIR=/database NODE_RELEASE_DIR=/node-release TZ=Asia/Shanghai
EXPOSE 6365
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 CMD ["/flux-panel", "healthcheck"]
ENTRYPOINT ["/flux-panel"]
