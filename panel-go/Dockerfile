FROM golang:1.26.10-alpine AS build
WORKDIR /src
COPY panel-go/go.mod panel-go/go.sum ./
RUN go mod download
COPY panel-go/ ./
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o /flux-panel ./cmd/panel
FROM scratch
COPY --from=build --chmod=0555 /flux-panel /flux-panel
COPY gost.sql /database/gost.sql
COPY database/migrations /database/migrations
USER 65532:65532
ENV PANEL_LISTEN=0.0.0.0:6365 PANEL_SCHEMA_DIR=/database TZ=Asia/Shanghai
EXPOSE 6365
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 CMD ["/flux-panel", "healthcheck"]
ENTRYPOINT ["/flux-panel"]
