# Runtime for the checksum-pinned, locally built release bundle.
FROM scratch
COPY --chmod=0555 flux-panel /flux-panel
COPY gost.sql /database/gost.sql
COPY migrations /database/migrations
USER 65532:65532
ENV PANEL_LISTEN=0.0.0.0:6365 PANEL_SCHEMA_DIR=/database TZ=Asia/Shanghai
EXPOSE 6365
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 CMD ["/flux-panel", "healthcheck"]
ENTRYPOINT ["/flux-panel"]
