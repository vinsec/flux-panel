# Runtime only. Supply a locally built static Linux binary as flux-panel.
# No package installation, network access or Java runtime is required.
FROM scratch
COPY --chmod=0555 flux-panel /flux-panel
USER 65532:65532
ENV PANEL_LISTEN=0.0.0.0:6365
EXPOSE 6365
ENTRYPOINT ["/flux-panel"]
