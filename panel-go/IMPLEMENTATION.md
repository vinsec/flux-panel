# Go panel implementation status

Baseline: a08e3d8. Authorized scope: complete replacement of retained Java features, local isolated tests only. GOST and native nftables; no iptables forwarding implementation.

COMPLETE for retained a08e3d8 features after local isolated validation. See ../doc/go-panel-validation.md and contracts/feature-matrix.json. No production deployment.

- [x] Independent worktree and baseline proposal updated.
- [x] Freeze 64 HTTP mappings and source DTO constraints.
- [x] Implement and verify authentication, all four captcha modes, configuration, OpenAPI.
- [x] Implement and verify user/node/tunnel/permission/limiter/forward management.
- [x] Implement and verify encrypted GOST + native Agent WebSockets and commands.
- [x] Implement and verify traffic v1/v2, credit, maintenance, revisions and recovery.
- [x] Implement and verify periodic jobs and ownership/shutdown.
- [x] Execute HTTP/permission/contracts, real MySQL integration, real GOST/nftables and frontend workflows.
- [x] Execute failure/concurrency/soak/performance and Go→Java rollback verification.
- [x] Produce complete feature/test manifest and delivery evidence.

Never reuse production credentials, databases or Agents. Never treat pre-existing Java results as Go validation.

Go-only repository cleanup and current build/install validation: ../doc/go-only-validation.md. Historical Java comparison uses old Git objects and artifacts only.
