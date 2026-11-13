# Full source publishing

This repository is an experimental **0.1** platform. `tests/L7` is an isolated gateway acceptance harness. `control-center/` now contains the latest full universal management app source, admin UI, agent, installer, Windows validation scripts and docs.

CI gate `.github/workflows/control-center-ci.yml` builds the **complete** application on Windows and Linux in addition to the existing L7 real-traffic acceptance workflow. A successful isolated L7 run does NOT imply the full control-center build succeeds.

No secrets, compiled outputs, package caches, or historical ZIP snapshots are committed.
