# Changelog

All notable changes to this project are documented in this file.

## [0.4.0] - 2026-05-17

### Added
- Public record-level DS APIs (`decode_record`, `read_record`, `iter_records`, `count_records`).
- Capacity preflight (`estimate_capacity`) and CLI `capacity` command.
- Carrier analysis and survivability evaluation commands.
- Optional encrypted payload envelope and authenticated manifests.
- Policy guardrails for authorized-use controls.
- Threshold shard split/reconstruct APIs and CLI commands.
- Repository governance scaffolding:
  - GitHub Actions CI and label sync workflows
  - Issue templates, discussion templates, PR template
  - Repository profile and label catalog

## [0.3.0] - 2026-05-16

### Added
- DS1/DS2 codec core, CLI encode/decode/inspect, and stego hide/reveal baseline.
