# Changelog

All notable changes recorded here. [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format; [SemVer](https://semver.org/spec/v2.0.0.html) versions.

## [1.11.2] — Unreleased

### Added

- **TAM-282 — image metadata reads.** `Trivy.InspectImage(…)` builds a `trivy image --format json --scanners ""` plan: Trivy reads the image config and emits the `Metadata` block without running any scanner, and without needing the vulnerability database. `TrivyImageMetadata.Parse(json)` reads that report into a typed record — reference, digest, OS, size, labels and, above all, the creation timestamp, plus `AgeInDays(asOf)`.

  Motivated by base-image age scoring downstream (tamp.findings TFND-134). A base image is usually the single largest source of inherited CVEs in a deployed artefact, and the publish date of its tag is the only reliable way to say how old that foundation is.

  `BaseImageName` / `BaseImageDigest` come from the standard OCI annotations and are **null when absent** rather than inferred from layer history — BuildKit only sets them under some configurations, and a guess would reach a dashboard as a fact. The parser is deliberately tolerant: Trivy's report shape has moved across its 0.x line, so every field is optional and an unfamiliar report yields nulls rather than taking an adopter's build down.

### Changed

- **TAM-254 — Repository migration.** Moved from the main `tamp` monorepo into this satellite repo. Package ID, namespace, public API, and version line unchanged — adopters see no break.

## [1.11.1] and earlier

Shipped from the main `tamp` monorepo. See [`tamp-build/tamp` CHANGELOG](https://github.com/tamp-build/tamp/blob/main/CHANGELOG.md) for the pre-migration history.
