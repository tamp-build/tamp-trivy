# Changelog

All notable changes recorded here. [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format; [SemVer](https://semver.org/spec/v2.0.0.html) versions.

## [Unreleased]

## [1.12.0] - 2026-11-20 - .NET 11 in, .NET 8 and .NET 9 out

### Changed

- **Multi-targets `net10.0;net11.0`** instead of `net8.0;net9.0;net10.0` ([ADR 0015](https://github.com/tamp-build/tamp/blob/main/docs/adr/0015-target-framework-strategy.md)). .NET 11 shipped 2026-11-10 and .NET 8 and .NET 9 reached end of support the same day; the rule is to add a TFM the day a release ships and drop one the day Microsoft ends its support. `global.json` pins SDK 11.0.100.

  **If you target `net8.0` or `net9.0`, stay on the previous version** — this one carries no assets your project can resolve.

- **`Tamp.*` pinned to 1.21.0**, which carries a SARIF fix worth knowing about if this package's output is read as evidence: before 1.21.0, a SARIF result whose scanner omitted `level` was read as `none` — the least severe value — instead of the declared `warning`, on every runtime before net11 ([tamp#166](https://github.com/tamp-build/tamp/issues/166)).

- **Publishing moved to nuget.org trusted publishing (OIDC).** The `tamp_nuget_api_key` org secret expired 2026-11-01 along with every other pre-2026-08-17 nuget.org key. The publish job now mints a short-lived key from its own OIDC token, so there is no long-lived credential to rotate or leak.

## [1.11.3] — 2026-09-27

### Added

- **TAM-282 — image metadata reads.** `Trivy.InspectImage(…)` builds a `trivy image --format json --scanners ""` plan: Trivy reads the image config and emits the `Metadata` block without running any scanner, and without needing the vulnerability database. `TrivyImageMetadata.Parse(json)` reads that report into a typed record — reference, digest, OS, size, labels and, above all, the creation timestamp, plus `AgeInDays(asOf)`.

  Motivated by base-image age scoring downstream (tamp.findings TFND-134). A base image is usually the single largest source of inherited CVEs in a deployed artefact, and the publish date of its tag is the only reliable way to say how old that foundation is.

  `TrivyImageInspectSettings.RemoteOnly` (`--image-src remote`) forces a registry read. Trivy prefers a local daemon copy, so a cached tag answers with the date the cache was filled rather than the date the tag points at now — measured at **ninety days** on `aspnet:10.0-alpine` (daemon said 2026-05-12 / alpine 3.23.4, registry said 2026-08-10 / alpine 3.24.1). Set it for base-image lookups; leave it off for an image you have just built and not yet pushed.

  `BaseImageName` / `BaseImageDigest` come from the standard OCI annotations and are **null when absent** rather than inferred from layer history — BuildKit only sets them under some configurations, and a guess would reach a dashboard as a fact. The parser is deliberately tolerant: Trivy's report shape has moved across its 0.x line, so every field is optional and an unfamiliar report yields nulls rather than taking an adopter's build down.
- Package now ships XML documentation files (`.xml`) alongside the assembly, so consumers get IntelliSense and API docs. (Mirrors [tamp-build/tamp#3](https://github.com/tamp-build/tamp/pull/50).)

### Changed

- **TAM-254 — Repository migration.** Moved from the main `tamp` monorepo into this satellite repo. Package ID, namespace, public API, and version line unchanged — adopters see no break.

## [1.11.1] and earlier

Shipped from the main `tamp` monorepo. See [`tamp-build/tamp` CHANGELOG](https://github.com/tamp-build/tamp/blob/main/CHANGELOG.md) for the pre-migration history.
