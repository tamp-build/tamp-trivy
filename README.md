# Tamp.Trivy

> Tamp wrapper for Aqua Security's trivy CLI — image / IaC config / filesystem scanning with SARIF output for the Tamp security pipeline.

| Package | Status |
|---|---|
| `Tamp.Trivy` | 1.11.2 (post-migration from main `tamp`) |

## Install

```bash
dotnet add package Tamp.Trivy
```

Multi-targets net8 / net9 / net10.

## Why a satellite repo

This package previously shipped from the main `tamp` repo (up to 1.11.1). It moved to its own satellite at 1.11.2 (TAM-254) so:

- Tool releases don't gate Tamp.Core releases (and vice versa).
- Adopters can pin the wrapper independently of Tamp.Core minors.
- The wrapper's release cadence tracks the wrapped tool instead of the whole framework.

Package ID, namespace, public API, and version line are unchanged — adopters see no break.

## Inspecting an image (TAM-282)

`Trivy.InspectImage` reads an image's metadata **without scanning it** — `trivy image --format json --scanners ""`. Trivy reads the image config and emits the `Metadata` block without running vulnerability, secret or misconfiguration detection, and without needing the vulnerability database.

```csharp
var plan = Trivy.InspectImage(s => s
    .SetImageRef("mcr.microsoft.com/dotnet/aspnet:10.0-alpine")
    .SetOutputFile("base-image.json"));

// ...run the plan through Tamp.Core, then:
var image = TrivyImageMetadata.Parse(File.ReadAllText("base-image.json"));

image.Created;                 // when the tag was published
image.AgeInDays(DateTimeOffset.UtcNow);
image.RepoDigests;             // what you actually pulled
image.BaseImageName;           // see the caveat below
```

**Why it exists:** a base image is usually the single largest source of inherited CVEs in a deployed artefact, and unlike a package it is one line in a Dockerfile — the highest leverage per fix available. The publish date of the base tag is the only reliable way to say how old that foundation is, and running a full vulnerability scan to learn one date would be an absurd price.

### Inspecting a base image: force the registry

```csharp
var plan = Trivy.InspectImage(s => s
    .SetImageRef("mcr.microsoft.com/dotnet/aspnet:10.0-alpine")
    .SetRemoteOnly());          // <- not optional for a base-image lookup
```

Trivy's source order is `docker,containerd,podman,remote`, so a tag your daemon has cached is answered *from that cache* — the date the cache was filled, not the date the tag points at now.

Measured on one machine:

| Source | Published | Alpine |
|---|---|---|
| daemon cache | 2026-05-12 | 3.23.4 |
| registry | 2026-08-10 | 3.24.1 |

Ninety days, in the direction that makes a current base image look neglected — and it fails silently, since you get back a date of the right shape that is simply wrong.

Leave `RemoteOnly` off when inspecting an image you just built and have not pushed: there is nothing in the registry to read.

### The base-image caveat

`BaseImageName` and `BaseImageDigest` come from the standard OCI annotations `org.opencontainers.image.base.name` / `.base.digest`, and **they are frequently absent**. BuildKit only sets them under some build configurations; neither the official .NET images nor Alpine carry them.

They are reported as `null` when missing rather than inferred from layer history. A base image guessed from layers is a confident wrong answer, and the consuming dashboard would present it as a fact. If you need the base image reliably, state it in your build script and inspect it directly — it is one string, and it is the string you already wrote in your `FROM` line.

### What this deliberately does not do

Listing the tags on a repository, to answer "how far behind is this base image". Trivy has no registry-catalog surface, so that would mean this wrapper opening its own registry connections — a different tool wearing this one's name. `Created` answers "how old", which is the question most policies actually ask.

## License

MIT — see [LICENSE](LICENSE).
