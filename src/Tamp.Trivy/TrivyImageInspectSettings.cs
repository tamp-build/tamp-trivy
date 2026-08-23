namespace Tamp.Trivy;

/// <summary>
/// Settings for <see cref="Trivy.InspectImage"/> — a metadata read of an
/// image, not a scan (TAM-282).
///
/// Deliberately a separate type from <see cref="TrivyImageSettings"/> rather
/// than a flag on it. An inspect has no severity filter, no ignore-unfixed and
/// no exit code, because it is not looking for anything; offering those knobs
/// on a call that cannot act on them would be an invitation to misread what it
/// does.
/// </summary>
/// <remarks>
/// <para>
/// Trivy has no dedicated inspect subcommand, so this is <c>trivy image</c>
/// with <c>--format json</c> and <c>--scanners</c> set to the empty list.
/// Trivy accepts that and skips scanning entirely while still emitting the
/// <c>Metadata</c> block — which is where the image config, the digest and the
/// creation timestamp live.
/// </para>
/// <para>
/// The point of it: the creation timestamp of a base image tag is the only
/// reliable way to say how old the foundation of a deployed artefact is, and
/// a base image is usually the single largest source of inherited CVEs. Running
/// a full vulnerability scan to learn one date would be an absurd price.
/// </para>
/// </remarks>
public sealed class TrivyImageInspectSettings
{
    /// <summary>Image reference, e.g. <c>mcr.microsoft.com/dotnet/aspnet:10.0-alpine</c>. Positional.</summary>
    public string? ImageRef { get; set; }

    /// <summary>Local tarball produced by <c>docker save</c>. Maps to <c>--input</c>. Mutually exclusive with <see cref="ImageRef"/>.</summary>
    public string? InputTarFile { get; set; }

    /// <summary>Where the JSON report is written. Maps to <c>--output</c>. Null streams to stdout.</summary>
    public string? OutputFile { get; set; }

    /// <summary>Override the image platform (multi-arch images). Maps to <c>--platform</c>.</summary>
    public string? Platform { get; set; }

    /// <summary>Image source priority (docker / containerd / podman / remote). Maps to <c>--image-src</c>.</summary>
    public List<string> ImageSources { get; } = new();

    /// <summary>
    /// Read the image from the REGISTRY, ignoring any local copy.
    ///
    /// Set this when asking "when was this tag published" — which is what a
    /// base-image age check is asking. Trivy's default source order is
    /// <c>docker,containerd,podman,remote</c>, so a tag the local daemon
    /// happens to have cached is answered from that cache, and the answer is
    /// the date the cache was filled rather than the date the tag currently
    /// points at.
    ///
    /// That failure is silent and plausible, which is what makes it worth its
    /// own property. Measured on a real machine: <c>aspnet:10.0-alpine</c> read
    /// from a stale daemon cache reported a publish date of 2026-05-12, while
    /// the registry reported 2026-08-10 for the same tag — a ninety-day error,
    /// in the direction of making a current base image look neglected.
    ///
    /// Leave it off when inspecting an image you have just built and not yet
    /// pushed: there is nothing in the registry to read.
    /// </summary>
    public bool RemoteOnly { get; set; }

    /// <summary>
    /// Suppress progress and log output. Defaults to <c>true</c>: an inspect is
    /// nearly always machine-read, and a progress bar interleaved into stdout
    /// is what turns a parse into a bug report.
    /// </summary>
    public bool Quiet { get; set; } = true;

    /// <summary>
    /// Suppress the "a new version of Trivy is available" notice. Defaults to
    /// <c>true</c> for the same reason as <see cref="Quiet"/>.
    /// </summary>
    public bool SkipVersionCheck { get; set; } = true;

    public string? WorkingDirectory { get; set; }
    public Dictionary<string, string> EnvironmentVariables { get; } = new();

    public TrivyImageInspectSettings SetImageRef(string? r) { ImageRef = r; return this; }
    public TrivyImageInspectSettings SetInputTarFile(string? p) { InputTarFile = p; return this; }
    public TrivyImageInspectSettings SetOutputFile(string? p) { OutputFile = p; return this; }
    public TrivyImageInspectSettings SetPlatform(string? v) { Platform = v; return this; }
    public TrivyImageInspectSettings AddImageSource(string source) { ImageSources.Add(source); return this; }

    /// <summary>Read from the registry only — see <see cref="RemoteOnly"/>.</summary>
    public TrivyImageInspectSettings SetRemoteOnly(bool v = true) { RemoteOnly = v; return this; }
    public TrivyImageInspectSettings SetQuiet(bool v) { Quiet = v; return this; }
    public TrivyImageInspectSettings SetSkipVersionCheck(bool v) { SkipVersionCheck = v; return this; }
    public TrivyImageInspectSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }

    public CommandPlan ToCommandPlan()
    {
        if (string.IsNullOrEmpty(ImageRef) && string.IsNullOrEmpty(InputTarFile))
            throw new InvalidOperationException("TrivyImageInspectSettings requires either ImageRef or InputTarFile.");
        if (!string.IsNullOrEmpty(ImageRef) && !string.IsNullOrEmpty(InputTarFile))
            throw new InvalidOperationException("TrivyImageInspectSettings.ImageRef and .InputTarFile are mutually exclusive.");

        var args = new List<string> { "image", "--format", "json" };

        // The empty scanner list is what makes this an inspect. Trivy reads the
        // image config and emits Metadata without running vuln, secret or
        // misconfig detection — and without needing the vulnerability database,
        // which is the expensive part.
        args.Add("--scanners");
        args.Add(string.Empty);

        if (!string.IsNullOrEmpty(OutputFile))
        {
            args.Add("--output");
            args.Add(OutputFile!);
        }

        if (Quiet) args.Add("--quiet");
        if (SkipVersionCheck) args.Add("--skip-version-check");

        if (!string.IsNullOrEmpty(InputTarFile))
        {
            args.Add("--input");
            args.Add(InputTarFile!);
        }

        if (!string.IsNullOrEmpty(Platform))
        {
            args.Add("--platform");
            args.Add(Platform!);
        }

        // RemoteOnly wins over an explicit source list. Setting both is
        // contradictory, and the safe reading of a contradiction here is the
        // one that cannot silently answer from a stale cache.
        if (RemoteOnly)
        {
            args.Add("--image-src");
            args.Add("remote");
        }
        else if (ImageSources.Count > 0)
        {
            args.Add("--image-src");
            args.Add(string.Join(",", ImageSources));
        }

        if (!string.IsNullOrEmpty(ImageRef))
            args.Add(ImageRef!);

        return new CommandPlan
        {
            Executable = "trivy",
            Arguments = args,
            Environment = new Dictionary<string, string>(EnvironmentVariables),
            WorkingDirectory = WorkingDirectory,
        };
    }
}
