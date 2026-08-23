namespace Tamp.Trivy;

/// <summary>
/// Tamp wrapper for Aqua Security's <c>trivy</c> CLI. Three subcommand
/// methods cover the canonical scan modes:
/// <list type="bullet">
///   <item><see cref="ScanImage"/> — <c>trivy image</c>; container OS-package + lockfile vulnerabilities.</item>
///   <item><see cref="ScanConfig"/> — <c>trivy config</c>; IaC misconfiguration scan (Terraform / Kubernetes / Dockerfile / CloudFormation / Helm / Ansible).</item>
///   <item><see cref="ScanFilesystem"/> — <c>trivy fs</c>; source-tree secrets + IaC + lockfile vulns.</item>
///   <item><see cref="InspectImage"/> — <c>trivy image</c> with no scanners; a metadata read, not a scan.</item>
/// </list>
/// </summary>
/// <remarks>
/// Adopter installs Trivy (homebrew, apt/yum, or release binary). Default
/// format is SARIF so output slots into the chain alongside OpenGrep, the
/// Roslyn ErrorLog leg, and OSV-Scanner.
/// </remarks>
public static class Trivy
{
    /// <summary>Scan a container image (registry, daemon, or local tar).</summary>
    public static CommandPlan ScanImage(Action<TrivyImageSettings> configure)
    {
        if (configure is null) throw new ArgumentNullException(nameof(configure));
        var settings = new TrivyImageSettings();
        configure(settings);
        return settings.ToCommandPlan();
    }

    /// <summary>Scan IaC configurations for misconfiguration findings.</summary>
    public static CommandPlan ScanConfig(Action<TrivyConfigSettings> configure)
    {
        if (configure is null) throw new ArgumentNullException(nameof(configure));
        var settings = new TrivyConfigSettings();
        configure(settings);
        return settings.ToCommandPlan();
    }

    /// <summary>
    /// Read an image's metadata without scanning it (TAM-282).
    ///
    /// <c>trivy image --format json --scanners ""</c>: Trivy reads the image
    /// config and emits the <c>Metadata</c> block without running vulnerability,
    /// secret or misconfiguration detection — and without needing the
    /// vulnerability database, which is the expensive part.
    ///
    /// Pair with <see cref="TrivyImageMetadata.Parse"/> to get the digest, the
    /// labels and, above all, the creation timestamp. The age of a base image
    /// tag is the only reliable way to say how old the foundation of a deployed
    /// artefact is, and running a full scan to learn one date would be an
    /// absurd price.
    ///
    /// <para>
    /// When inspecting a BASE image by tag, set
    /// <see cref="TrivyImageInspectSettings.RemoteOnly"/>. Trivy prefers a
    /// local daemon copy, so a cached tag answers with the date the cache was
    /// filled rather than the date the tag points at now — a silent, plausible
    /// error measured at ninety days on a real machine.
    /// </para>
    /// </summary>
    public static CommandPlan InspectImage(Action<TrivyImageInspectSettings> configure)
    {
        if (configure is null) throw new ArgumentNullException(nameof(configure));
        var settings = new TrivyImageInspectSettings();
        configure(settings);
        return settings.ToCommandPlan();
    }

    /// <summary>Scan a filesystem path for secrets, misconfig, and/or lockfile vulnerabilities.</summary>
    public static CommandPlan ScanFilesystem(Action<TrivyFilesystemSettings> configure)
    {
        if (configure is null) throw new ArgumentNullException(nameof(configure));
        var settings = new TrivyFilesystemSettings();
        configure(settings);
        return settings.ToCommandPlan();
    }
}
