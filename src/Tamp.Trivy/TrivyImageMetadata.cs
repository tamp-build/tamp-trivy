using System.Globalization;
using System.Text.Json;

namespace Tamp.Trivy;

/// <summary>
/// What an image is, read out of a <c>trivy image --format json</c> report
/// (TAM-282).
///
/// The facts a consumer needs to say how old the foundation of a deployed
/// artefact is: which image, at which digest, published when. A base image is
/// usually the single largest source of inherited CVEs in a container, and
/// unlike a package it is one line in a Dockerfile — the highest leverage per
/// fix available.
/// </summary>
/// <remarks>
/// This is the one place in the wrapper that READS Trivy output rather than
/// building a command for it. That is deliberate: parsing Trivy's own report
/// shape is squarely wrapping Trivy, and the alternative is every consumer
/// hand-rolling the same <c>Metadata.ImageConfig.created</c> lookup and getting
/// the null cases differently wrong.
/// </remarks>
public sealed record TrivyImageMetadata
{
    /// <summary>The reference Trivy was pointed at, as reported back.</summary>
    public string? Reference { get; init; }

    /// <summary>Tags this image is known by, e.g. <c>alpine:3.19</c>.</summary>
    public IReadOnlyList<string> RepoTags { get; init; } = [];

    /// <summary>Repository digests, e.g. <c>alpine@sha256:…</c>.</summary>
    public IReadOnlyList<string> RepoDigests { get; init; } = [];

    /// <summary>The image config digest (<c>sha256:…</c>).</summary>
    public string? ImageId { get; init; }

    /// <summary>
    /// When the image was built, from the image config.
    ///
    /// THE field this whole type exists for. Null when the config carries no
    /// timestamp — which happens with reproducible builds that zero it — and a
    /// consumer must treat that as "unknown", never as "new".
    /// </summary>
    public DateTimeOffset? Created { get; init; }

    /// <summary>OS family and version, when Trivy identified one.</summary>
    public string? OsFamily { get; init; }

    /// <summary>OS version, when Trivy identified one.</summary>
    public string? OsVersion { get; init; }

    /// <summary>Total image size in bytes, when reported.</summary>
    public long? SizeBytes { get; init; }

    /// <summary>Image config labels, verbatim.</summary>
    public IReadOnlyDictionary<string, string> Labels { get; init; } =
        new Dictionary<string, string>();

    /// <summary>
    /// The base image this was built FROM, from the standard OCI annotation
    /// <c>org.opencontainers.image.base.name</c>.
    ///
    /// Frequently null, and that is worth knowing rather than working around:
    /// BuildKit only sets it under certain build configurations, and most
    /// published images — including the official .NET and Alpine ones — do not
    /// carry it. A consumer that needs the base image reliably should have the
    /// adopter state it (it is one line in their build script) rather than
    /// infer one, because inferring it from layer history produces a confident
    /// guess and this is not a place for those.
    /// </summary>
    public string? BaseImageName { get; init; }

    /// <summary>Base image digest, from <c>org.opencontainers.image.base.digest</c>. Usually null, as above.</summary>
    public string? BaseImageDigest { get; init; }

    /// <summary>How old the image is at <paramref name="asOf"/>, or null when it carries no timestamp.</summary>
    public int? AgeInDays(DateTimeOffset asOf) =>
        Created is { } created ? (int)Math.Max(0, (asOf - created).TotalDays) : null;

    /// <summary>
    /// Read the metadata out of a Trivy JSON report.
    ///
    /// Tolerant on purpose. Trivy's report shape has changed across its 0.x
    /// line and will change again, so every field is optional and a missing one
    /// yields null rather than an exception — a wrapper that threw on an
    /// unfamiliar report would take an adopter's whole build down for a field
    /// they may not even use.
    /// </summary>
    /// <exception cref="ArgumentException">The input is not JSON at all.</exception>
    public static TrivyImageMetadata Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            throw new ArgumentException("Trivy report JSON is empty.", nameof(json));

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException ex)
        {
            // Named as the wrapper's problem to diagnose rather than surfacing
            // a bare parser error, because the usual cause is Trivy's progress
            // output being interleaved into stdout — which --quiet prevents and
            // InspectImage sets by default.
            throw new ArgumentException(
                "Trivy report is not valid JSON. If the report was read from stdout, check that "
                + "--quiet was passed: progress output interleaved with the report is the usual cause.",
                nameof(json), ex);
        }

        using (document)
        {
            var root = document.RootElement;
            var metadata = Child(root, "Metadata");

            if (metadata is not { } meta) return new TrivyImageMetadata
            {
                Reference = String(root, "ArtifactName"),
            };

            var config = Child(meta, "ImageConfig");
            var labels = ReadLabels(config);
            var os = Child(meta, "OS");

            return new TrivyImageMetadata
            {
                // Trivy reports the reference it resolved under Metadata, and
                // the name it was given at the root. Prefer the resolved one.
                Reference = String(meta, "Reference") ?? String(root, "ArtifactName"),
                RepoTags = Strings(meta, "RepoTags"),
                RepoDigests = Strings(meta, "RepoDigests"),
                ImageId = String(meta, "ImageID"),
                Created = config is { } c ? Timestamp(c, "created") : null,
                OsFamily = os is { } o ? String(o, "Family") : null,
                OsVersion = os is { } o2 ? String(o2, "Name") : null,
                SizeBytes = Number(meta, "Size"),
                Labels = labels,
                BaseImageName = Label(labels, "org.opencontainers.image.base.name"),
                BaseImageDigest = Label(labels, "org.opencontainers.image.base.digest"),
            };
        }
    }

    private static JsonElement? Child(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object
        && parent.TryGetProperty(name, out var child)
        && child.ValueKind == JsonValueKind.Object
            ? child
            : null;

    private static string? String(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object
        && parent.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static long? Number(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object
        && parent.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.Number
        && value.TryGetInt64(out var number)
            ? number
            : null;

    private static IReadOnlyList<string> Strings(JsonElement parent, string name)
    {
        if (parent.ValueKind != JsonValueKind.Object
            || !parent.TryGetProperty(name, out var array)
            || array.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var values = new List<string>();
        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String && item.GetString() is { } value)
                values.Add(value);
        }

        return values;
    }

    private static DateTimeOffset? Timestamp(JsonElement parent, string name)
    {
        var raw = String(parent, name);
        if (string.IsNullOrWhiteSpace(raw)) return null;

        // Round-trip, and ASSUME UTC when the string carries no offset. Trivy
        // emits RFC 3339 with a Z, but a report hand-edited or produced by an
        // older build can omit it — and reading a naive timestamp as local time
        // would shift the age by the reader's timezone, which is the kind of
        // bug that only shows up in one office.
        return DateTimeOffset.TryParse(
            raw, CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
            out var parsed)
            ? parsed
            : null;
    }

    private static IReadOnlyDictionary<string, string> ReadLabels(JsonElement? config)
    {
        var labels = new Dictionary<string, string>(StringComparer.Ordinal);

        if (config is not { } c
            || !c.TryGetProperty("config", out var inner)
            || inner.ValueKind != JsonValueKind.Object
            || !inner.TryGetProperty("Labels", out var raw)
            || raw.ValueKind != JsonValueKind.Object)
        {
            return labels;
        }

        foreach (var property in raw.EnumerateObject())
        {
            if (property.Value.ValueKind == JsonValueKind.String
                && property.Value.GetString() is { } value)
            {
                labels[property.Name] = value;
            }
        }

        return labels;
    }

    private static string? Label(IReadOnlyDictionary<string, string> labels, string key) =>
        labels.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;
}
