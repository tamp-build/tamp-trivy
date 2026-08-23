using Xunit;

namespace Tamp.Trivy.Tests;

// Reading a Trivy image report (TAM-282).
//
// The fixture below is a REAL `trivy image --format json --scanners ""` report
// (Trivy 0.70.0, alpine:3.19), trimmed of the fields this type does not read.
// Hand-writing a fixture to match what the parser expects is how a parser comes
// to pass its tests and fail on the tool's actual output.
public class TrivyImageMetadataTests
{
    private const string AlpineReport = """
        {
          "SchemaVersion": 2,
          "ArtifactName": "alpine:3.19",
          "ArtifactType": "container_image",
          "Metadata": {
            "Size": 7688192,
            "OS": { "Family": "alpine", "Name": "3.19.9" },
            "ImageID": "sha256:83b2b6703a620bf2e001ab57f7adc414d891787b3c59859b1b62909e48dd2242",
            "RepoTags": [ "alpine:3.19" ],
            "RepoDigests": [ "alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1" ],
            "ImageConfig": {
              "architecture": "amd64",
              "created": "2025-10-08T11:10:40Z",
              "os": "linux",
              "config": {
                "Cmd": [ "/bin/sh" ],
                "Env": [ "PATH=/usr/local/sbin:/usr/local/bin" ],
                "WorkingDir": "/"
              }
            }
          },
          "Results": []
        }
        """;

    [Fact]
    public void It_Reads_The_Creation_Timestamp()
    {
        // The field the whole type exists for.
        var metadata = TrivyImageMetadata.Parse(AlpineReport);

        Assert.Equal(
            new DateTimeOffset(2025, 10, 8, 11, 10, 40, TimeSpan.Zero),
            metadata.Created);
    }

    [Fact]
    public void It_Reads_The_Identity_Fields()
    {
        var metadata = TrivyImageMetadata.Parse(AlpineReport);

        Assert.Equal("alpine:3.19", metadata.Reference);
        Assert.Equal("alpine:3.19", Assert.Single(metadata.RepoTags));
        Assert.StartsWith("alpine@sha256:", Assert.Single(metadata.RepoDigests), StringComparison.Ordinal);
        Assert.StartsWith("sha256:", metadata.ImageId, StringComparison.Ordinal);
        Assert.Equal("alpine", metadata.OsFamily);
        Assert.Equal("3.19.9", metadata.OsVersion);
        Assert.Equal(7_688_192, metadata.SizeBytes);
    }

    [Fact]
    public void Age_Is_Measured_From_The_Creation_Timestamp()
    {
        var metadata = TrivyImageMetadata.Parse(AlpineReport);

        var asOf = new DateTimeOffset(2026, 1, 6, 11, 10, 40, TimeSpan.Zero);

        Assert.Equal(90, metadata.AgeInDays(asOf));
    }

    [Fact]
    public void Age_Never_Goes_Negative()
    {
        // Clock skew between a build agent and a registry is normal, and an
        // image "minus three days old" reads as a bug in the reader rather than
        // as the two seconds of skew it actually is.
        var metadata = TrivyImageMetadata.Parse(AlpineReport);

        Assert.Equal(0, metadata.AgeInDays(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero)));
    }

    [Fact]
    public void An_Image_With_No_Timestamp_Has_An_Unknown_Age_Not_A_Zero_One()
    {
        // Reproducible builds zero the created field. A consumer must read that
        // as "unknown", never as "brand new" — which is what a 0 would say.
        var metadata = TrivyImageMetadata.Parse("""
            { "Metadata": { "ImageConfig": { "architecture": "amd64" } } }
            """);

        Assert.Null(metadata.Created);
        Assert.Null(metadata.AgeInDays(DateTimeOffset.UtcNow));
    }

    [Fact]
    public void The_Base_Image_Comes_From_The_Standard_Oci_Annotations()
    {
        var metadata = TrivyImageMetadata.Parse("""
            {
              "Metadata": {
                "ImageConfig": {
                  "created": "2026-02-01T00:00:00Z",
                  "config": {
                    "Labels": {
                      "org.opencontainers.image.base.name": "mcr.microsoft.com/dotnet/aspnet:10.0-alpine",
                      "org.opencontainers.image.base.digest": "sha256:abc123",
                      "org.opencontainers.image.version": "1.2.3"
                    }
                  }
                }
              }
            }
            """);

        Assert.Equal("mcr.microsoft.com/dotnet/aspnet:10.0-alpine", metadata.BaseImageName);
        Assert.Equal("sha256:abc123", metadata.BaseImageDigest);
        Assert.Equal("1.2.3", metadata.Labels["org.opencontainers.image.version"]);
    }

    [Fact]
    public void A_Missing_Base_Annotation_Is_Null_Rather_Than_Guessed()
    {
        // The common case, and worth a test precisely because it is tempting to
        // infer a base image from layer history. BuildKit only sets these
        // annotations under some configurations — the official .NET and Alpine
        // images carry neither — and a guess here would become a confident
        // wrong sentence on somebody's dashboard.
        var metadata = TrivyImageMetadata.Parse(AlpineReport);

        Assert.Null(metadata.BaseImageName);
        Assert.Null(metadata.BaseImageDigest);
        Assert.Empty(metadata.Labels);
    }

    [Fact]
    public void A_Blank_Base_Annotation_Is_Also_Null()
    {
        // An empty label is a build system setting it to nothing, which is the
        // same as not knowing.
        var metadata = TrivyImageMetadata.Parse("""
            {
              "Metadata": {
                "ImageConfig": { "config": { "Labels": { "org.opencontainers.image.base.name": "  " } } }
              }
            }
            """);

        Assert.Null(metadata.BaseImageName);
    }

    [Fact]
    public void A_Report_With_No_Metadata_Block_Still_Yields_The_Artifact_Name()
    {
        // Trivy's report shape has moved across its 0.x line and will move
        // again. A wrapper that threw on an unfamiliar report would take an
        // adopter's whole build down over a field they may not even use.
        var metadata = TrivyImageMetadata.Parse("""
            { "SchemaVersion": 2, "ArtifactName": "alpine:3.19" }
            """);

        Assert.Equal("alpine:3.19", metadata.Reference);
        Assert.Null(metadata.Created);
        Assert.Empty(metadata.RepoTags);
    }

    [Fact]
    public void Unexpected_Types_Do_Not_Throw()
    {
        // Same reasoning: every field is read defensively rather than cast.
        var metadata = TrivyImageMetadata.Parse("""
            {
              "ArtifactName": 42,
              "Metadata": {
                "Size": "not-a-number",
                "RepoTags": "not-an-array",
                "OS": [],
                "ImageConfig": { "created": 12345, "config": { "Labels": [ "nope" ] } }
              }
            }
            """);

        Assert.Null(metadata.Reference);
        Assert.Null(metadata.SizeBytes);
        Assert.Null(metadata.Created);
        Assert.Empty(metadata.RepoTags);
        Assert.Empty(metadata.Labels);
    }

    [Fact]
    public void A_Timestamp_Without_An_Offset_Is_Read_As_Utc()
    {
        // Reading a naive timestamp as local time would shift the age by the
        // reader's timezone — a bug that only appears in one office.
        var metadata = TrivyImageMetadata.Parse("""
            { "Metadata": { "ImageConfig": { "created": "2026-02-01T00:00:00" } } }
            """);

        Assert.Equal(TimeSpan.Zero, metadata.Created!.Value.Offset);
        Assert.Equal(new DateTimeOffset(2026, 2, 1, 0, 0, 0, TimeSpan.Zero), metadata.Created);
    }

    [Fact]
    public void Non_Json_Says_What_Probably_Went_Wrong()
    {
        // The usual cause is progress output interleaved into stdout, and the
        // fix is one flag. Saying so beats surfacing a column number.
        var ex = Assert.Throws<ArgumentException>(
            () => TrivyImageMetadata.Parse("2026-01-01 INFO Need to update DB\n{}"));

        Assert.Contains("--quiet", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Empty_Input_Is_Refused(string json)
    {
        Assert.Throws<ArgumentException>(() => TrivyImageMetadata.Parse(json));
    }
}
