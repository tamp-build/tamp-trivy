using Xunit;

namespace Tamp.Trivy.Tests;

// Metadata reads (TAM-282).
//
// The plan half. What makes this an inspect rather than a scan is one argument
// — an empty --scanners list — so that is the thing most worth pinning down.
public class TrivyImageInspectTests
{
    [Fact]
    public void Minimal_Settings_Produce_A_Json_Metadata_Read()
    {
        var plan = Trivy.InspectImage(s => s.SetImageRef("alpine:3.19"));

        Assert.Equal("trivy", plan.Executable);
        Assert.Equal(
            new[] { "image", "--format", "json", "--scanners", "", "--quiet", "--skip-version-check", "alpine:3.19" },
            plan.Arguments);
    }

    [Fact]
    public void The_Scanner_List_Is_Empty_Which_Is_What_Skips_The_Scan()
    {
        // THE argument. With any scanner named, Trivy downloads the
        // vulnerability database and scans — which is a long wait and a network
        // dependency to learn one timestamp.
        var args = Trivy.InspectImage(s => s.SetImageRef("x:y")).Arguments.ToList();

        var idx = args.IndexOf("--scanners");
        Assert.True(idx >= 0);
        Assert.Equal(string.Empty, args[idx + 1]);
    }

    [Fact]
    public void Json_Is_Not_Overridable()
    {
        // There is no SetFormat. A metadata read that emitted SARIF would carry
        // no metadata at all, so the format is not a choice worth offering.
        Assert.Null(typeof(TrivyImageInspectSettings).GetProperty("Format"));

        var args = Trivy.InspectImage(s => s.SetImageRef("x:y")).Arguments.ToList();
        Assert.Equal("json", args[args.IndexOf("--format") + 1]);
    }

    [Fact]
    public void Quiet_Is_On_By_Default_Because_The_Output_Is_Parsed()
    {
        // Progress output interleaved into stdout is what turns a parse into a
        // bug report.
        Assert.Contains("--quiet", Trivy.InspectImage(s => s.SetImageRef("x:y")).Arguments);
    }

    [Fact]
    public void Quiet_Can_Be_Turned_Off_For_A_Human_Watching_It()
    {
        var args = Trivy.InspectImage(s => s.SetImageRef("x:y").SetQuiet(false)).Arguments;

        Assert.DoesNotContain("--quiet", args);
    }

    [Fact]
    public void A_Tar_Input_Is_Supported()
    {
        var args = Trivy.InspectImage(s => s.SetInputTarFile("out/image.tar")).Arguments.ToList();

        Assert.Equal("out/image.tar", args[args.IndexOf("--input") + 1]);
    }

    [Fact]
    public void An_Output_File_Is_Passed_Through()
    {
        var args = Trivy.InspectImage(s => s.SetImageRef("x:y").SetOutputFile("meta.json")).Arguments.ToList();

        Assert.Equal("meta.json", args[args.IndexOf("--output") + 1]);
    }

    [Fact]
    public void Platform_And_Image_Sources_Are_Passed_Through()
    {
        var args = Trivy.InspectImage(s => s
            .SetImageRef("x:y")
            .SetPlatform("linux/arm64")
            .AddImageSource("remote")
            .AddImageSource("docker")).Arguments.ToList();

        Assert.Equal("linux/arm64", args[args.IndexOf("--platform") + 1]);
        Assert.Equal("remote,docker", args[args.IndexOf("--image-src") + 1]);
    }

    [Fact]
    public void The_Image_Reference_Is_Last()
    {
        // Positional. Trivy takes the target after the flags, and putting it
        // anywhere else makes the flags after it look like arguments to it.
        var args = Trivy.InspectImage(s => s.SetImageRef("alpine:3.19").SetPlatform("linux/amd64")).Arguments;

        Assert.Equal("alpine:3.19", args.Last());
    }

    [Fact]
    public void Remote_Only_Forces_A_Registry_Read()
    {
        // The trap this exists for: Trivy prefers a local daemon copy, so a
        // cached tag answers with the date the cache was filled rather than the
        // date the tag points at now. Measured at ninety days on a real machine
        // for aspnet:10.0-alpine — in the direction of making a current base
        // image look neglected.
        var args = Trivy.InspectImage(s => s.SetImageRef("x:y").SetRemoteOnly()).Arguments.ToList();

        Assert.Equal("remote", args[args.IndexOf("--image-src") + 1]);
    }

    [Fact]
    public void Remote_Only_Wins_Over_An_Explicit_Source_List()
    {
        // Setting both is contradictory, and the safe reading of a
        // contradiction here is the one that cannot answer from a stale cache.
        var args = Trivy.InspectImage(s => s
            .SetImageRef("x:y")
            .AddImageSource("docker")
            .SetRemoteOnly()).Arguments.ToList();

        Assert.Equal("remote", args[args.IndexOf("--image-src") + 1]);
        Assert.DoesNotContain("docker", args);
    }

    [Fact]
    public void Remote_Only_Is_Off_By_Default()
    {
        // Because inspecting an image you just built and have not pushed has
        // nothing in the registry to read.
        Assert.DoesNotContain("--image-src", Trivy.InspectImage(s => s.SetImageRef("x:y")).Arguments);
    }

    [Fact]
    public void A_Target_Is_Required()
    {
        Assert.Throws<InvalidOperationException>(() => Trivy.InspectImage(_ => { }));
    }

    [Fact]
    public void A_Ref_And_A_Tar_Together_Are_Refused()
    {
        // Trivy would silently prefer one. Refusing is better than a report
        // about an image the caller did not think they asked for.
        Assert.Throws<InvalidOperationException>(
            () => Trivy.InspectImage(s => s.SetImageRef("x:y").SetInputTarFile("a.tar")));
    }

    [Fact]
    public void A_Null_Configure_Is_Refused()
    {
        Assert.Throws<ArgumentNullException>(() => Trivy.InspectImage(null!));
    }
}
