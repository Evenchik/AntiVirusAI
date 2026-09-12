using System.IO.Compression;
using ArmorAV;

namespace ArmorAV.SmokeTests;

internal static class Program
{
    private static int Main()
    {
        var root = Path.Combine(Path.GetTempPath(), "armorav-smoke-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            DetectsKnownAndBenignSamples(root);
            DetectsZipTraversal(root);
            QuarantineIsAuthenticatedAndRestorable(root);
            Console.WriteLine("ArmorAV smoke tests passed.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("ArmorAV smoke test failed: " + ex.Message);
            return 1;
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    private static void DetectsKnownAndBenignSamples(string root)
    {
        var samples = Path.Combine(root, "samples");
        Directory.CreateDirectory(samples);
        CopyFixture("benign.txt", samples);
        CopyFixture("eicar.txt", samples);
        CopyFixture("suspicious.ps1", samples);

        var report = ArmorAVService.Scan(new ScanRequest
        {
            Path = samples,
            DataDirectory = Path.Combine(root, "app-data"),
            UseCache = false
        });
        Assert(report.Results.Count == 3, "the sample directory should produce three results");
        Assert(report.Results.Single(x => x.Path.EndsWith("eicar.txt")).VerdictText == Verdict.Confirmed.ToString(),
            "the EICAR test string must be confirmed");
        Assert(report.Results.Single(x => x.Path.EndsWith("benign.txt")).VerdictText == Verdict.Clean.ToString(),
            "a benign text sample must remain clean");
        Assert(report.Results.Single(x => x.Path.EndsWith("suspicious.ps1")).VerdictText == Verdict.Suspicious.ToString(),
            "a shadow-copy deletion command must be suspicious");
    }

    private static void DetectsZipTraversal(string root)
    {
        var path = Path.Combine(root, "traversal.zip");
        using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("../../invoice.exe");
            using var writer = new StreamWriter(entry.Open());
            writer.Write("not an executable");
        }

        var report = ArmorAVService.Scan(new ScanRequest
        {
            Path = path,
            DataDirectory = Path.Combine(root, "zip-app-data"),
            UseCache = false
        });
        Assert(report.Results.Single().Findings.Any(x => x.Name == "Archive.PathTraversal"),
            "a path traversal ZIP entry must be reported");
    }

    private static void QuarantineIsAuthenticatedAndRestorable(string root)
    {
        var dataDirectory = Path.Combine(root, "quarantine-data");
        var source = Path.Combine(root, "confirmed.bin");
        var bytes = "quarantine round trip"u8.ToArray();
        File.WriteAllBytes(source, bytes);
        var hashes = Hasher.FromFile(source);
        var store = new QuarantineStore(dataDirectory, null);
        var record = store.Store(source, hashes, "fingerprint", 100, new[] { "test" }, dryRun: false);

        var blob = Path.Combine(dataDirectory, "quarantine", record.Id + ".bin");
        Assert(!File.Exists(source), "a committed quarantine operation must remove the original file");
        Assert(File.Exists(blob), "the encrypted quarantine blob must exist");
        Assert(!File.ReadAllBytes(blob).AsSpan().SequenceEqual(bytes), "the quarantine blob must not store the source plaintext");

        Assert(store.Restore(record.Id, out var message), "the new quarantine format must restore: " + message);
        Assert(File.ReadAllBytes(source).AsSpan().SequenceEqual(bytes), "restored bytes must match the original file");
    }

    private static void CopyFixture(string fileName, string destination)
    {
        var source = Path.Combine(AppContext.BaseDirectory, "Fixtures", fileName);
        if (!File.Exists(source)) throw new FileNotFoundException("Test fixture was not copied to output.", source);
        File.Copy(source, Path.Combine(destination, fileName));
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
