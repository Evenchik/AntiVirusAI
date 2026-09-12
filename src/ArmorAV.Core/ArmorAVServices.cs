using System;
using System.IO;

namespace ArmorAV
{

    public static class ArmorAVPaths
    {
        public static string DataDirectory
        {
            get
            {
                var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (string.IsNullOrWhiteSpace(root))
                    root = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                if (string.IsNullOrWhiteSpace(root))
                    root = AppContext.BaseDirectory;

                var directory = Path.Combine(root, Product.Name);
                Directory.CreateDirectory(directory);
                return directory;
            }
        }
    }

    public sealed class ScanRequest
    {
        public string Path { get; set; } = "";
        public bool QuarantineConfirmed { get; set; }
        public bool UseCache { get; set; } = true;
        public int MaxDepth { get; set; } = 10;
        public int Threads { get; set; } = Math.Max(1, Environment.ProcessorCount / 2);
        public string? AllowlistPath { get; set; }
        public string? DataDirectory { get; set; }
    }

    public static class ArmorAVService
    {
        public static ScanReport Scan(ScanRequest request)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));
            if (string.IsNullOrWhiteSpace(request.Path)) throw new ArgumentException("A file or directory path is required.", nameof(request));
            if (!File.Exists(request.Path) && !Directory.Exists(request.Path))
                throw new FileNotFoundException("The scan path does not exist.", request.Path);
            if (request.MaxDepth < 0) throw new ArgumentOutOfRangeException(nameof(request.MaxDepth));
            if (request.Threads < 1) throw new ArgumentOutOfRangeException(nameof(request.Threads));

            var dataDirectory = string.IsNullOrWhiteSpace(request.DataDirectory)
                ? ArmorAVPaths.DataDirectory
                : Path.GetFullPath(request.DataDirectory);
            Directory.CreateDirectory(dataDirectory);

            var options = new Options
            {
                Path = request.Path,
                Quarantine = request.QuarantineConfirmed,
                UseCache = request.UseCache,
                MaxDepth = request.MaxDepth,
                Threads = request.Threads,
                AllowlistPath = request.AllowlistPath
            };
            var report = new ScanReport
            {
                RootPath = Path.GetFullPath(request.Path),
                StartedUtc = Util.Iso8601Utc(DateTime.UtcNow)
            };
            var store = new QuarantineStore(dataDirectory, options.AllowlistPath);
            var cache = new ScanCache(dataDirectory, options.UseCache);
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            new ScanEngine(options, report, store, cache).Run(options.Path);
            stopwatch.Stop();

            report.DurationSeconds = stopwatch.Elapsed.TotalSeconds;
            report.CacheHits = cache.Hits;
            report.Consolidate();
            cache.Save();
            return report;
        }

        public static void ExportJson(ScanReport report, string path) => File.WriteAllText(path, Reporter.Json(report));
        public static void ExportHtml(ScanReport report, string path) => File.WriteAllText(path, Reporter.Html(report));
        public static void ExportCsv(ScanReport report, string path) => File.WriteAllText(path, Reporter.Csv(report));
        public static void ExportSarif(ScanReport report, string path) => File.WriteAllText(path, Reporter.Sarif(report));
    }
}
