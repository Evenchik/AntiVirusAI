using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using ArmorAV;

namespace ArmorAV.Web;

internal static class Program
{
    private const string TokenHeader = "X-ArmorAV-Token";

    public static async Task Main(string[] args)
    {
        var dataDirectory = ArmorAVPaths.DataDirectory;
        try
        {
            await RunAsync(args, dataDirectory);
        }
        catch (Exception ex)
        {
            File.AppendAllText(Path.Combine(dataDirectory, "armorav-web.log"), $"{DateTime.UtcNow:O} {ex}{Environment.NewLine}");
        }
    }

    private static async Task RunAsync(string[] args, string dataDirectory)
    {
        var noBrowser = args.Any(arg => string.Equals(arg, "--no-browser", StringComparison.OrdinalIgnoreCase));
        var requestedPort = ReadPort(args);
        var fallbackUrl = requestedPort.HasValue ? $"http://127.0.0.1:{requestedPort.Value}" : "http://127.0.0.1";
        var runningUrlPath = Path.Combine(dataDirectory, "armorav-web-url.txt");
        using var instance = new Mutex(true, "ArmorAV.Web.Local", out var isFirstInstance);
        if (!isFirstInstance)
        {
            if (!noBrowser)
            {
                var activeUrl = await WaitForRunningUrlAsync(runningUrlPath);
                if (activeUrl != null) OpenBrowser(activeUrl);
            }
            return;
        }
        try { if (File.Exists(runningUrlPath)) File.Delete(runningUrlPath); }
        catch { }

        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var builder = WebApplication.CreateBuilder(args);
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, requestedPort ?? 0));
        builder.Services.AddSingleton<ScanJobs>();
        var app = builder.Build();

        app.Use(async (context, next) =>
        {
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["X-Frame-Options"] = "DENY";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
            await next();
        });
        app.UseDefaultFiles();
        app.UseStaticFiles();

        app.MapGet("/api/config", () => Results.Ok(new
        {
            token,
            product = Product.Name,
            version = Product.Version,
            locations = GetLocations()
        }));

        app.MapGet("/api/browse", (HttpRequest request, string? path) =>
        {
            if (!Authorized(request, token)) return Unauthorized();
            try
            {
                var current = ResolveBrowsePath(path);
                var directory = new DirectoryInfo(current);
                if (!directory.Exists) return Results.NotFound(new { message = "Папка не найдена." });
                var directories = directory.EnumerateDirectories()
                    .Where(item => !item.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    .Take(200)
                    .OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
                    .Select(item => new BrowseItem(item.Name, item.FullName, "directory", 0))
                    .ToList();
                var files = directory.EnumerateFiles()
                    .Where(item => !item.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    .Take(200)
                    .OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
                    .Select(item => new BrowseItem(item.Name, item.FullName, "file", item.Length))
                    .ToList();
                return Results.Ok(new BrowseResponse(current, directory.Parent?.FullName, directories, files));
            }
            catch (UnauthorizedAccessException)
            {
                return Results.Json(new { message = "Нет доступа к этой папке." }, statusCode: StatusCodes.Status403Forbidden);
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new { message = ex.Message });
            }
        });

        app.MapPost("/api/scans", (HttpRequest request, ScanCommand command, ScanJobs jobs) =>
        {
            if (!Authorized(request, token)) return Unauthorized();
            if (string.IsNullOrWhiteSpace(command.Path)) return Results.BadRequest(new { message = "Выберите файл или папку." });
            if (!File.Exists(command.Path) && !Directory.Exists(command.Path)) return Results.NotFound(new { message = "Выбранный путь не существует." });
            if (command.MaxDepth is < 0 or > 100) return Results.BadRequest(new { message = "Глубина должна быть от 0 до 100." });
            if (command.Threads is < 1 or > 64) return Results.BadRequest(new { message = "Количество потоков должно быть от 1 до 64." });
            if (!jobs.TryEnqueue(command, out var job))
                return Results.Json(new { message = "Очередь проверок заполнена. Дождитесь завершения текущей проверки." }, statusCode: StatusCodes.Status429TooManyRequests);
            return Results.Accepted($"/api/scans/{job.Id}", JobResponse.From(job));
        });

        app.MapGet("/api/scans/{id}", (HttpRequest request, string id, ScanJobs jobs) =>
        {
            if (!Authorized(request, token)) return Unauthorized();
            return jobs.TryGet(id, out var job) ? Results.Ok(JobResponse.From(job)) : Results.NotFound(new { message = "Проверка не найдена." });
        });

        app.MapGet("/api/scans/{id}/report", (HttpRequest request, string id, string? format, ScanJobs jobs) =>
        {
            if (!Authorized(request, token)) return Unauthorized();
            if (!jobs.TryGet(id, out var job) || job.Report == null) return Results.NotFound(new { message = "Отчёт ещё не готов." });
            return ReportResult(job.Report, format);
        });

        app.MapGet("/api/quarantine", (HttpRequest request) =>
        {
            if (!Authorized(request, token)) return Unauthorized();
            return Results.Ok(ArmorAVService.ListQuarantine().Select(item => new { item.Id, item.OriginalPath, item.TimestampUtc, item.Sha256, item.Score, item.Reasons }));
        });

        app.MapPost("/api/quarantine/{id}/restore", (HttpRequest request, string id) =>
        {
            if (!Authorized(request, token)) return Unauthorized();
            var restored = ArmorAVService.RestoreQuarantine(id, out var message);
            return restored ? Results.Ok(new { message }) : Results.BadRequest(new { message });
        });

        app.MapPost("/api/shutdown", (HttpRequest request, IHostApplicationLifetime lifetime) =>
        {
            if (!Authorized(request, token)) return Unauthorized();
            lifetime.StopApplication();
            return Results.Ok(new { message = "ArmorAV завершает работу." });
        });

        app.Lifetime.ApplicationStarted.Register(() =>
        {
            var activeUrl = app.Urls.FirstOrDefault(candidate => Uri.TryCreate(candidate, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback) ?? fallbackUrl;
            File.WriteAllText(runningUrlPath, activeUrl);
            if (!noBrowser) OpenBrowser(activeUrl);
        });
        app.Lifetime.ApplicationStopping.Register(() =>
        {
            try { if (File.Exists(runningUrlPath)) File.Delete(runningUrlPath); }
            catch { }
        });

        await app.RunAsync();
    }

    private static bool Authorized(HttpRequest request, string token)
    {
        var provided = request.Headers[TokenHeader].ToString();
        if (provided.Length != token.Length) return false;
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(provided), Encoding.UTF8.GetBytes(token));
    }

    private static IResult Unauthorized() => Results.Json(new { message = "Локальная сессия не авторизована." }, statusCode: StatusCodes.Status401Unauthorized);

    private static IResult ReportResult(ScanReport report, string? format)
    {
        return format?.ToLowerInvariant() switch
        {
            "html" => Results.File(Encoding.UTF8.GetBytes(Reporter.Html(report)), "text/html; charset=utf-8", "ArmorAV-report.html"),
            "csv" => Results.File(Encoding.UTF8.GetBytes(Reporter.Csv(report)), "text/csv; charset=utf-8", "ArmorAV-report.csv"),
            "sarif" => Results.File(Encoding.UTF8.GetBytes(Reporter.Sarif(report)), "application/sarif+json; charset=utf-8", "ArmorAV-report.sarif"),
            _ => Results.File(Encoding.UTF8.GetBytes(Reporter.Json(report)), "application/json; charset=utf-8", "ArmorAV-report.json")
        };
    }

    private static int? ReadPort(string[] arguments)
    {
        for (var index = 0; index < arguments.Length - 1; index++)
            if (string.Equals(arguments[index], "--port", StringComparison.OrdinalIgnoreCase) && int.TryParse(arguments[index + 1], out var port) && port is > 1024 and < 65536)
                return port;
        return null;
    }

    private static void OpenBrowser(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch { }
    }

    private static async Task<string?> WaitForRunningUrlAsync(string path)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        using var client = new HttpClient { Timeout = TimeSpan.FromMilliseconds(750) };
        while (DateTime.UtcNow < deadline)
        {
            var candidate = ReadRunningUrl(path);
            if (candidate != null)
            {
                try
                {
                    using var response = await client.GetAsync(candidate + "/api/config");
                    if (response.IsSuccessStatusCode) return candidate;
                }
                catch (HttpRequestException) { }
                catch (TaskCanceledException) { }
            }
            await Task.Delay(100);
        }
        return null;
    }

    private static string? ReadRunningUrl(string path)
    {
        try
        {
            var candidate = File.ReadAllText(path).Trim();
            return Uri.TryCreate(candidate, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback ? candidate : null;
        }
        catch
        {
            return null;
        }
    }

    private static object GetLocations()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new
        {
            home,
            downloads = ExistingDirectory(home, "Downloads"),
            documents = ExistingDirectory(home, "Documents"),
            desktop = ExistingDirectory(home, "Desktop")
        };
    }

    private static string ResolveBrowsePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.GetFullPath(path);
    }

    private static string ExistingDirectory(string root, string name)
    {
        var candidate = Path.Combine(root, name);
        return Directory.Exists(candidate) ? candidate : root;
    }

    private sealed record BrowseItem(string Name, string Path, string Kind, long Size);
    private sealed record BrowseResponse(string Path, string? ParentPath, IReadOnlyList<BrowseItem> Directories, IReadOnlyList<BrowseItem> Files);
    private sealed record ScanCommand(string Path, bool QuarantineConfirmed, bool UseCache, int? MaxDepth, int? Threads);

    private sealed class ScanJobs
    {
        private const int MaximumRetainedJobs = 12;
        private readonly ConcurrentDictionary<string, ScanJob> _jobs = new(StringComparer.Ordinal);
        private readonly SemaphoreSlim _gate = new(1, 1);
        private readonly object _jobLock = new();

        public bool TryEnqueue(ScanCommand command, out ScanJob job)
        {
            lock (_jobLock)
            {
                var removable = _jobs.Values.Where(item => item.FinishedUtc.HasValue).OrderBy(item => item.FinishedUtc).ToList();
                foreach (var completed in removable.Take(Math.Max(0, _jobs.Count - MaximumRetainedJobs + 1)))
                    _jobs.TryRemove(completed.Id, out _);
                if (_jobs.Count >= MaximumRetainedJobs)
                {
                    job = null!;
                    return false;
                }
                job = new ScanJob(Guid.NewGuid().ToString("N"), command);
                _jobs[job.Id] = job;
            }
            var queuedJob = job;
            _ = Task.Run(async () =>
            {
                await _gate.WaitAsync();
                try
                {
                    queuedJob.State = "running";
                    queuedJob.Message = "Выполняется локальный анализ…";
                    queuedJob.StartedUtc = DateTime.UtcNow;
                    queuedJob.Report = ArmorAVService.Scan(new ScanRequest
                    {
                        Path = queuedJob.Command.Path,
                        QuarantineConfirmed = queuedJob.Command.QuarantineConfirmed,
                        UseCache = queuedJob.Command.UseCache,
                        MaxDepth = queuedJob.Command.MaxDepth ?? 10,
                        Threads = queuedJob.Command.Threads ?? Math.Max(1, Environment.ProcessorCount / 2)
                    });
                    queuedJob.State = "completed";
                    queuedJob.Message = "Проверка завершена.";
                }
                catch (Exception ex)
                {
                    queuedJob.State = "failed";
                    queuedJob.Message = ex.Message;
                }
                finally
                {
                    queuedJob.FinishedUtc = DateTime.UtcNow;
                    _gate.Release();
                }
            });
            return true;
        }

        public bool TryGet(string id, out ScanJob job) => _jobs.TryGetValue(id, out job!);
    }

    private sealed class ScanJob
    {
        public ScanJob(string id, ScanCommand command)
        {
            Id = id;
            Command = command;
        }

        public string Id { get; }
        public ScanCommand Command { get; }
        public string State { get; set; } = "queued";
        public string Message { get; set; } = "Ожидание запуска…";
        public DateTime? StartedUtc { get; set; }
        public DateTime? FinishedUtc { get; set; }
        public ScanReport? Report { get; set; }
    }

    private sealed record JobResponse(string Id, string State, string Message, DateTime? StartedUtc, DateTime? FinishedUtc, ReportResponse? Report)
    {
        public static JobResponse From(ScanJob job) => new(job.Id, job.State, job.Message, job.StartedUtc, job.FinishedUtc, job.Report == null ? null : ReportResponse.From(job.Report));
    }

    private sealed record ReportResponse(string RootPath, double DurationSeconds, int FilesScanned, long BytesScanned, int Confirmed, int Suspicious, int Clean, int CacheHits, IReadOnlyList<ResultResponse> Results, IReadOnlyList<SkippedResponse> Skipped)
    {
        public static ReportResponse From(ScanReport report) => new(
            report.RootPath,
            report.DurationSeconds,
            report.FilesScanned,
            report.BytesScanned,
            report.Results.Count(item => item.VerdictText == Verdict.Confirmed.ToString()),
            report.Results.Count(item => item.VerdictText == Verdict.Suspicious.ToString()),
            report.Results.Count(item => item.VerdictText == Verdict.Clean.ToString()),
            report.CacheHits,
            report.Results.Select(ResultResponse.From).ToList(),
            report.Skipped.Select(item => new SkippedResponse(item.Path, item.Reason)).ToList());
    }

    private sealed record ResultResponse(string Path, long Size, string FileType, string Verdict, int Score, string Sha256, IReadOnlyList<FindingResponse> Findings, IReadOnlyList<string> Families, IReadOnlyList<string> Techniques, bool Quarantined, string QuarantineNote)
    {
        public static ResultResponse From(FileResult result) => new(
            result.Path,
            result.Size,
            result.FileType,
            result.VerdictText,
            result.Score,
            result.Sha256,
            result.Findings.Select(item => new FindingResponse(item.Name, item.Weight, item.Severity.ToString(), item.Family, item.Detector, item.Detail)).ToList(),
            result.Families,
            result.Techniques,
            result.Quarantined,
            result.QuarantineNote);
    }

    private sealed record FindingResponse(string Name, int Weight, string Severity, string Family, string Detector, string Detail);
    private sealed record SkippedResponse(string Path, string Reason);
}
