using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using ArmorAV;

var port = ReadPort(args, 5088);
var noBrowser = args.Any(arg => string.Equals(arg, "--no-browser", StringComparison.OrdinalIgnoreCase));
using var instance = new Mutex(true, "ArmorAV.Web.Local", out var isFirstInstance);
if (!isFirstInstance)
{
    if (!noBrowser)
    {
        try { Process.Start(new ProcessStartInfo($"http://127.0.0.1:{port}") { UseShellExecute = true }); }
        catch { }
    }
    return;
}

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls($"http://127.0.0.1:{port}");
builder.Services.AddSingleton<ScanJobs>();

var app = builder.Build();
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/health", () => Results.Ok(new { product = Product.Name, version = Product.Version, dataDirectory = ArmorAVPaths.DataDirectory }));
app.MapPost("/api/shutdown", (IHostApplicationLifetime lifetime) =>
{
    lifetime.StopApplication();
    return Results.Ok(new { message = "ArmorAV завершает работу." });
});

app.MapGet("/api/locations", () =>
{
    var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    return Results.Ok(new
    {
        home,
        downloads = ExistingDirectory(home, "Downloads"),
        documents = ExistingDirectory(home, "Documents"),
        desktop = ExistingDirectory(home, "Desktop")
    });
});

app.MapGet("/api/browse", (string? path) =>
{
    try
    {
        var current = ResolveBrowsePath(path);
        var directory = new DirectoryInfo(current);
        if (!directory.Exists) return Results.NotFound(new { message = "Папка не найдена." });

        var directories = directory.EnumerateDirectories()
            .Where(item => !item.Attributes.HasFlag(FileAttributes.ReparsePoint))
            .OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
            .Take(200)
            .Select(item => new BrowseItem(item.Name, item.FullName, "directory", 0))
            .ToList();
        var files = directory.EnumerateFiles()
            .Where(item => !item.Attributes.HasFlag(FileAttributes.ReparsePoint))
            .OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
            .Take(200)
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

app.MapPost("/api/scans", (ScanCommand command, ScanJobs jobs) =>
{
    if (string.IsNullOrWhiteSpace(command.Path)) return Results.BadRequest(new { message = "Выберите файл или папку." });
    if (!File.Exists(command.Path) && !Directory.Exists(command.Path)) return Results.NotFound(new { message = "Выбранный путь не существует." });
    if (command.MaxDepth is < 0 or > 100) return Results.BadRequest(new { message = "Глубина должна быть от 0 до 100." });
    if (command.Threads is < 1 or > 64) return Results.BadRequest(new { message = "Количество потоков должно быть от 1 до 64." });

    var job = jobs.Enqueue(command);
    return Results.Accepted($"/api/scans/{job.Id}", JobResponse.From(job));
});

app.MapGet("/api/scans/{id}", (string id, ScanJobs jobs) => jobs.TryGet(id, out var job)
    ? Results.Ok(JobResponse.From(job))
    : Results.NotFound(new { message = "Проверка не найдена." }));

app.MapGet("/api/scans/{id}/report", (string id, string? format, ScanJobs jobs) =>
{
    if (!jobs.TryGet(id, out var job) || job.Report == null) return Results.NotFound(new { message = "Отчёт ещё не готов." });
    var report = job.Report;
    return format?.ToLowerInvariant() switch
    {
        "html" => Results.File(Encoding.UTF8.GetBytes(Reporter.Html(report)), "text/html; charset=utf-8", "ArmorAV-report.html"),
        "csv" => Results.File(Encoding.UTF8.GetBytes(Reporter.Csv(report)), "text/csv; charset=utf-8", "ArmorAV-report.csv"),
        "sarif" => Results.File(Encoding.UTF8.GetBytes(Reporter.Sarif(report)), "application/sarif+json; charset=utf-8", "ArmorAV-report.sarif"),
        _ => Results.File(Encoding.UTF8.GetBytes(Reporter.Json(report)), "application/json; charset=utf-8", "ArmorAV-report.json")
    };
});

app.MapGet("/api/quarantine", () => Results.Ok(ArmorAVService.ListQuarantine().Select(item => new { item.Id, item.OriginalPath, item.TimestampUtc, item.Sha256, item.Score, item.Reasons })));

app.MapPost("/api/quarantine/{id}/restore", (string id) =>
{
    var restored = ArmorAVService.RestoreQuarantine(id, out var message);
    return restored ? Results.Ok(new { message }) : Results.BadRequest(new { message });
});

app.Lifetime.ApplicationStarted.Register(() =>
{
    if (noBrowser) return;
    var url = app.Urls.FirstOrDefault() ?? $"http://127.0.0.1:{port}";
    _ = Task.Run(async () =>
    {
        await Task.Delay(250);
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch { }
    });
});

app.Run();

static int ReadPort(string[] arguments, int fallback)
{
    for (var index = 0; index < arguments.Length - 1; index++)
        if (string.Equals(arguments[index], "--port", StringComparison.OrdinalIgnoreCase) && int.TryParse(arguments[index + 1], out var port) && port is > 1024 and < 65536)
            return port;
    return fallback;
}

static string ResolveBrowsePath(string? path)
{
    if (string.IsNullOrWhiteSpace(path)) return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    return Path.GetFullPath(path);
}

static string ExistingDirectory(string root, string name)
{
    var candidate = Path.Combine(root, name);
    return Directory.Exists(candidate) ? candidate : root;
}

sealed record BrowseItem(string Name, string Path, string Kind, long Size);
sealed record BrowseResponse(string Path, string? ParentPath, IReadOnlyList<BrowseItem> Directories, IReadOnlyList<BrowseItem> Files);
sealed record ScanCommand(string Path, bool QuarantineConfirmed, bool UseCache, int? MaxDepth, int? Threads);

sealed class ScanJobs
{
    private readonly ConcurrentDictionary<string, ScanJob> _jobs = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _gate = new(1, 1);

    public ScanJob Enqueue(ScanCommand command)
    {
        var job = new ScanJob(Guid.NewGuid().ToString("N"), command);
        _jobs[job.Id] = job;
        _ = Task.Run(async () =>
        {
            await _gate.WaitAsync();
            try
            {
                job.State = "running";
                job.Message = "Выполняется локальный анализ…";
                job.StartedUtc = DateTime.UtcNow;
                job.Report = ArmorAVService.Scan(new ScanRequest
                {
                    Path = job.Command.Path,
                    QuarantineConfirmed = job.Command.QuarantineConfirmed,
                    UseCache = job.Command.UseCache,
                    MaxDepth = job.Command.MaxDepth ?? 10,
                    Threads = job.Command.Threads ?? Math.Max(1, Environment.ProcessorCount / 2)
                });
                job.State = "completed";
                job.Message = "Проверка завершена.";
            }
            catch (Exception ex)
            {
                job.State = "failed";
                job.Message = ex.Message;
            }
            finally
            {
                job.FinishedUtc = DateTime.UtcNow;
                _gate.Release();
            }
        });
        return job;
    }

    public bool TryGet(string id, out ScanJob job) => _jobs.TryGetValue(id, out job!);
}

sealed class ScanJob
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

sealed record JobResponse(string Id, string State, string Message, DateTime? StartedUtc, DateTime? FinishedUtc, ReportResponse? Report)
{
    public static JobResponse From(ScanJob job) => new(job.Id, job.State, job.Message, job.StartedUtc, job.FinishedUtc, job.Report == null ? null : ReportResponse.From(job.Report));
}

sealed record ReportResponse(string RootPath, double DurationSeconds, int FilesScanned, long BytesScanned, int Confirmed, int Suspicious, int Clean, int CacheHits, IReadOnlyList<ResultResponse> Results, IReadOnlyList<SkippedResponse> Skipped)
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

sealed record ResultResponse(string Path, long Size, string FileType, string Verdict, int Score, string Sha256, IReadOnlyList<FindingResponse> Findings, IReadOnlyList<string> Families, IReadOnlyList<string> Techniques, bool Quarantined, string QuarantineNote)
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

sealed record FindingResponse(string Name, int Weight, string Severity, string Family, string Detector, string Detail);
sealed record SkippedResponse(string Path, string Reason);
