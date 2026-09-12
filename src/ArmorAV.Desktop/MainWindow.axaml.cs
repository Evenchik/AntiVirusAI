using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using ArmorAV;

namespace ArmorAV.Desktop;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<ScanRow> _results = new();
    private readonly ObservableCollection<QuarantineRow> _quarantine = new();
    private ScanReport? _lastReport;

    public MainWindow()
    {
        InitializeComponent();
        DashboardResultsList.ItemsSource = _results;
        ScanResultsList.ItemsSource = _results;
        QuarantineList.ItemsSource = _quarantine;
        TargetPathBox.Text = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    }

    private void Dashboard_Click(object? sender, RoutedEventArgs e) => ShowPage(Page.Dashboard);
    private void ScanPage_Click(object? sender, RoutedEventArgs e) => ShowPage(Page.Scan);
    private async void Quarantine_Click(object? sender, RoutedEventArgs e)
    {
        ShowPage(Page.Quarantine);
        await LoadQuarantineAsync();
    }
    private void Reports_Click(object? sender, RoutedEventArgs e) => ShowPage(Page.Reports);
    private void StartFromHeader_Click(object? sender, RoutedEventArgs e) => ShowPage(Page.Scan);

    private void ShowPage(Page page)
    {
        DashboardPanel.IsVisible = page == Page.Dashboard;
        ScanPanel.IsVisible = page == Page.Scan;
        QuarantinePanel.IsVisible = page == Page.Quarantine;
        ReportsPanel.IsVisible = page == Page.Reports;

        SetActive(DashboardButton, page == Page.Dashboard);
        SetActive(ScanButtonNav, page == Page.Scan);
        SetActive(QuarantineButton, page == Page.Quarantine);
        SetActive(ReportsButton, page == Page.Reports);

        switch (page)
        {
            case Page.Dashboard:
                PageTitleText.Text = "Панель безопасности";
                PageSubtitleText.Text = "Контроль локальных проверок и результатов анализа";
                break;
            case Page.Scan:
                PageTitleText.Text = "Новая проверка";
                PageSubtitleText.Text = "Выберите файл или папку для статического анализа";
                break;
            case Page.Quarantine:
                PageTitleText.Text = "Карантин";
                PageSubtitleText.Text = "Безопасное локальное хранилище подтверждённых угроз";
                break;
            case Page.Reports:
                PageTitleText.Text = "Отчёты";
                PageSubtitleText.Text = "Экспортируйте результаты последней проверки";
                break;
        }
    }

    private static void SetActive(Button button, bool active)
    {
        if (active)
        {
            if (!button.Classes.Contains("active")) button.Classes.Add("active");
        }
        else
        {
            button.Classes.Remove("active");
        }
    }

    private async void BrowseFile_Click(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Выберите файл для проверки", AllowMultiple = false });
        if (files.Count > 0) TargetPathBox.Text = files[0].Path.LocalPath;
    }

    private async void BrowseFolder_Click(object? sender, RoutedEventArgs e)
    {
        var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = "Выберите папку для проверки", AllowMultiple = false });
        if (folders.Count > 0) TargetPathBox.Text = folders[0].Path.LocalPath;
    }

    private async void Scan_Click(object? sender, RoutedEventArgs e)
    {
        var path = TargetPathBox.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(path) || (!File.Exists(path) && !Directory.Exists(path)))
        {
            ScanSummaryText.Text = "Нужен существующий файл или папка";
            ScanMetricsText.Text = "Проверьте путь и повторите попытку.";
            return;
        }

        SetScanningState(true);
        _results.Clear();
        ResultDetailsText.Text = "ArmorAV анализирует выбранный объект локально…";
        ScanSummaryText.Text = "Выполняется анализ";
        ScanMetricsText.Text = "Сканирование может занять некоторое время для больших архивов и папок.";
        HeaderStatusText.Text = "Проверка выполняется";
        try
        {
            _lastReport = await Task.Run(() => ArmorAVService.Scan(new ScanRequest
            {
                Path = path,
                QuarantineConfirmed = QuarantineCheckBox.IsChecked == true,
                UseCache = CacheCheckBox.IsChecked == true
            }));
            RenderReport(_lastReport);
            HeaderStatusText.Text = "Проверка завершена";
            DashboardStateText.Text = _lastReport.Results.Any(r => r.VerdictText == Verdict.Confirmed.ToString())
                ? "Обнаружены подтверждённые угрозы"
                : "Последняя проверка завершена";
        }
        catch (Exception ex)
        {
            _lastReport = null;
            ScanSummaryText.Text = "Не удалось завершить проверку";
            ScanMetricsText.Text = ex.Message;
            HeaderStatusText.Text = "Ошибка проверки";
            DashboardStateText.Text = "Требуется повторить проверку";
        }
        finally
        {
            SetScanningState(false);
        }
    }

    private void RenderReport(ScanReport report)
    {
        var confirmed = report.Results.Count(r => r.VerdictText == Verdict.Confirmed.ToString());
        var suspicious = report.Results.Count(r => r.VerdictText == Verdict.Suspicious.ToString());
        var clean = report.Results.Count(r => r.VerdictText == Verdict.Clean.ToString());
        StatusMetricText.Text = confirmed > 0 ? "Внимание" : "Защищено";
        ScannedMetricText.Text = report.FilesScanned.ToString();
        ThreatMetricText.Text = confirmed.ToString();
        DurationMetricText.Text = $"{report.DurationSeconds:F1} с";
        ScanSummaryText.Text = $"Подтверждено: {confirmed}   Подозрительно: {suspicious}   Чисто: {clean}";
        ScanMetricsText.Text = $"Проверено {report.FilesScanned} файл(ов) · {Util.HumanSize(report.BytesScanned)} · кэш: {report.CacheHits} · пропущено: {report.Skipped.Count}";

        foreach (var result in report.Results)
        {
            var summary = result.Findings.Count == 0
                ? "Срабатываний нет"
                : string.Join(" · ", result.Findings.Take(4).Select(f => f.Name));
            _results.Add(new ScanRow(result.VerdictText.ToUpperInvariant(), result.Score.ToString(), result.FileType, result.Path, summary, result));
        }
        foreach (var skipped in report.Skipped)
            _results.Add(new ScanRow("ПРОПУЩЕН", "—", "", skipped.Path, skipped.Reason, null));

        SetExportState(true);
    }

    private void ScanResults_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (ScanResultsList.SelectedItem is not ScanRow row)
        {
            ResultDetailsText.Text = "Выберите строку в результатах, чтобы увидеть срабатывания.";
            return;
        }
        if (row.Result == null)
        {
            ResultDetailsText.Text = row.Summary;
            return;
        }

        var findings = row.Result.Findings.Count == 0
            ? "Срабатываний нет."
            : string.Join(Environment.NewLine, row.Result.Findings.Select(f => $"{f.Severity} · {f.Name} · {f.Detail}"));
        ResultDetailsText.Text = $"SHA-256: {row.Result.Sha256}{Environment.NewLine}{Environment.NewLine}{findings}";
    }

    private async void RefreshQuarantine_Click(object? sender, RoutedEventArgs e) => await LoadQuarantineAsync();

    private async Task LoadQuarantineAsync()
    {
        QuarantineInfoText.Text = "Загрузка объектов карантина…";
        RestoreButton.IsEnabled = false;
        try
        {
            var records = await Task.Run(() => ArmorAVService.ListQuarantine());
            _quarantine.Clear();
            foreach (var record in records)
                _quarantine.Add(new QuarantineRow(record, record.OriginalPath, $"{record.TimestampUtc} · SHA-256 {record.Sha256}"));
            QuarantineInfoText.Text = records.Count == 0 ? "Карантин пуст." : $"Объектов в карантине: {records.Count}.";
        }
        catch (Exception ex)
        {
            QuarantineInfoText.Text = "Не удалось прочитать карантин: " + ex.Message;
        }
    }

    private void Quarantine_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (QuarantineList.SelectedItem is QuarantineRow row)
        {
            QuarantineInfoText.Text = $"Выбран объект {row.Record.Id}. Восстановление вернёт его по исходному пути, только если файл там отсутствует.";
            RestoreButton.IsEnabled = true;
        }
        else
        {
            RestoreButton.IsEnabled = false;
        }
    }

    private async void Restore_Click(object? sender, RoutedEventArgs e)
    {
        if (QuarantineList.SelectedItem is not QuarantineRow row) return;
        RestoreButton.IsEnabled = false;
        QuarantineInfoText.Text = "Восстановление и проверка целостности…";
        var outcome = await Task.Run(() =>
        {
            var ok = ArmorAVService.RestoreQuarantine(row.Record.Id, out var message);
            return (ok, message);
        });
        QuarantineInfoText.Text = outcome.message;
        await LoadQuarantineAsync();
    }

    private void SetScanningState(bool scanning)
    {
        RunScanButton.IsEnabled = !scanning;
        ScanButtonNav.IsEnabled = !scanning;
        ScanProgress.IsIndeterminate = scanning;
        SetExportState(!scanning && _lastReport != null);
    }

    private void SetExportState(bool enabled)
    {
        ExportJsonButton.IsEnabled = enabled;
        ExportHtmlButton.IsEnabled = enabled;
        ExportCsvButton.IsEnabled = enabled;
        ExportSarifButton.IsEnabled = enabled;
    }

    private async void ExportJson_Click(object? sender, RoutedEventArgs e) => await ExportAsync("json", "ArmorAV-report.json", ArmorAVService.ExportJson);
    private async void ExportHtml_Click(object? sender, RoutedEventArgs e) => await ExportAsync("html", "ArmorAV-report.html", ArmorAVService.ExportHtml);
    private async void ExportCsv_Click(object? sender, RoutedEventArgs e) => await ExportAsync("csv", "ArmorAV-report.csv", ArmorAVService.ExportCsv);
    private async void ExportSarif_Click(object? sender, RoutedEventArgs e) => await ExportAsync("sarif", "ArmorAV-report.sarif", ArmorAVService.ExportSarif);

    private async Task ExportAsync(string extension, string suggestedName, Action<ScanReport, string> exporter)
    {
        if (_lastReport == null) return;
        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions { Title = "Сохранить отчёт ArmorAV", SuggestedFileName = suggestedName, DefaultExtension = extension });
        if (file == null) return;
        try
        {
            exporter(_lastReport, file.Path.LocalPath);
            HeaderStatusText.Text = "Отчёт сохранён";
        }
        catch (Exception ex)
        {
            HeaderStatusText.Text = "Ошибка сохранения: " + ex.Message;
        }
    }

    private enum Page { Dashboard, Scan, Quarantine, Reports }

    public sealed record ScanRow(string Verdict, string ScoreText, string FileType, string Path, string Summary, FileResult? Result);
    public sealed record QuarantineRow(QuarantineRecord Record, string Headline, string Details);
}
