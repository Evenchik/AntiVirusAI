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
    private readonly ObservableCollection<ScanRow> _rows = new();
    private ScanReport? _lastReport;

    public MainWindow()
    {
        InitializeComponent();
        ResultsList.ItemsSource = _rows;
        TargetPathBox.Text = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    }

    private async void BrowseFile_Click(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Выберите файл для проверки",
            AllowMultiple = false
        });
        if (files.Count > 0) TargetPathBox.Text = files[0].Path.LocalPath;
    }

    private async void BrowseFolder_Click(object? sender, RoutedEventArgs e)
    {
        var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Выберите папку для проверки",
            AllowMultiple = false
        });
        if (folders.Count > 0) TargetPathBox.Text = folders[0].Path.LocalPath;
    }

    private async void Scan_Click(object? sender, RoutedEventArgs e)
    {
        var path = TargetPathBox.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(path) || (!File.Exists(path) && !Directory.Exists(path)))
        {
            StatusText.Text = "Укажите существующий файл или папку.";
            return;
        }

        SetScanningState(true);
        StatusText.Text = "Анализ выполняется локально…";
        SummaryText.Text = "Сканирование…";
        _rows.Clear();
        try
        {
            _lastReport = await Task.Run(() => ArmorAVService.Scan(new ScanRequest
            {
                Path = path,
                QuarantineConfirmed = QuarantineCheckBox.IsChecked == true,
                UseCache = CacheCheckBox.IsChecked == true
            }));
            RenderReport(_lastReport);
            StatusText.Text = "Сканирование завершено.";
        }
        catch (Exception ex)
        {
            _lastReport = null;
            SummaryText.Text = "Не удалось завершить сканирование";
            MetricsText.Text = ex.Message;
            StatusText.Text = "Ошибка сканирования.";
        }
        finally
        {
            SetScanningState(false);
        }
    }

    private void RenderReport(ScanReport report)
    {
        var confirmed = report.Results.Count(x => x.VerdictText == Verdict.Confirmed.ToString());
        var suspicious = report.Results.Count(x => x.VerdictText == Verdict.Suspicious.ToString());
        var clean = report.Results.Count(x => x.VerdictText == Verdict.Clean.ToString());
        SummaryText.Text = $"Подтверждено: {confirmed}   Подозрительно: {suspicious}   Чисто: {clean}";
        MetricsText.Text = $"Проверено: {report.FilesScanned} файл(ов), {Util.HumanSize(report.BytesScanned)}, " +
                           $"{report.DurationSeconds:F2} с, кэш: {report.CacheHits}, пропущено: {report.Skipped.Count}.";

        foreach (var result in report.Results)
        {
            var names = result.Findings.Take(3).Select(f => f.Name);
            var findings = result.Findings.Count == 0 ? "Нет срабатываний." : string.Join(" · ", names);
            if (result.Findings.Count > 3) findings += $" · и ещё {result.Findings.Count - 3}";
            _rows.Add(new ScanRow(
                $"{result.VerdictText.ToUpperInvariant()}  •  {result.Score}  •  {result.FileType}  •  {result.Path}",
                $"{findings}{(string.IsNullOrEmpty(result.QuarantineNote) ? "" : "  |  " + result.QuarantineNote)}"));
        }
        foreach (var skipped in report.Skipped)
            _rows.Add(new ScanRow($"ПРОПУЩЕН  •  {skipped.Path}", skipped.Reason));

        ExportJsonButton.IsEnabled = true;
        ExportHtmlButton.IsEnabled = true;
    }

    private void SetScanningState(bool scanning)
    {
        ScanButton.IsEnabled = !scanning;
        ExportJsonButton.IsEnabled = !scanning && _lastReport != null;
        ExportHtmlButton.IsEnabled = !scanning && _lastReport != null;
        ScanProgress.IsIndeterminate = scanning;
    }

    private async void ExportJson_Click(object? sender, RoutedEventArgs e) => await ExportAsync("json", "ArmorAV-report.json", ArmorAVService.ExportJson);
    private async void ExportHtml_Click(object? sender, RoutedEventArgs e) => await ExportAsync("html", "ArmorAV-report.html", ArmorAVService.ExportHtml);

    private async Task ExportAsync(string extension, string suggestedName, Action<ScanReport, string> exporter)
    {
        if (_lastReport == null) return;
        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Сохранить отчёт ArmorAV",
            SuggestedFileName = suggestedName,
            DefaultExtension = extension
        });
        if (file == null) return;

        try
        {
            exporter(_lastReport, file.Path.LocalPath);
            StatusText.Text = "Отчёт сохранён: " + file.Path.LocalPath;
        }
        catch (Exception ex)
        {
            StatusText.Text = "Не удалось сохранить отчёт: " + ex.Message;
        }
    }

    public sealed record ScanRow(string Headline, string Details);
}
