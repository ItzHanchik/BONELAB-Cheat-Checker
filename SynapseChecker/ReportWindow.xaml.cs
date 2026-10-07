using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using SynapseChecker.Models;
using SynapseChecker.Scanner.Reports;

namespace SynapseChecker;

public partial class ReportWindow : Window
{
    private readonly ReportPaths _paths;
    public ReportWindow(ScanReport report, ReportPaths paths)
    {
        InitializeComponent();
        _paths = paths;
        int detected = report.Findings.Count(x => x.Status == FindingStatus.Detected);
        int suspicious = report.Findings.Count(x => x.Status == FindingStatus.Suspicious);
        Summary.Text = $"{report.Result}  ·  DETECTED {detected}  ·  SUSPICIOUS {suspicious}  ·  FILES {report.Statistics.FilesInspected:N0}  ·  GAME LOGS {report.Statistics.GameLogsChecked:N0}  ·  ERRORS {report.Statistics.AccessErrors:N0}  ·  {report.Duration:hh\\:mm\\:ss}";
        if (report.Findings.Count == 0) FindingsPanel.Children.Add(new TextBlock { Text = "NO FINDINGS", FontFamily = new FontFamily("Consolas"), Foreground = Brushes.Gray });
        foreach (ScanFinding finding in report.Findings)
        {
            var details = new TextBlock { TextWrapping = TextWrapping.Wrap, Foreground = Brushes.LightGray,
                Text = $"CATEGORY  {finding.Category}\nREASON    {finding.Reason}\nLOCATION  {finding.Location}\nSHA-256   {finding.Sha256 ?? "N/A"}\nSIZE      {(finding.Size?.ToString() ?? "N/A")}\nMODIFIED  {(finding.LastModifiedUtc?.ToString("O") ?? "N/A")}\nINDICATORS {(finding.Indicators is null ? "N/A" : string.Join(", ", finding.Indicators))}" };
            FindingsPanel.Children.Add(new Expander { Header = $"[{finding.Status.ToString().ToUpperInvariant()}] {finding.Detection}", Content = details });
        }
        var events = new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            Foreground = Brushes.LightGray,
            FontFamily = new FontFamily("Consolas"),
            Text = report.Events.Count == 0 ? "NO CHECK EVENTS" : string.Join("\n", report.Events)
        };
        FindingsPanel.Children.Add(new Expander
        {
            Header = $"[CHECK LOG] {report.Events.Count:N0} EVENTS",
            Content = events,
            IsExpanded = report.Findings.Count == 0
        });
        OpenArchiveButton.Visibility = string.IsNullOrWhiteSpace(paths.ModArchive) || !File.Exists(paths.ModArchive)
            ? Visibility.Collapsed : Visibility.Visible;
    }
    private void OpenJson_Click(object sender, RoutedEventArgs e) => Open(_paths.Json);
    private void OpenText_Click(object sender, RoutedEventArgs e) => Open(_paths.Text);
    private void OpenArchive_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(_paths.ModArchive) && File.Exists(_paths.ModArchive)) Open(_paths.ModArchive);
    }
    private static void Open(string path) => Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
    private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e) { if (e.ButtonState == MouseButtonState.Pressed && e.GetPosition(this).Y < 48) DragMove(); }
}
