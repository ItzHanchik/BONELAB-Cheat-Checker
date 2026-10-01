using System.Diagnostics;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using BoneZAntiCheat.Models;
using BoneZAntiCheat.Scanner;
using BoneZAntiCheat.Scanner.Reports;

namespace BoneZAntiCheat;

public partial class MainWindow : Window
{
    private readonly ScanCoordinator _scanner;
    private CancellationTokenSource? _cancellation;
    private ScanReport? _report;
    private ReportPaths? _paths;
    private readonly Stopwatch _scanWatch = new();
    private readonly DispatcherTimer _elapsedTimer;

    public MainWindow()
    {
        InitializeComponent();
        _scanner = new ScanCoordinator(Path.Combine(AppContext.BaseDirectory, "signatures"));
        _elapsedTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _elapsedTimer.Tick += (_, _) => ScanElapsed.Text = _scanWatch.Elapsed.ToString(@"mm\:ss");
        Closing += (_, _) => _cancellation?.Cancel();
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        if (_cancellation is not null) return;
        IdleView.Visibility = Visibility.Collapsed;
        ResultView.Visibility = Visibility.Collapsed;
        ScanView.Visibility = Visibility.Visible;
        WindowControls.Visibility = Visibility.Collapsed;
        ((Storyboard)FindResource("Spin")).Begin(this, true);
        _cancellation = new CancellationTokenSource();
        _scanWatch.Restart();
        _elapsedTimer.Start();
        ScanPhase.Text = "STARTING";
        ScanCounters.Text = "0 FILES  ·  0 DIRECTORIES";
        var progress = new Progress<ScanProgress>(p =>
        {
            ScanPhase.Text = p.Phase;
            ScanCounters.Text = $"{p.FilesSeen:N0} SEEN  ·  {p.FilesInspected:N0} CHECKED  ·  {p.DirectoriesSeen:N0} DIRS";
        });
        try
        {
            CancellationToken token = _cancellation.Token;
            (_report, _paths) = await Task.Run(() => _scanner.ScanAsync(progress, token), token);
            ShowResult(_report);
            if (!string.IsNullOrWhiteSpace(_paths.ModArchive) && File.Exists(_paths.ModArchive))
            {
                Process.Start(new ProcessStartInfo(_paths.ModArchive) { UseShellExecute = true });
            }
        }
        catch (OperationCanceledException)
        {
            IdleView.Visibility = Visibility.Visible;
            ScanView.Visibility = Visibility.Collapsed;
        }
        catch (Exception ex)
        {
            _report = new ScanReport { StartedAtUtc = DateTime.UtcNow, FinishedAtUtc = DateTime.UtcNow };
            _report.Events.Add("FATAL | " + ex);
            ResultTitle.Text = "SCAN FAILED";
            ResultTitle.Foreground = Brushes.White;
            ResultCounts.Text = ex.Message;
            ResultView.Visibility = Visibility.Visible;
            ScanView.Visibility = Visibility.Collapsed;
        }
        finally
        {
            ((Storyboard)FindResource("Spin")).Stop(this);
            _scanWatch.Stop();
            _elapsedTimer.Stop();
            WindowControls.Visibility = Visibility.Visible;
            _cancellation.Dispose();
            _cancellation = null;
        }
    }

    private void CancelScan_Click(object sender, RoutedEventArgs e)
    {
        if (_cancellation is null) return;
        ScanPhase.Text = "STOPPING";
        _cancellation.Cancel();
    }

    private void ShowResult(ScanReport report)
    {
        int detected = report.Findings.Count(x => x.Status == FindingStatus.Detected);
        int suspicious = report.Findings.Count(x => x.Status == FindingStatus.Suspicious);
        ResultTitle.Text = detected > 0 ? "THREATS DETECTED" : suspicious > 0 ? "SUSPICIOUS ITEMS" : "NO THREATS";
        ResultTitle.Foreground = detected > 0 ? new SolidColorBrush(Color.FromRgb(255, 75, 75)) : Brushes.White;
        ResultCounts.Text = $"DETECTED {detected}  ·  SUSPICIOUS {suspicious}  ·  FILES {report.Statistics.FilesInspected:N0}  ·  MOD DLL {report.Statistics.ModDllsFound:N0} / C# FILES {report.Statistics.ModSourceFilesWritten:N0}  ·  STEAM {report.Statistics.SteamAccountsChecked:N0}  ·  DISCORD {report.Statistics.DiscordPackagesFound:N0} PKG / {report.Statistics.DiscordMessagesChecked:N0} RECORDS\n{report.Duration:hh\\:mm\\:ss}";
        ScanView.Visibility = Visibility.Collapsed;
        ResultView.Visibility = Visibility.Visible;
    }

    private void ViewReport_Click(object sender, RoutedEventArgs e)
    {
        if (_report is not null && _paths is not null) new ReportWindow(_report, _paths) { Owner = this }.ShowDialog();
    }

    private void Discord_Click(object sender, RoutedEventArgs e) =>
        Process.Start(new ProcessStartInfo("https://discord.gg/pAg7XZa5AF") { UseShellExecute = true });
    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
    private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed && e.GetPosition(this).Y < 48) DragMove();
    }
}
