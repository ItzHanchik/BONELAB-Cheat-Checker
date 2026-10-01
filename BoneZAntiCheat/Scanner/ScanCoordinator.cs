using BoneZAntiCheat.Models;
using BoneZAntiCheat.Scanner.Discord;
using BoneZAntiCheat.Scanner.FileSystem;
using BoneZAntiCheat.Scanner.Hashes;
using BoneZAntiCheat.Scanner.Logs;
using BoneZAntiCheat.Scanner.Mods;
using BoneZAntiCheat.Scanner.Processes;
using BoneZAntiCheat.Scanner.Reports;
using BoneZAntiCheat.Scanner.Signatures;
using BoneZAntiCheat.Scanner.Startup;
using BoneZAntiCheat.Scanner.Steam;

namespace BoneZAntiCheat.Scanner;

public sealed class ScanCoordinator
{
    private readonly FileSystemScanner _files;
    private readonly ProcessScanner _processes;
    private readonly StartupScanner _startup;
    private readonly DiscordArtifactScanner _discord;
    private readonly DiscordExportScanner _discordExport;
    private readonly DiscordExportLocator _discordExportLocator = new();
    private readonly GameLogScanner _gameLogs;
    private readonly SteamAccountScanner _steamAccounts;
    private readonly ModAssemblyScanner _modAssemblies;
    private readonly ReportWriter _reports = new();

    public ScanCoordinator(string signatureDirectory)
    {
        var database = new SignatureDatabase(signatureDirectory);
        var hashes = new HashMatcher(database);
        _files = new(database, hashes);
        _modAssemblies = new(_files, database);
        _processes = new(database, _files);
        _startup = new(database, _files);
        _discord = new(database, _files);
        _discordExport = new(database);
        _gameLogs = new(database);
        _steamAccounts = new(signatureDirectory);
    }

    public async Task<(ScanReport Report, ReportPaths Paths)> ScanAsync(
        IProgress<ScanProgress>? progress, CancellationToken token, IEnumerable<string>? rootOverride = null)
    {
        List<string> roots = (rootOverride ?? GetLocalDisks()).Where(Directory.Exists)
            .Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var report = new ScanReport { StartedAtUtc = DateTime.UtcNow, Disks = roots };
        try
        {
            progress?.Report(FileSystemScanner.ToProgress(report, "PROCESSES", "Running processes"));
            await _processes.ScanAsync(report, token);
            progress?.Report(FileSystemScanner.ToProgress(report, "STARTUP", "Startup entries"));
            await _startup.ScanAsync(report, token);
            progress?.Report(FileSystemScanner.ToProgress(report, "DISCORD", "Local Discord artifacts"));
            await _discord.ScanAsync(report, token);
            progress?.Report(FileSystemScanner.ToProgress(report, "DISCORD FIND", "Downloads · Desktop · Documents · OneDrive"));
            IReadOnlyList<string> discordPackages = await _discordExportLocator.DiscoverAsync(report, token);
            progress?.Report(FileSystemScanner.ToProgress(report, "DISCORD EXPORT", discordPackages.Count == 0 ? "No verified package found" : $"{discordPackages.Count} verified package(s)"));
            if (discordPackages.Count == 0) await _discordExport.ScanAsync(null, report, token, false);
            foreach (string package in discordPackages)
                await _discordExport.ScanAsync(package, report, token, false);
            progress?.Report(FileSystemScanner.ToProgress(report, "STEAM ACCOUNT", "Project ban snapshot"));
            await _steamAccounts.ScanAsync(report, token);
            progress?.Report(FileSystemScanner.ToProgress(report, "GAME LOGS", "BONELAB / MelonLoader / Fusion logs"));
            await _gameLogs.ScanAsync(report, progress, token);
            progress?.Report(FileSystemScanner.ToProgress(report, "MOD DLL AUDIT", "Mods + suspicious DLLs across BONELAB"));
            await _modAssemblies.ScanAsync(report, progress, token);
            progress?.Report(FileSystemScanner.ToProgress(report, "FILES", string.Join(" · ", roots)));
            await _files.ScanAsync(roots, report, progress, token);
        }
        finally
        {
            report.FinishedAtUtc = DateTime.UtcNow;
        }
        ReportPaths paths = await _reports.WriteAsync(report, CancellationToken.None);
        return (report, paths);
    }

    private static IEnumerable<string> GetLocalDisks() => DriveInfo.GetDrives()
        .Where(x => x.IsReady && x.DriveType == DriveType.Fixed)
        .Select(x => x.RootDirectory.FullName);
}
