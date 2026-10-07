using System.IO.Compression;
using SynapseChecker.Models;

namespace SynapseChecker.Scanner.Discord;

public sealed class DiscordExportLocator
{
    private const int MaxDepth = 4;
    private const int MaxEntriesSeen = 12000;
    private const int MaxArchivesInspected = 400;
    private const int MaxPackages = 5;
    private static readonly HashSet<string> PackageSections = new(StringComparer.OrdinalIgnoreCase)
        { "account", "activity", "activities", "messages", "servers", "ads", "support_tickets" };

    public Task<IReadOnlyList<string>> DiscoverAsync(ScanReport report, CancellationToken token,
        IEnumerable<string>? searchRoots = null)
    {
        return Task.Run<IReadOnlyList<string>>(() => Discover(report, token, searchRoots), token);
    }

    private static IReadOnlyList<string> Discover(ScanReport report, CancellationToken token,
        IEnumerable<string>? searchRoots)
    {
        var found = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var queue = new Queue<(string Path, int Depth)>();
        foreach (string root in (searchRoots ?? GetDefaultRoots()).Where(Directory.Exists))
        {
            string full = Path.GetFullPath(root);
            if (seen.Add(full)) queue.Enqueue((full, 0));
        }

        int entriesSeen = 0;
        int archivesInspected = 0;
        while (queue.Count > 0 && entriesSeen < MaxEntriesSeen && found.Count < MaxPackages)
        {
            token.ThrowIfCancellationRequested();
            (string directory, int depth) = queue.Dequeue();
            report.Statistics.DiscordDiscoveryDirectoriesChecked++;

            try
            {
                if (IsPackageDirectory(directory))
                {
                    found.Add(directory);
                    continue;
                }

                foreach (string file in Directory.EnumerateFiles(directory))
                {
                    token.ThrowIfCancellationRequested();
                    if (found.Count >= MaxPackages) break;
                    if (!Path.GetExtension(file).Equals(".zip", StringComparison.OrdinalIgnoreCase)) continue;
                    if (++entriesSeen > MaxEntriesSeen || archivesInspected >= MaxArchivesInspected) break;
                    archivesInspected++;
                    report.Statistics.DiscordDiscoveryArchivesChecked++;
                    if (IsPackageArchive(file)) found.Add(Path.GetFullPath(file));
                }

                if (depth >= MaxDepth) continue;
                foreach (string child in Directory.EnumerateDirectories(directory))
                {
                    token.ThrowIfCancellationRequested();
                    if (++entriesSeen > MaxEntriesSeen) break;
                    try
                    {
                        if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) != 0) continue;
                        string full = Path.GetFullPath(child);
                        if (seen.Add(full)) queue.Enqueue((full, depth + 1));
                    }
                    catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { report.Statistics.AccessErrors++; }
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                report.Statistics.AccessErrors++;
            }
        }

        IReadOnlyList<string> result = found.Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(GetLastWriteTimeUtcSafe).Take(MaxPackages).ToArray();
        report.Statistics.DiscordPackagesFound = result.Count;
        report.Events.Add($"DISCORD_DISCOVERY | roots={seen.Count(x => GetDefaultRoots().Contains(x, StringComparer.OrdinalIgnoreCase))} | directories={report.Statistics.DiscordDiscoveryDirectoriesChecked} | archives={report.Statistics.DiscordDiscoveryArchivesChecked} | verifiedPackages={result.Count} | scope=Downloads,Desktop,Documents,OneDrive");
        return result;
    }

    internal static bool IsPackageDirectory(string path)
    {
        try
        {
            HashSet<string> sections = Directory.EnumerateDirectories(path)
                .Select(Path.GetFileName).Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x!).Where(PackageSections.Contains)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            return HasOfficialShape(sections);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { return false; }
    }

    internal static bool IsPackageArchive(string path)
    {
        try
        {
            using ZipArchive archive = ZipFile.OpenRead(path);
            var sections = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (ZipArchiveEntry entry in archive.Entries.Take(20000))
            {
                string[] parts = entry.FullName.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
                foreach (string part in parts.Take(2))
                    if (PackageSections.Contains(part)) sections.Add(part);
                if (HasOfficialShape(sections)) return true;
            }
            return false;
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException) { return false; }
    }

    private static bool HasOfficialShape(IReadOnlySet<string> sections) =>
        sections.Contains("messages") &&
        sections.Count(x => x is "account" or "activity" or "activities" or "servers" or "ads" or "support_tickets") >= 2;

    private static IEnumerable<string> GetDefaultRoots()
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        string documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        string? oneDrive = Environment.GetEnvironmentVariable("OneDrive");
        string[] candidates =
        {
            Path.Combine(profile, "Downloads"), desktop, documents,
            string.IsNullOrWhiteSpace(oneDrive) ? "" : Path.Combine(oneDrive, "Downloads"),
            string.IsNullOrWhiteSpace(oneDrive) ? "" : Path.Combine(oneDrive, "Desktop"),
            string.IsNullOrWhiteSpace(oneDrive) ? "" : Path.Combine(oneDrive, "Documents")
        };
        return candidates.Where(x => !string.IsNullOrWhiteSpace(x)).Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private static DateTime GetLastWriteTimeUtcSafe(string path)
    {
        try { return File.Exists(path) ? File.GetLastWriteTimeUtc(path) : Directory.GetLastWriteTimeUtc(path); }
        catch { return DateTime.MinValue; }
    }
}
