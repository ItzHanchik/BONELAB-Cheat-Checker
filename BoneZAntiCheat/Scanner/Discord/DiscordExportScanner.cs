using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using BoneZAntiCheat.Models;
using BoneZAntiCheat.Scanner.FileSystem;
using BoneZAntiCheat.Scanner.Signatures;

namespace BoneZAntiCheat.Scanner.Discord;

public sealed class DiscordExportScanner
{
    private const long MaxEntryBytes = 8L * 1024 * 1024;
    private const long MaxTotalBytes = 128L * 1024 * 1024;
    private const int MaxFindings = 50;
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".json", ".csv", ".txt", ".html", ".htm", ".md" };
    private static readonly (string Name, string Value)[] StrongTerms =
    {
        ("ALTClient", "altclient"), ("Pavelmenu", "pavelmenu"), ("FusionFucker", "fusionfuck"),
        ("Spawn Lab", "spawn lab"), ("SpawnLab", "spawnlab"), ("Kill All", "kill all"),
        ("Despawn All", "despawn all"), ("Clean Scene", "clean scene"), ("Lag Server", "lag server"),
        ("SceneCleaner", "scenecleaner"), ("TeleportAll", "teleportallrequestdata"),
        ("DamageAll", "damageallplayers"), ("Rigspam", "rigspam"), ("HideFromPlayerList", "hidefromplayerlist")
    };
    private static readonly Regex Transfer = new(
        "(?i)(?:https?://|attachment|filename|file).{0,180}\\.(?:dll|melon|asi|zip|rar|7z)(?:\\b|[?&\\\"])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public DiscordExportScanner(SignatureDatabase database)
    {
        // Keep the constructor tied to the same signed/static database lifecycle.
        _ = database.Indicators.Count;
    }

    public async Task ScanAsync(string? exportPath, ScanReport report, CancellationToken token, bool selectedByUser = true)
    {
        if (string.IsNullOrWhiteSpace(exportPath))
        {
            report.Events.Add("DISCORD_EXPORT | no verified package found; live Discord account, tokens and private client databases were not accessed");
            return;
        }

        string fullPath = Path.GetFullPath(exportPath);
        report.Statistics.DiscordExportsChecked++;
        long total = 0;
        if (Directory.Exists(fullPath))
        {
            foreach (string file in Directory.EnumerateFiles(fullPath, "*", SearchOption.AllDirectories))
            {
                token.ThrowIfCancellationRequested();
                if (!TextExtensions.Contains(Path.GetExtension(file))) continue;
                var info = new FileInfo(file);
                if (info.Length > MaxEntryBytes || total + info.Length > MaxTotalBytes) continue;
                total += info.Length;
                await InspectTextAsync(file, await File.ReadAllTextAsync(file, token), report, token);
            }
        }
        else if (File.Exists(fullPath) && Path.GetExtension(fullPath).Equals(".zip", StringComparison.OrdinalIgnoreCase))
        {
            using ZipArchive archive = ZipFile.OpenRead(fullPath);
            foreach (ZipArchiveEntry entry in archive.Entries.Take(20000))
            {
                token.ThrowIfCancellationRequested();
                if (!TextExtensions.Contains(Path.GetExtension(entry.FullName)) || entry.Length > MaxEntryBytes || total + entry.Length > MaxTotalBytes) continue;
                total += entry.Length;
                await using Stream stream = entry.Open();
                using var reader = new StreamReader(stream, Encoding.UTF8, true, 8192, false);
                await InspectTextAsync(fullPath + " :: " + entry.FullName, await reader.ReadToEndAsync(token), report, token);
            }
        }
        else if (File.Exists(fullPath) && TextExtensions.Contains(Path.GetExtension(fullPath)))
        {
            var info = new FileInfo(fullPath);
            if (info.Length <= MaxEntryBytes) await InspectTextAsync(fullPath, await File.ReadAllTextAsync(fullPath, token), report, token);
        }
        else throw new InvalidDataException("Select a Discord data ZIP, JSON/CSV/TXT/HTML export, or extracted export folder.");

        report.Events.Add($"DISCORD_EXPORT | selectedByUser={selectedByUser.ToString().ToLowerInvariant()} | package={Path.GetFileName(fullPath)} | channels={report.Statistics.DiscordChannelsChecked} | records={report.Statistics.DiscordMessagesChecked} | bytes={total} | message text is not stored in reports; received messages are checked only when present in the export");
    }

    private static Task InspectTextAsync(string location, string text, ScanReport report, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        report.Statistics.DiscordMessagesChecked += Math.Max(1, text.Count(x => x == '\n'));
        if (location.Contains("channel", StringComparison.OrdinalIgnoreCase) || location.Contains("message", StringComparison.OrdinalIgnoreCase))
            report.Statistics.DiscordChannelsChecked++;
        if (report.Findings.Count(x => x.Category == "DISCORD_EXPORT") >= MaxFindings) return Task.CompletedTask;

        List<string> indicators = StrongTerms.Where(x => text.Contains(x.Value, StringComparison.OrdinalIgnoreCase))
            .Select(x => x.Name).Distinct(StringComparer.OrdinalIgnoreCase).Take(12).ToList();
        bool transfer = Transfer.IsMatch(text);
        if (indicators.Count == 0) return Task.CompletedTask;

        string reason = transfer
            ? "Selected Discord export contains a possible executable/archive transfer near known BONELAB/Fusion cheat terminology. Message contents were not copied."
            : "Selected Discord export contains known BONELAB/Fusion cheat terminology. This is review evidence only and does not prove usage.";
        FileSystemScanner.AddUnique(report, new(FindingStatus.Suspicious, "DISCORD_EXPORT",
            transfer ? "Possible cheat file transfer in Discord export" : "Cheat-related Discord channel/message evidence",
            reason, location, Indicators: indicators));
        return Task.CompletedTask;
    }
}
