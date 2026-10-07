using System.Text;
using System.Text.RegularExpressions;
using SynapseChecker.Models;
using SynapseChecker.Scanner.FileSystem;
using SynapseChecker.Scanner.Signatures;
using Microsoft.Win32;

namespace SynapseChecker.Scanner.Logs;

public sealed class GameLogScanner(SignatureDatabase database)
{
    private const int HeadBytes = 4 * 1024 * 1024;
    private const int TailBytes = 8 * 1024 * 1024;

    public async Task ScanAsync(ScanReport report, IProgress<ScanProgress>? progress, CancellationToken token)
    {
        List<string> logs = DiscoverLogs().Where(File.Exists).Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        foreach (string log in logs)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                byte[] content = await ReadBoundedAsync(log, token);
                report.Statistics.GameLogsChecked++;
                report.Statistics.GameLogBytesRead += content.LongLength;
                Inspect(log, Encoding.UTF8.GetString(content), report);
                progress?.Report(FileSystemScanner.ToProgress(report, "GAME LOGS", log));
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
            {
                FileSystemScanner.RecordError(report, log, ex);
            }
        }
        report.Events.Add($"BONELAB_LOG_CHECK | logs={report.Statistics.GameLogsChecked} | bytes={report.Statistics.GameLogBytesRead} | content not copied to report");
    }

    private void Inspect(string path, string text, ScanReport report)
    {
        foreach (IndicatorRule rule in database.Indicators)
        {
            List<string> matched = rule.Indicators.Where(x =>
                text.Contains(x, StringComparison.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            string family = rule.Name.Replace(" static signature", "", StringComparison.OrdinalIgnoreCase);
            bool familyName = text.Contains(family, StringComparison.OrdinalIgnoreCase);
            if (matched.Count >= 2)
            {
                FileSystemScanner.AddUnique(report, new(FindingStatus.Detected, "GAME_LOG", family,
                    $"KNOWN LOG SIGNATURE ({matched.Count} independent indicators)", path,
                    Indicators: matched, LastModifiedUtc: File.GetLastWriteTimeUtc(path)));
            }
            else if (familyName || matched.Count == 1)
            {
                IReadOnlyList<string> evidence = matched.Count > 0 ? matched : new[] { family };
                FileSystemScanner.AddUnique(report, new(FindingStatus.Suspicious, "GAME_LOG", family,
                    "LOG REFERENCE; file/hash confirmation required", path,
                    Indicators: evidence, LastModifiedUtc: File.GetLastWriteTimeUtc(path)));
            }
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(string path, CancellationToken token)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, 128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length <= HeadBytes + TailBytes)
        {
            using var all = new MemoryStream((int)stream.Length);
            await stream.CopyToAsync(all, token);
            return all.ToArray();
        }

        byte[] result = new byte[HeadBytes + TailBytes];
        int headRead = await ReadFullyAsync(stream, result.AsMemory(0, HeadBytes), token);
        stream.Seek(-TailBytes, SeekOrigin.End);
        int tailRead = await ReadFullyAsync(stream, result.AsMemory(HeadBytes, TailBytes), token);
        if (headRead + tailRead == result.Length) return result;
        return result.AsSpan(0, headRead + tailRead).ToArray();
    }

    private static async Task<int> ReadFullyAsync(Stream stream, Memory<byte> buffer, CancellationToken token)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer[total..], token);
            if (read == 0) break;
            total += read;
        }
        return total;
    }

    private static IEnumerable<string> DiscoverLogs()
    {
        string localLow = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "AppData", "LocalLow", "Stress Level Zero", "BONELAB");
        foreach (string name in new[] { "Player.log", "Player-prev.log" })
        {
            string path = Path.Combine(localLow, name);
            if (File.Exists(path)) yield return path;
        }
        foreach (string path in SafeGetFiles(Path.Combine(localLow, "Logs"), "*.log")) yield return path;
        foreach (string path in SafeGetFiles(Path.Combine(localLow, "Fusion", "Logs"), "*.log")) yield return path;

        foreach (string game in DiscoverGameRoots())
        {
            foreach (string relative in new[] { "ReShade.log", @"MelonLoader\Latest.log" })
            {
                string path = Path.Combine(game, relative);
                if (File.Exists(path)) yield return path;
            }
            foreach (string path in SafeGetFiles(Path.Combine(game, "MelonLoader", "Logs"), "*.log")) yield return path;
        }
    }

    private static IEnumerable<string> DiscoverGameRoots()
    {
        var libraries = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\Program Files (x86)\Steam",
            @"C:\Program Files\Steam"
        };
        if (Registry.GetValue(@"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) is string steam)
            libraries.Add(steam);
        foreach (string steamRoot in libraries.ToArray())
        {
            string vdf = Path.Combine(steamRoot, "steamapps", "libraryfolders.vdf");
            try
            {
                if (!File.Exists(vdf)) continue;
                string text = File.ReadAllText(vdf);
                foreach (Match match in Regex.Matches(text, @"""path""\s+""(?<p>[^""]+)""", RegexOptions.IgnoreCase))
                    libraries.Add(match.Groups["p"].Value.Replace(@"\\", @"\"));
            }
            catch (Exception) { }
        }
        foreach (string root in libraries)
        {
            string game = Path.Combine(root, "steamapps", "common", "BONELAB");
            if (Directory.Exists(game)) yield return game;
        }
    }

    private static IEnumerable<string> SafeGetFiles(string directory, string pattern)
    {
        if (!Directory.Exists(directory)) return Array.Empty<string>();
        try { return Directory.GetFiles(directory, pattern, SearchOption.AllDirectories); }
        catch (Exception) { return Array.Empty<string>(); }
    }
}
