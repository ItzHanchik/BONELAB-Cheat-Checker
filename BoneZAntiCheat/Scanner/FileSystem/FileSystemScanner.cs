using System.Text;
using BoneZAntiCheat.Models;
using BoneZAntiCheat.Scanner.Hashes;
using BoneZAntiCheat.Scanner.Signatures;

namespace BoneZAntiCheat.Scanner.FileSystem;

public sealed class FileSystemScanner(SignatureDatabase database, HashMatcher hashMatcher)
{
    private static readonly HashSet<string> CandidateExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".dll", ".exe", ".asi", ".melon", ".sys" };
    private const long MaxHashBytes = 512L * 1024 * 1024;
    private const long MaxStaticBytes = 24L * 1024 * 1024;
    private readonly HashSet<long> _knownHashSizes = database.Hashes.Where(x => x.Size is > 0)
        .Select(x => x.Size!.Value).ToHashSet();

    public async Task ScanAsync(IEnumerable<string> roots, ScanReport report,
        IProgress<ScanProgress>? progress, CancellationToken token)
    {
        var seenFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string root in roots.Where(Directory.Exists))
        {
            var pending = new Stack<string>();
            pending.Push(Path.GetFullPath(root));
            while (pending.Count > 0)
            {
                token.ThrowIfCancellationRequested();
                string directory = pending.Pop();
                if (!seenDirectories.Add(directory)) continue;
                report.Statistics.DirectoriesSeen++;
                if (report.Statistics.DirectoriesSeen % 64 == 0)
                    progress?.Report(ToProgress(report, "FILES", directory));
                try
                {
                    var info = new DirectoryInfo(directory);
                    if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        report.Statistics.SkippedLinks++;
                        continue;
                    }
                    foreach (string child in Directory.EnumerateDirectories(directory)) pending.Push(child);
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
                {
                    RecordError(report, directory, ex);
                }

                string[] files;
                try { files = Directory.GetFiles(directory); }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
                {
                    RecordError(report, directory, ex);
                    continue;
                }

                foreach (string file in files)
                {
                    token.ThrowIfCancellationRequested();
                    report.Statistics.FilesSeen++;
                    if (!seenFiles.Add(file)) continue;
                    bool nameHit = database.FileNames.Any(x =>
                        Path.GetFileName(file).Equals(x.Value, StringComparison.OrdinalIgnoreCase));
                    TextRule? pathHit = database.Paths.FirstOrDefault(x =>
                        file.Contains(x.Value, StringComparison.OrdinalIgnoreCase));
                    bool executableCandidate = CandidateExtensions.Contains(Path.GetExtension(file));
                    if (!executableCandidate && !nameHit && pathHit is null) continue;
                    long length;
                    try { length = new FileInfo(file).Length; }
                    catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
                    { RecordError(report, file, ex); continue; }
                    bool shouldInspect = nameHit || pathHit is not null || _knownHashSizes.Contains(length) ||
                                         (executableCandidate && IsHighRiskPath(file));
                    if (!shouldInspect)
                    {
                        report.Statistics.MetadataFilteredFiles++;
                        continue;
                    }
                    await InspectFileAsync(file, nameHit, pathHit, report, token);
                    progress?.Report(ToProgress(report, "FILES", file));
                }
            }
        }
    }

    private static bool IsHighRiskPath(string path)
    {
        string normalized = path.Replace('/', '\\');
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string[] roots =
        {
            Path.Combine(profile, "Downloads"), Path.Combine(profile, "Desktop"),
            Path.Combine(profile, "Documents"), Path.Combine(local, "Temp"),
            roaming, Path.Combine(local, "Stress Level Zero")
        };
        return roots.Any(root => !string.IsNullOrWhiteSpace(root) &&
                                 normalized.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
               || normalized.Contains("\\BONELAB\\", StringComparison.OrdinalIgnoreCase)
               || normalized.Contains("\\Mods\\", StringComparison.OrdinalIgnoreCase)
               || normalized.Contains("\\MelonLoader\\", StringComparison.OrdinalIgnoreCase);
    }

    public async Task InspectFileAsync(string file, bool nameHit, TextRule? pathHit,
        ScanReport report, CancellationToken token)
    {
        try
        {
            var info = new FileInfo(file);
            if (!info.Exists || info.Length <= 0) return;
            if (info.Length > MaxHashBytes)
            {
                report.Statistics.SkippedLargeFiles++;
                return;
            }
            report.Statistics.FilesInspected++;
            var (hash, hashRule) = await hashMatcher.InspectAsync(file, token);
            report.Statistics.BytesHashed += info.Length;
            if (hashRule is not null)
            {
                AddUnique(report, new(FindingStatus.Detected, "FILE", hashRule.Name,
                    $"SHA-256 MATCH ({hashRule.Severity})", file, hash, info.Length, null, info.LastWriteTimeUtc));
                return;
            }

            if (info.Length <= MaxStaticBytes && CandidateExtensions.Contains(info.Extension))
            {
                IReadOnlyList<ScanFinding> indicators = await MatchIndicatorsAsync(file, hash, info.Length, token);
                if (indicators.Count > 0)
                {
                    foreach (ScanFinding indicator in indicators) AddUnique(report, indicator);
                    return;
                }
            }

            if (nameHit || pathHit is not null)
            {
                string label = database.FileNames.FirstOrDefault(x =>
                    Path.GetFileName(file).Equals(x.Value, StringComparison.OrdinalIgnoreCase))?.Name
                    ?? pathHit!.Name;
                AddUnique(report, new(FindingStatus.Suspicious, "FILE", label,
                    nameHit ? "FILENAME MATCH; hash/signature not confirmed" : "PATH MATCH; hash/signature not confirmed",
                    file, hash, info.Length, null, info.LastWriteTimeUtc));
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            RecordError(report, file, ex);
        }
    }

    private async Task<IReadOnlyList<ScanFinding>> MatchIndicatorsAsync(string path, string hash, long size,
        CancellationToken token)
    {
        byte[] data = await File.ReadAllBytesAsync(path, token);
        string ascii = Encoding.Latin1.GetString(data);
        string unicode = Encoding.Unicode.GetString(data);
        var findings = new List<ScanFinding>();
        foreach (IndicatorRule rule in database.Indicators)
        {
            List<string> matched = rule.Indicators.Where(x =>
                ascii.Contains(x, StringComparison.Ordinal) || unicode.Contains(x, StringComparison.Ordinal)).ToList();
            if (matched.Count >= Math.Max(2, rule.Threshold))
                findings.Add(new(FindingStatus.Detected, "FILE", rule.Name,
                    $"KNOWN STATIC SIGNATURE ({matched.Count} indicators)", path, hash, size, matched,
                    File.GetLastWriteTimeUtc(path)));
        }
        return findings;
    }

    public static ScanProgress ToProgress(ScanReport report, string phase, string path) => new(phase,
        report.Statistics.FilesSeen, report.Statistics.FilesInspected, report.Statistics.DirectoriesSeen,
        report.Findings.Count(x => x.Status == FindingStatus.Detected),
        report.Findings.Count(x => x.Status == FindingStatus.Suspicious), report.Statistics.AccessErrors, path);

    public static void AddUnique(ScanReport report, ScanFinding finding)
    {
        if (!report.Findings.Any(x => x.Status == finding.Status && x.Location.Equals(finding.Location,
                StringComparison.OrdinalIgnoreCase) && x.Detection == finding.Detection)) report.Findings.Add(finding);
    }

    public static void RecordError(ScanReport report, string location, Exception error)
    {
        report.Statistics.AccessErrors++;
        if (report.Events.Count < 5000) report.Events.Add($"ACCESS_ERROR | {location} | {error.GetType().Name}");
    }
}
