using System.IO.Compression;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using BoneZAntiCheat.Models;
using BoneZAntiCheat.Scanner.FileSystem;
using BoneZAntiCheat.Scanner.Signatures;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp.ProjectDecompiler;
using ICSharpCode.Decompiler.Metadata;
using Microsoft.Win32;

namespace BoneZAntiCheat.Scanner.Mods;

/// <summary>
/// Audits every DLL under discovered BONELAB Mods directories without loading it.
/// Every DLL gets a separate archive folder containing the original file, an
/// ILSpy-generated project tree with individual source files and a local info
/// record. Native or malformed files are preserved and explicitly logged instead
/// of being executed.
/// </summary>
public sealed class ModAssemblyScanner(FileSystemScanner fileScanner, SignatureDatabase database)
{
    private const long MaxDecompileBytes = 128L * 1024 * 1024;

    public async Task<string?> ScanAsync(ScanReport report, IProgress<ScanProgress>? progress,
        CancellationToken token, IEnumerable<string>? rootOverride = null)
    {
        bool explicitRoots = rootOverride is not null;
        List<string> modRoots = (rootOverride ?? DiscoverModRoots()).Where(Directory.Exists)
            .Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        List<string> gameRoots = explicitRoots ? new() : DiscoverBonelabRoots().Where(Directory.Exists)
            .Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        List<string> roots = modRoots.Concat(gameRoots).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var candidates = new Dictionary<string, DllCandidate>(StringComparer.OrdinalIgnoreCase);
        foreach (string root in roots)
        {
            try
            {
                bool forceRoot = explicitRoots || modRoots.Contains(root, StringComparer.OrdinalIgnoreCase);
                foreach (string path in Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories))
                {
                    string fullPath = Path.GetFullPath(path);
                    bool forceInclude = forceRoot || IsKnownModLocation(root, fullPath);
                    if (candidates.TryGetValue(fullPath, out DllCandidate? existing))
                        candidates[fullPath] = existing with { ForceInclude = existing.ForceInclude || forceInclude };
                    else
                        candidates.Add(fullPath, new(root, fullPath, forceInclude, false));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                FileSystemScanner.RecordError(report, root, ex);
            }
        }
        var dlls = new List<DllCandidate>();
        int candidateIndex = 0;
        foreach (DllCandidate candidate in candidates.Values.OrderBy(x => x.Path, StringComparer.OrdinalIgnoreCase))
        {
            token.ThrowIfCancellationRequested();
            candidateIndex++;
            report.Statistics.ModDllCandidatesChecked++;
            if (candidate.ForceInclude)
            {
                dlls.Add(candidate);
            }
            else
            {
                bool nameHit = database.FileNames.Any(x =>
                    Path.GetFileName(candidate.Path).Equals(x.Value, StringComparison.OrdinalIgnoreCase));
                TextRule? pathHit = database.Paths.FirstOrDefault(x =>
                    candidate.Path.Contains(x.Value, StringComparison.OrdinalIgnoreCase));
                int findingsBefore = report.Findings.Count;
                await fileScanner.InspectFileAsync(candidate.Path, nameHit, pathHit, report, token);
                bool suspicious = report.Findings.Skip(findingsBefore).Any(x =>
                    x.Location.Equals(candidate.Path, StringComparison.OrdinalIgnoreCase) &&
                    x.Status is FindingStatus.Suspicious or FindingStatus.Detected);
                if (suspicious)
                {
                    dlls.Add(candidate with { AlreadyInspected = true });
                    AddEvent(report, $"BONELAB DLL SELECTED BY SIGNATURE · {candidate.Path}");
                }
                else
                {
                    report.Statistics.ModDllCandidatesSkipped++;
                }
            }
            progress?.Report(FileSystemScanner.ToProgress(report, "BONELAB DLL DISCOVERY",
                $"{candidateIndex}/{candidates.Count} · {candidate.Path}"));
        }
        report.Statistics.ModDllsFound = dlls.Count;
        if (dlls.Count == 0)
        {
            report.Events.Add($"MOD_DLL_AUDIT | no mod or suspicious BONELAB DLLs selected | candidates={candidates.Count}");
            return null;
        }

        string reportDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BoneZAntiCheat", "Reports");
        Directory.CreateDirectory(reportDirectory);
        string zipPath = Path.Combine(reportDirectory, $"mod-dll-sources-{DateTime.Now:yyyyMMdd-HHmmss}.zip");
        var log = new StringBuilder()
            .AppendLine("BONEZ MOD DLL STATIC AUDIT")
            .AppendLine($"Created UTC: {DateTime.UtcNow:O}")
            .AppendLine("DLL files were copied and parsed as data; none were loaded or executed.")
            .AppendLine();

        using (ZipArchive archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            int index = 0;
            foreach (var item in dlls)
            {
                token.ThrowIfCancellationRequested();
                index++;
                string relative = Path.GetRelativePath(item.Root, item.Path).Replace('\\', '/');
                string assemblyFolder = $"assemblies/{CreateAssemblyFolderName(index, item.Path)}";
                string originalEntry = $"{assemblyFolder}/original/{SanitizeFileName(Path.GetFileName(item.Path))}";
                var assemblyInfo = new StringBuilder()
                    .AppendLine("BONEZ MOD DLL RECORD")
                    .AppendLine($"Original path: {item.Path}")
                    .AppendLine($"Relative path: {relative}")
                    .AppendLine($"Archive folder: {assemblyFolder}");
                try
                {
                    var info = new FileInfo(item.Path);
                    assemblyInfo.AppendLine($"Size: {info.Length} bytes")
                        .AppendLine($"Last modified UTC: {info.LastWriteTimeUtc:O}");
                    report.Statistics.ModDllBytesArchived += info.Length;
                    archive.CreateEntryFromFile(item.Path, originalEntry, CompressionLevel.Optimal);
                    if (!item.AlreadyInspected)
                    {
                        bool nameHit = database.FileNames.Any(x =>
                            Path.GetFileName(item.Path).Equals(x.Value, StringComparison.OrdinalIgnoreCase));
                        TextRule? pathHit = database.Paths.FirstOrDefault(x =>
                            item.Path.Contains(x.Value, StringComparison.OrdinalIgnoreCase));
                        await fileScanner.InspectFileAsync(item.Path, nameHit, pathHit, report, token);
                    }

                    if (info.Length > MaxDecompileBytes)
                    {
                        report.Statistics.ModDllDecompileErrors++;
                        log.AppendLine($"SKIP_TOO_LARGE | {item.Path} | {info.Length} bytes");
                        assemblyInfo.AppendLine("Status: skipped — file exceeds 128 MiB")
                            .AppendLine("Source files: 0");
                        AddEvent(report, $"MOD DLL SKIPPED (>128 MiB) · {item.Path}");
                    }
                    else if (!IsManagedAssembly(item.Path))
                    {
                        report.Statistics.ModDllDecompileErrors++;
                        log.AppendLine($"NATIVE_OR_NO_METADATA | {item.Path}");
                        assemblyInfo.AppendLine("Status: native or missing managed metadata")
                            .AppendLine("Source files: 0");
                        AddEvent(report, $"MOD DLL NATIVE/NO METADATA · {item.Path}");
                    }
                    else
                    {
                        string temporaryProject = Path.Combine(Path.GetTempPath(),
                            "BoneZAntiCheat-Decompile-" + Guid.NewGuid().ToString("N"));
                        try
                        {
                            Directory.CreateDirectory(temporaryProject);
                            using var module = new PEFile(item.Path);
                            string targetFramework = module.GetRuntime().ToString();
                            var resolver = new UniversalAssemblyResolver(item.Path, false, targetFramework: null);
                            var decompiler = new WholeProjectDecompiler(resolver)
                            {
                                MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount, 1, 4)
                            };
                            decompiler.Settings.ThrowOnAssemblyResolveErrors = false;
                            decompiler.Settings.UseSdkStyleProjectFormat = true;
                            decompiler.DecompileProject(module, temporaryProject, token);

                            string[] projectFiles = Directory.EnumerateFiles(temporaryProject, "*",
                                    SearchOption.AllDirectories)
                                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray();
                            int sourceFiles = 0;
                            foreach (string projectFile in projectFiles)
                            {
                                token.ThrowIfCancellationRequested();
                                string projectRelative = Path.GetRelativePath(temporaryProject, projectFile);
                                string safeProjectRelative = SanitizeZipPath(projectRelative);
                                archive.CreateEntryFromFile(projectFile,
                                    $"{assemblyFolder}/source/{safeProjectRelative}", CompressionLevel.Optimal);
                                if (Path.GetExtension(projectFile).Equals(".cs", StringComparison.OrdinalIgnoreCase))
                                    sourceFiles++;
                            }
                            report.Statistics.ModSourceFilesWritten += sourceFiles;
                            assemblyInfo.AppendLine("Status: decompiled project")
                                .AppendLine($"Project files: {projectFiles.Length}")
                                .AppendLine($"C# source files: {sourceFiles}")
                                .AppendLine($"Target runtime: {targetFramework}");
                            log.AppendLine($"DECOMPILED_PROJECT | {item.Path} | project_files={projectFiles.Length} | cs_files={sourceFiles}");
                            AddEvent(report, $"MOD DLL PROJECT DECOMPILED · {item.Path} · {sourceFiles:N0} C# files");
                        }
                        finally
                        {
                            try { if (Directory.Exists(temporaryProject)) Directory.Delete(temporaryProject, true); }
                            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                            {
                                log.AppendLine($"TEMP_CLEANUP_WARNING | {temporaryProject} | {OneLine(ex.Message)}");
                            }
                        }
                        report.Statistics.ModDllsDecompiled++;
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    report.Statistics.ModDllDecompileErrors++;
                    FileSystemScanner.RecordError(report, item.Path, ex);
                    log.AppendLine($"ERROR | {item.Path} | {ex.GetType().Name}: {OneLine(ex.Message)}");
                    assemblyInfo.AppendLine($"Status: error — {ex.GetType().Name}: {OneLine(ex.Message)}")
                        .AppendLine("Source files: 0");
                    AddEvent(report, $"MOD DLL ERROR · {item.Path} · {ex.GetType().Name}: {OneLine(ex.Message)}");
                }
                await WriteTextEntryAsync(archive, $"{assemblyFolder}/info.txt", assemblyInfo.ToString(), token);
                progress?.Report(FileSystemScanner.ToProgress(report, "MOD DLL AUDIT",
                    $"{index}/{dlls.Count} · {item.Path}"));
            }

            await WriteTextEntryAsync(archive, "audit.log", log.ToString(), token);
        }

        report.ModAssemblyArchivePath = zipPath;
        report.Events.Add($"MOD_DLL_AUDIT | roots={roots.Count} | candidates={report.Statistics.ModDllCandidatesChecked} | skipped_game_dlls={report.Statistics.ModDllCandidatesSkipped} | selected={report.Statistics.ModDllsFound} | decompiled={report.Statistics.ModDllsDecompiled} | source_files={report.Statistics.ModSourceFilesWritten} | errors_or_native={report.Statistics.ModDllDecompileErrors} | archive={zipPath}");
        return zipPath;
    }

    private sealed record DllCandidate(string Root, string Path, bool ForceInclude, bool AlreadyInspected);

    private static bool IsKnownModLocation(string gameRoot, string path)
    {
        string relative = Path.GetRelativePath(gameRoot, path).Replace('/', '\\');
        string[] segments = relative.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        return segments.Any(segment => segment.Equals("Mods", StringComparison.OrdinalIgnoreCase) ||
                                       segment.Equals("Plugins", StringComparison.OrdinalIgnoreCase) ||
                                       segment.Equals("UserData", StringComparison.OrdinalIgnoreCase));
    }

    private static string CreateAssemblyFolderName(int index, string path)
    {
        string name = SanitizeFileName(Path.GetFileNameWithoutExtension(path));
        if (name.Length > 70) name = name[..70];
        string pathId = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path)))[..8];
        return $"{index:000}-{name}-{pathId}";
    }

    private static string SanitizeFileName(string value)
    {
        string sanitized = string.Concat(value.Select(ch =>
            Path.GetInvalidFileNameChars().Contains(ch) ? '_' : ch)).Trim();
        return string.IsNullOrWhiteSpace(sanitized) ? "assembly" : sanitized;
    }

    private static async Task WriteTextEntryAsync(ZipArchive archive, string path, string text,
        CancellationToken token)
    {
        ZipArchiveEntry entry = archive.CreateEntry(path, CompressionLevel.Optimal);
        await using Stream stream = entry.Open();
        await using var writer = new StreamWriter(stream, new UTF8Encoding(false));
        await writer.WriteAsync(text.AsMemory(), token);
    }

    private static bool IsManagedAssembly(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        using var pe = new PEReader(stream, PEStreamOptions.LeaveOpen);
        return pe.HasMetadata;
    }

    private static string SanitizeZipPath(string path)
    {
        string normalized = path.Replace('\\', '/').TrimStart('/');
        normalized = Regex.Replace(normalized, @"(^|/)\.\.(/|$)", "$1");
        return string.Join('/', normalized.Split('/').Select(part =>
            string.Concat(part.Select(ch => Path.GetInvalidFileNameChars().Contains(ch) ? '_' : ch))));
    }

    private static string OneLine(string text) =>
        text.Replace('\r', ' ').Replace('\n', ' ').Trim()[..Math.Min(300, text.Replace('\r', ' ').Replace('\n', ' ').Trim().Length)];

    private static void AddEvent(ScanReport report, string value)
    {
        if (report.Events.Count < 5000) report.Events.Add(value);
    }

    internal static IEnumerable<string> DiscoverModRoots()
    {
        string localLowMods = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "AppData", "LocalLow", "Stress Level Zero", "BONELAB", "Mods");
        if (Directory.Exists(localLowMods)) yield return localLowMods;

        foreach (string root in DiscoverSteamLibraries())
        {
            string mods = Path.Combine(root, "steamapps", "common", "BONELAB", "Mods");
            if (Directory.Exists(mods)) yield return mods;
        }
    }

    internal static IEnumerable<string> DiscoverBonelabRoots()
    {
        foreach (string root in DiscoverSteamLibraries())
        {
            string bonelab = Path.Combine(root, "steamapps", "common", "BONELAB");
            if (Directory.Exists(bonelab)) yield return bonelab;
        }
    }

    private static IEnumerable<string> DiscoverSteamLibraries()
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
        return libraries;
    }
}
