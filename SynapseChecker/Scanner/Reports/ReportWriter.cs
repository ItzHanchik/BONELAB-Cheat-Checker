using System.Text;
using System.Text.Json;
using System.IO.Compression;
using SynapseChecker.Models;

namespace SynapseChecker.Scanner.Reports;

public sealed record ReportPaths(string Json, string Text, string? ModArchive);

public sealed class ReportWriter
{
    public async Task<ReportPaths> WriteAsync(ScanReport report, CancellationToken token = default)
    {
        string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SynapseChecker", "Reports");
        Directory.CreateDirectory(directory);
        string stem = Path.Combine(directory, $"scan-{DateTime.Now:yyyyMMdd-HHmmss}");
        string jsonPath = stem + ".json";
        string textPath = stem + ".txt";
        await File.WriteAllTextAsync(jsonPath, JsonSerializer.Serialize(report,
            new JsonSerializerOptions { WriteIndented = true, Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } }), token);

        var text = new StringBuilder();
        text.AppendLine("SYNAPSE CHECKER REPORT").AppendLine($"Result: {report.Result}")
            .AppendLine($"Started UTC: {report.StartedAtUtc:O}").AppendLine($"Finished UTC: {report.FinishedAtUtc:O}")
            .AppendLine($"Duration: {report.Duration}").AppendLine($"Disks: {string.Join(", ", report.Disks)}")
            .AppendLine($"Files seen: {report.Statistics.FilesSeen}").AppendLine($"Files inspected: {report.Statistics.FilesInspected}")
            .AppendLine($"Directories: {report.Statistics.DirectoriesSeen}").AppendLine($"Processes: {report.Statistics.ProcessesChecked}")
            .AppendLine($"Metadata-filtered files: {report.Statistics.MetadataFilteredFiles}")
            .AppendLine($"BONELAB game logs: {report.Statistics.GameLogsChecked} ({report.Statistics.GameLogBytesRead} bytes read)")
            .AppendLine($"Steam accounts: {report.Statistics.SteamAccountsChecked} (project ban matches: {report.Statistics.ProjectBanMatches})")
            .AppendLine($"Discord roots: {report.Statistics.DiscordRootsChecked}")
            .AppendLine($"Discord packages found: {report.Statistics.DiscordPackagesFound} (archives inspected: {report.Statistics.DiscordDiscoveryArchivesChecked})")
            .AppendLine($"Discord exports checked: {report.Statistics.DiscordExportsChecked} (records: {report.Statistics.DiscordMessagesChecked})")
            .AppendLine($"BONELAB DLL candidates: {report.Statistics.ModDllCandidatesChecked} (ordinary game DLLs skipped: {report.Statistics.ModDllCandidatesSkipped})")
            .AppendLine($"Selected mod/suspicious DLLs: {report.Statistics.ModDllsFound} (decompiled projects: {report.Statistics.ModDllsDecompiled}, C# files: {report.Statistics.ModSourceFilesWritten}, errors/native: {report.Statistics.ModDllDecompileErrors})")
            .AppendLine($"Mod source archive: {report.ModAssemblyArchivePath ?? "N/A"}")
            .AppendLine($"Access errors: {report.Statistics.AccessErrors}")
            .AppendLine().AppendLine("FINDINGS");
        foreach (ScanFinding f in report.Findings)
            text.AppendLine($"[{f.Status}] {f.Detection}\nCategory: {f.Category}\nReason: {f.Reason}\nLocation: {f.Location}\nSHA-256: {f.Sha256 ?? "N/A"}\nModified UTC: {(f.LastModifiedUtc?.ToString("O") ?? "N/A")}\n");
        text.AppendLine("EVENTS");
        foreach (string e in report.Events) text.AppendLine(e);
        await File.WriteAllTextAsync(textPath, text.ToString(), token);
        if (!string.IsNullOrWhiteSpace(report.ModAssemblyArchivePath) && File.Exists(report.ModAssemblyArchivePath))
        {
            try
            {
                using var archive = System.IO.Compression.ZipFile.Open(report.ModAssemblyArchivePath,
                    System.IO.Compression.ZipArchiveMode.Update);
                archive.CreateEntryFromFile(jsonPath, "reports/scan-report.json",
                    System.IO.Compression.CompressionLevel.Optimal);
                archive.CreateEntryFromFile(textPath, "reports/scan-report.txt",
                    System.IO.Compression.CompressionLevel.Optimal);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                report.Events.Add($"MOD_ARCHIVE_REPORT_ERROR | {ex.GetType().Name}");
            }
        }
        return new(jsonPath, textPath, report.ModAssemblyArchivePath);
    }
}
