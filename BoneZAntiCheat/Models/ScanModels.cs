using System.Text.Json.Serialization;

namespace BoneZAntiCheat.Models;

public enum FindingStatus { Clean, Suspicious, Detected }

public sealed record ScanFinding(FindingStatus Status, string Category, string Detection,
    string Reason, string Location, string? Sha256 = null, long? Size = null,
    IReadOnlyList<string>? Indicators = null, DateTime? LastModifiedUtc = null);

public sealed record ScanProgress(string Phase, long FilesSeen, long FilesInspected,
    long DirectoriesSeen, int Detected, int Suspicious, int AccessErrors, string CurrentPath);

public sealed class ScanStatistics
{
    public long FilesSeen { get; set; }
    public long FilesInspected { get; set; }
    public long DirectoriesSeen { get; set; }
    public long BytesHashed { get; set; }
    public int ProcessesChecked { get; set; }
    public int StartupEntriesChecked { get; set; }
    public int DiscordRootsChecked { get; set; }
    public int DiscordExportsChecked { get; set; }
    public int DiscordDiscoveryDirectoriesChecked { get; set; }
    public int DiscordDiscoveryArchivesChecked { get; set; }
    public int DiscordPackagesFound { get; set; }
    public int DiscordChannelsChecked { get; set; }
    public int DiscordMessagesChecked { get; set; }
    public int SteamLoginFilesChecked { get; set; }
    public int SteamAccountsChecked { get; set; }
    public int ProjectBanMatches { get; set; }
    public int GameLogsChecked { get; set; }
    public long GameLogBytesRead { get; set; }
    public int AccessErrors { get; set; }
    public int SkippedLinks { get; set; }
    public int SkippedLargeFiles { get; set; }
    public long MetadataFilteredFiles { get; set; }
    public int ModDllsFound { get; set; }
    public int ModDllCandidatesChecked { get; set; }
    public int ModDllCandidatesSkipped { get; set; }
    public int ModDllsDecompiled { get; set; }
    public int ModSourceFilesWritten { get; set; }
    public int ModDllDecompileErrors { get; set; }
    public long ModDllBytesArchived { get; set; }
}

public sealed class ScanReport
{
    public string Product { get; init; } = "BoneZ AntiCheat Checker";
    public string Version { get; init; } = "2.6";
    public DateTime StartedAtUtc { get; init; }
    public DateTime FinishedAtUtc { get; set; }
    [JsonIgnore] public TimeSpan Duration => FinishedAtUtc - StartedAtUtc;
    public double DurationSeconds => Duration.TotalSeconds;
    public List<string> Disks { get; init; } = new();
    public ScanStatistics Statistics { get; init; } = new();
    public List<ScanFinding> Findings { get; init; } = new();
    public List<string> Events { get; init; } = new();
    public string? ModAssemblyArchivePath { get; set; }
    public string Result => Findings.Any(x => x.Status == FindingStatus.Detected)
        ? "THREATS DETECTED" : Findings.Any(x => x.Status == FindingStatus.Suspicious)
            ? "SUSPICIOUS ITEMS" : "NO THREATS";
}

public sealed class HashRule
{
    [JsonPropertyName("name")] public string Name { get; set; } = "Unknown";
    [JsonPropertyName("sha256")] public string Sha256 { get; set; } = "";
    [JsonPropertyName("severity")] public string Severity { get; set; } = "HIGH";
    [JsonPropertyName("size")] public long? Size { get; set; }
}

public sealed class TextRule
{
    [JsonPropertyName("name")] public string Name { get; set; } = "Unknown";
    [JsonPropertyName("value")] public string Value { get; set; } = "";
}

public sealed class IndicatorRule
{
    [JsonPropertyName("name")] public string Name { get; set; } = "Unknown";
    [JsonPropertyName("threshold")] public int Threshold { get; set; } = 3;
    [JsonPropertyName("indicators")] public List<string> Indicators { get; set; } = new();
}

public sealed class ProjectBanDatabase
{
    [JsonPropertyName("generatedAtUtc")] public DateTime GeneratedAtUtc { get; set; }
    [JsonPropertyName("source")] public string Source { get; set; } = "BoneZ project ban list";
    [JsonPropertyName("entries")] public List<ProjectBanRule> Entries { get; set; } = new();
}

public sealed class ProjectBanRule
{
    [JsonPropertyName("steamIdSha256")] public string SteamIdSha256 { get; set; } = "";
    [JsonPropertyName("reason")] public string Reason { get; set; } = "Black Listed";
}
