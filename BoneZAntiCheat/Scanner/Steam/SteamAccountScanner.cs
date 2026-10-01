using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using BoneZAntiCheat.Models;
using BoneZAntiCheat.Scanner.FileSystem;

namespace BoneZAntiCheat.Scanner.Steam;

public sealed class SteamAccountScanner
{
    private static readonly Regex AccountBlock = new(
        "\\\"(?<id>7656119[0-9]{10})\\\"\\s*\\{(?<body>.*?)\\n\\s*\\}",
        RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.CultureInvariant);
    private static readonly Regex Persona = new(
        "\\\"PersonaName\\\"\\s*\\\"(?<value>[^\\\"]{0,128})\\\"",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly IReadOnlyDictionary<string, ProjectBanRule> _bans;
    private readonly DateTime _generatedAtUtc;

    public SteamAccountScanner(string signatureDirectory)
    {
        string path = Path.Combine(signatureDirectory, "banned-steam-ids.json");
        if (!File.Exists(path)) throw new FileNotFoundException("Missing project ban database", path);
        ProjectBanDatabase database = JsonSerializer.Deserialize<ProjectBanDatabase>(File.ReadAllText(path),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new();
        _generatedAtUtc = database.GeneratedAtUtc;
        _bans = database.Entries.Where(x => x.SteamIdSha256.Length == 64)
            .GroupBy(x => x.SteamIdSha256, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);
    }

    internal SteamAccountScanner(IEnumerable<ProjectBanRule> bans, DateTime generatedAtUtc)
    {
        _generatedAtUtc = generatedAtUtc;
        _bans = bans.ToDictionary(x => x.SteamIdSha256, StringComparer.OrdinalIgnoreCase);
    }

    public async Task ScanAsync(ScanReport report, CancellationToken token)
    {
        List<string> files = FindLoginUserFiles();
        foreach (string file in files) await ScanFileAsync(file, report, token);
        report.Events.Add($"STEAM_PROJECT_BANS | loginFiles={files.Count} | accounts={report.Statistics.SteamAccountsChecked} | matches={report.Statistics.ProjectBanMatches} | snapshot={_generatedAtUtc:O} | SteamID fingerprints only");
    }

    internal async Task ScanFileAsync(string path, ScanReport report, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        try
        {
            string text = await File.ReadAllTextAsync(path, token);
            report.Statistics.SteamLoginFilesChecked++;
            foreach (Match match in AccountBlock.Matches(text))
            {
                token.ThrowIfCancellationRequested();
                string steamId = match.Groups["id"].Value;
                report.Statistics.SteamAccountsChecked++;
                string fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(steamId)));
                if (!_bans.TryGetValue(fingerprint, out ProjectBanRule? ban)) continue;
                report.Statistics.ProjectBanMatches++;
                string persona = Persona.Match(match.Groups["body"].Value).Groups["value"].Value;
                string label = string.IsNullOrWhiteSpace(persona) ? steamId : $"{persona} ({steamId})";
                FileSystemScanner.AddUnique(report, new(FindingStatus.Detected, "PROJECT_BAN",
                    "BoneZ banned Steam account", $"Local Steam account {label} matches the BoneZ project ban snapshot. Reason: {ban.Reason}", path));
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            FileSystemScanner.RecordError(report, path, ex);
        }
    }

    private static List<string> FindLoginUserFiles()
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddRegistryPath(roots, Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam"), "SteamPath");
        AddRegistryPath(roots, Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Valve\Steam"), "InstallPath");
        AddRegistryPath(roots, Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Valve\Steam"), "InstallPath");
        string programFiles86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        if (!string.IsNullOrWhiteSpace(programFiles86)) roots.Add(Path.Combine(programFiles86, "Steam"));
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!string.IsNullOrWhiteSpace(programFiles)) roots.Add(Path.Combine(programFiles, "Steam"));
        return roots.Select(x => Path.Combine(x, "config", "loginusers.vdf"))
            .Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static void AddRegistryPath(HashSet<string> roots, RegistryKey? key, string valueName)
    {
        using (key)
        {
            if (key?.GetValue(valueName) is string value && !string.IsNullOrWhiteSpace(value))
                roots.Add(value.Replace('/', Path.DirectorySeparatorChar));
        }
    }
}
