using System.Text.RegularExpressions;
using BoneZAntiCheat.Models;
using BoneZAntiCheat.Scanner.FileSystem;
using BoneZAntiCheat.Scanner.Signatures;
using Microsoft.Win32;

namespace BoneZAntiCheat.Scanner.Startup;

public sealed class StartupScanner(SignatureDatabase database, FileSystemScanner files)
{
    public async Task ScanAsync(ScanReport report, CancellationToken token)
    {
        var entries = new List<(string Source, string Value)>();
        ReadRegistry(entries, RegistryHive.CurrentUser, RegistryView.Default, @"Software\Microsoft\Windows\CurrentVersion\Run", report);
        ReadRegistry(entries, RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Microsoft\Windows\CurrentVersion\Run", report);
        ReadRegistry(entries, RegistryHive.LocalMachine, RegistryView.Registry32, @"Software\Microsoft\Windows\CurrentVersion\Run", report);
        foreach (string folder in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        }.Where(Directory.Exists))
        {
            try { entries.AddRange(Directory.GetFiles(folder).Select(x => ($"Startup folder: {folder}", x))); }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { FileSystemScanner.RecordError(report, folder, ex); }
        }

        foreach (var entry in entries)
        {
            token.ThrowIfCancellationRequested();
            report.Statistics.StartupEntriesChecked++;
            string? target = ExtractTarget(entry.Value);
            TextRule? name = database.FileNames.FirstOrDefault(x =>
                Path.GetFileName(target ?? entry.Value).Equals(x.Value, StringComparison.OrdinalIgnoreCase));
            TextRule? path = database.Paths.FirstOrDefault(x => entry.Value.Contains(x.Value, StringComparison.OrdinalIgnoreCase));
            if (target is not null && File.Exists(target))
                await files.InspectFileAsync(target, name is not null, path, report, token);
            else if (name is not null || path is not null)
                FileSystemScanner.AddUnique(report, new(FindingStatus.Suspicious, "STARTUP", name?.Name ?? path!.Name,
                    "STARTUP ENTRY MATCH; target unavailable for signature verification", entry.Source + " -> " + entry.Value));
        }
    }

    private static void ReadRegistry(List<(string, string)> entries, RegistryHive hive, RegistryView view,
        string path, ScanReport report)
    {
        try
        {
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
            using RegistryKey? key = baseKey.OpenSubKey(path);
            if (key is null) return;
            foreach (string name in key.GetValueNames())
                if (key.GetValue(name)?.ToString() is string value) entries.Add(($"{hive}\\{path}\\{name}", value));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        { FileSystemScanner.RecordError(report, $"registry:{hive}:{path}", ex); }
    }

    private static string? ExtractTarget(string value)
    {
        Match quoted = Regex.Match(value, "^\\\"(?<p>[^\\\"]+)\\\"");
        string candidate = quoted.Success ? quoted.Groups["p"].Value : value.Split(' ', 2)[0];
        candidate = Environment.ExpandEnvironmentVariables(candidate.Trim());
        return Path.IsPathRooted(candidate) ? candidate : null;
    }
}
