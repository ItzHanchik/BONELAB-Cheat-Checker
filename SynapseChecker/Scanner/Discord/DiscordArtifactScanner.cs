using SynapseChecker.Models;
using SynapseChecker.Scanner.FileSystem;
using SynapseChecker.Scanner.Signatures;

namespace SynapseChecker.Scanner.Discord;

public sealed class DiscordArtifactScanner(SignatureDatabase database, FileSystemScanner files)
{
    public async Task ScanAsync(ScanReport report, CancellationToken token)
    {
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roots = new[] { "Discord", "discordcanary", "discordptb", "BetterDiscord" }
            .SelectMany(name => new[] { Path.Combine(roaming, name), Path.Combine(local, name) })
            .Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        foreach (string root in roots)
        {
            token.ThrowIfCancellationRequested();
            report.Statistics.DiscordRootsChecked++;
            foreach (TextRule rule in database.FileNames)
            {
                string[] matches;
                try { matches = Directory.GetFiles(root, rule.Value, SearchOption.AllDirectories); }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
                { FileSystemScanner.RecordError(report, root, ex); continue; }
                foreach (string match in matches)
                    await files.InspectFileAsync(match, true,
                        database.Paths.FirstOrDefault(x => match.Contains(x.Value, StringComparison.OrdinalIgnoreCase)), report, token);
            }
        }
        report.Events.Add($"DISCORD_LOCAL_CHECK | roots={roots.Count} | filenames/paths/hashes only; no tokens, messages or accounts read");
    }
}
