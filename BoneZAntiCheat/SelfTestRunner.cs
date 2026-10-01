using System.Security.Cryptography;
using System.Text;
using System.IO.Compression;
using System.Reflection;
using BoneZAntiCheat.Models;
using BoneZAntiCheat.Scanner.Discord;
using BoneZAntiCheat.Scanner.FileSystem;
using BoneZAntiCheat.Scanner.Hashes;
using BoneZAntiCheat.Scanner.Mods;
using BoneZAntiCheat.Scanner.Signatures;
using BoneZAntiCheat.Scanner.Steam;

namespace BoneZAntiCheat;

internal static class SelfTestRunner
{
    public static async Task RunAsync(string signatureDirectory)
    {
        string root = Path.Combine(Path.GetTempPath(), "BoneZAntiCheat-SelfTest-" + Guid.NewGuid().ToString("N"));
        string? generatedModArchive = null;
        Directory.CreateDirectory(root);
        try
        {
            const string steamId = "76561199999999999";
            string fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(steamId)));
            string loginUsers = Path.Combine(root, "loginusers.vdf");
            await File.WriteAllTextAsync(loginUsers,
                $"\"users\"\n{{\n  \"{steamId}\"\n  {{\n    \"PersonaName\" \"Synthetic BoneZ Test\"\n  }}\n}}\n");
            var steamReport = NewReport();
            var steam = new SteamAccountScanner(new[]
            {
                new ProjectBanRule { SteamIdSha256 = fingerprint, Reason = "Self test" }
            }, DateTime.UtcNow);
            await steam.ScanFileAsync(loginUsers, steamReport, CancellationToken.None);
            if (steamReport.Statistics.ProjectBanMatches != 1 ||
                !steamReport.Findings.Any(x => x.Category == "PROJECT_BAN" && x.Status == FindingStatus.Detected))
                throw new InvalidOperationException("Steam project-ban self-test failed.");

            string discord = Path.Combine(root, "discord-export.json");
            await File.WriteAllTextAsync(discord,
                "{\"channel\":\"altclient-downloads\",\"message\":\"Pavelmenu attachment https://example.invalid/payload.dll\"}");
            var discordReport = NewReport();
            var exportScanner = new DiscordExportScanner(new SignatureDatabase(signatureDirectory));
            await exportScanner.ScanAsync(discord, discordReport, CancellationToken.None);
            if (!discordReport.Findings.Any(x => x.Category == "DISCORD_EXPORT" && x.Status == FindingStatus.Suspicious))
                throw new InvalidOperationException("Discord export self-test failed.");

            string officialPackage = Path.Combine(root, "package.zip");
            using (ZipArchive archive = ZipFile.Open(officialPackage, ZipArchiveMode.Create))
            {
                foreach (string entryName in new[]
                         {
                             "account/user.json", "messages/index.json", "messages/c123/messages.json",
                             "servers/index.json", "activity/analytics/events.json"
                         })
                {
                    ZipArchiveEntry entry = archive.CreateEntry(entryName);
                    await using StreamWriter writer = new(entry.Open());
                    await writer.WriteAsync("{}");
                }
            }
            await File.WriteAllTextAsync(Path.Combine(root, "ordinary.zip.note"), "not an archive");
            var discoveryReport = NewReport();
            var locator = new DiscordExportLocator();
            IReadOnlyList<string> discovered = await locator.DiscoverAsync(discoveryReport,
                CancellationToken.None, new[] { root });
            if (discovered.Count != 1 || !discovered[0].Equals(officialPackage, StringComparison.OrdinalIgnoreCase) ||
                discoveryReport.Statistics.DiscordPackagesFound != 1)
                throw new InvalidOperationException("Discord Data Package auto-discovery self-test failed.");

            string modRoot = Path.Combine(root, "Mods", "Synthetic.Mod");
            Directory.CreateDirectory(modRoot);
            string modDll = Path.Combine(modRoot, "Synthetic.Mod.dll");
            File.Copy(Assembly.GetExecutingAssembly().Location, modDll);
            var signatureDatabase = new SignatureDatabase(signatureDirectory);
            var modScanner = new ModAssemblyScanner(new FileSystemScanner(signatureDatabase,
                new HashMatcher(signatureDatabase)), signatureDatabase);
            var modReport = NewReport();
            generatedModArchive = await modScanner.ScanAsync(modReport, null, CancellationToken.None,
                new[] { Path.Combine(root, "Mods") });
            if (string.IsNullOrWhiteSpace(generatedModArchive) || !File.Exists(generatedModArchive))
                throw new InvalidOperationException("Mod project archive self-test did not create an archive.");
            using (ZipArchive modZip = ZipFile.OpenRead(generatedModArchive))
            {
                string[] entries = modZip.Entries.Select(x => x.FullName).ToArray();
                string[] assemblyFolders = entries.Where(x => x.StartsWith("assemblies/", StringComparison.Ordinal))
                    .Select(x => string.Join('/', x.Split('/').Take(2)))
                    .Distinct(StringComparer.Ordinal).ToArray();
                int sourceFiles = entries.Count(x => x.Contains("/source/", StringComparison.Ordinal) &&
                    x.EndsWith(".cs", StringComparison.OrdinalIgnoreCase));
                bool hasOriginal = entries.Any(x => x.EndsWith("/original/Synthetic.Mod.dll", StringComparison.Ordinal));
                bool hasProject = entries.Any(x => x.Contains("/source/", StringComparison.Ordinal) &&
                    x.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase));
                bool hasLegacySingleFile = entries.Any(x => x.EndsWith(".decompiled.cs", StringComparison.OrdinalIgnoreCase));
                if (assemblyFolders.Length != 1 || !hasOriginal || !hasProject || sourceFiles < 2 ||
                    hasLegacySingleFile || modReport.Statistics.ModSourceFilesWritten != sourceFiles)
                    throw new InvalidOperationException("Per-DLL project decompilation archive self-test failed.");
            }
        }
        finally
        {
            try { if (!string.IsNullOrWhiteSpace(generatedModArchive) && File.Exists(generatedModArchive)) File.Delete(generatedModArchive); } catch { }
            try { Directory.Delete(root, true); } catch { }
        }
    }

    private static ScanReport NewReport() => new()
    {
        StartedAtUtc = DateTime.UtcNow,
        FinishedAtUtc = DateTime.UtcNow
    };
}
