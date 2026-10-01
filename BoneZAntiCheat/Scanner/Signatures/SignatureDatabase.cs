using System.Text.Json;
using BoneZAntiCheat.Models;

namespace BoneZAntiCheat.Scanner.Signatures;

public sealed class SignatureDatabase
{
    public IReadOnlyList<HashRule> Hashes { get; }
    public IReadOnlyList<TextRule> FileNames { get; }
    public IReadOnlyList<TextRule> Paths { get; }
    public IReadOnlyList<TextRule> Processes { get; }
    public IReadOnlyList<IndicatorRule> Indicators { get; }

    public SignatureDatabase(string directory)
    {
        Hashes = Read<HashRule>(directory, "hashes.json").Where(x => x.Sha256.Length == 64).ToList();
        FileNames = Read<TextRule>(directory, "filenames.json");
        Paths = Read<TextRule>(directory, "paths.json");
        Processes = Read<TextRule>(directory, "processes.json");
        Indicators = Read<IndicatorRule>(directory, "indicators.json");
    }

    private static List<T> Read<T>(string directory, string name)
    {
        string path = Path.Combine(directory, name);
        if (!File.Exists(path)) throw new FileNotFoundException($"Missing signature database: {name}", path);
        return JsonSerializer.Deserialize<List<T>>(File.ReadAllText(path),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new();
    }
}
