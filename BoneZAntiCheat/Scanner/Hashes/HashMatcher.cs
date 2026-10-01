using System.Security.Cryptography;
using BoneZAntiCheat.Models;
using BoneZAntiCheat.Scanner.Signatures;

namespace BoneZAntiCheat.Scanner.Hashes;

public sealed class HashMatcher(SignatureDatabase database)
{
    public async Task<(string Hash, HashRule? Rule)> InspectAsync(string path, CancellationToken token)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, 1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        string hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, token));
        return (hash, database.Hashes.FirstOrDefault(x =>
            x.Sha256.Equals(hash, StringComparison.OrdinalIgnoreCase)));
    }
}
