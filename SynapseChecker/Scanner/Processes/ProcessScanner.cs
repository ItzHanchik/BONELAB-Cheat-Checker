using System.Diagnostics;
using SynapseChecker.Models;
using SynapseChecker.Scanner.FileSystem;
using SynapseChecker.Scanner.Signatures;

namespace SynapseChecker.Scanner.Processes;

public sealed class ProcessScanner(SignatureDatabase database, FileSystemScanner files)
{
    public async Task ScanAsync(ScanReport report, CancellationToken token)
    {
        foreach (Process process in Process.GetProcesses())
        {
            using (process)
            {
                token.ThrowIfCancellationRequested();
                report.Statistics.ProcessesChecked++;
                TextRule? processRule = database.Processes.FirstOrDefault(x =>
                    process.ProcessName.Equals(x.Value, StringComparison.OrdinalIgnoreCase));
                if (processRule is not null)
                    FileSystemScanner.AddUnique(report, new(FindingStatus.Suspicious, "PROCESS", processRule.Name,
                        "PROCESS NAME MATCH; executable signature not confirmed", $"PID {process.Id}: {process.ProcessName}"));
                if (processRule is null) continue;
                try
                {
                    string? executable = process.MainModule?.FileName;
                    if (!string.IsNullOrWhiteSpace(executable) && File.Exists(executable))
                        await files.InspectFileAsync(executable, false,
                            database.Paths.FirstOrDefault(x => executable.Contains(x.Value, StringComparison.OrdinalIgnoreCase)),
                            report, token);
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                    FileSystemScanner.RecordError(report, $"process:{process.ProcessName}:{process.Id}", ex);
                }
            }
        }
    }
}
