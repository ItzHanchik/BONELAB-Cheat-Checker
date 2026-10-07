using System.Windows;
using SynapseChecker.Scanner;

namespace SynapseChecker;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (e.Args.Any(x => x.Equals("--self-test", StringComparison.OrdinalIgnoreCase)))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            try
            {
                await SelfTestRunner.RunAsync(Path.Combine(AppContext.BaseDirectory, "signatures"));
                Shutdown(0);
            }
            catch { Shutdown(3); }
            return;
        }
        int verify = Array.FindIndex(e.Args, x => x.Equals("--verify-root", StringComparison.OrdinalIgnoreCase));
        if (verify >= 0 && verify + 1 < e.Args.Length && Directory.Exists(e.Args[verify + 1]))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            try
            {
                var scanner = new ScanCoordinator(Path.Combine(AppContext.BaseDirectory, "signatures"));
                await scanner.ScanAsync(null, CancellationToken.None, new[] { e.Args[verify + 1] });
                Shutdown(0);
            }
            catch { Shutdown(2); }
            return;
        }
        new MainWindow().Show();
    }
}
