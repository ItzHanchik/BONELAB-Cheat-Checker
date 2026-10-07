# Synapse Checker

Public source and signed releases for Synapse Checker, the defensive BONELAB cheat checker maintained by Synapse.

Download verified builds from [GitHub Releases](https://github.com/irembo337/BONELAB-Cheat-Checker/releases).

The application scans local BONELAB, MelonLoader, Fusion and verified Discord Data
Package artifacts without executing discovered DLLs. Suspicious managed assemblies
can be preserved and decompiled into isolated evidence projects for manual review.

Full documentation: [`SynapseChecker/README.md`](SynapseChecker/README.md).

## Build and test

```powershell
dotnet build SynapseChecker/SynapseChecker.csproj -c Release
dotnet SynapseChecker/bin/Release/net9.0-windows/SynapseChecker.dll --self-test
```

Runtime reports, evidence archives, binaries, local certificates and private keys
are intentionally excluded from this repository.

