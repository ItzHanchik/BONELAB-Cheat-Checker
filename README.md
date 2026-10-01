# BONELAB Cheat Checker

Public source and signed releases for the defensive BONELAB Cheat Checker maintained by BoneZ.

Download verified builds from [GitHub Releases](https://github.com/irembo337/BONELAB-Cheat-Checker/releases).

The application scans local BONELAB, MelonLoader, Fusion and verified Discord Data
Package artifacts without executing discovered DLLs. Suspicious managed assemblies
can be preserved and decompiled into isolated evidence projects for manual review.

Full documentation: [`BoneZAntiCheat/README.md`](BoneZAntiCheat/README.md).

## Build and test

```powershell
dotnet build BoneZAntiCheat/BoneZAntiCheat.csproj -c Release
dotnet BoneZAntiCheat/bin/Release/net9.0-windows/Checker.dll --self-test
```

Runtime reports, evidence archives, binaries, local certificates and private keys
are intentionally excluded from this repository.

