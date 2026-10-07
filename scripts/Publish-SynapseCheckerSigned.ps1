[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$CertificateThumbprint,

    [string]$Configuration = 'Release',
    [string]$Runtime = 'win-x64',
    [string]$TimestampUrl = 'http://timestamp.digicert.com',
    [string]$OutputDirectory,
    [string]$ArchivePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent $PSScriptRoot
$projectPath = Join-Path $projectRoot 'SynapseChecker\SynapseChecker.csproj'
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectRoot "artifacts\SynapseChecker-signed-$Runtime"
}
if ([string]::IsNullOrWhiteSpace($ArchivePath)) {
    $ArchivePath = "$OutputDirectory.zip"
}
if (Test-Path -LiteralPath $OutputDirectory) {
    throw "Output directory already exists: $OutputDirectory"
}
if (Test-Path -LiteralPath $ArchivePath) {
    throw "Archive already exists: $ArchivePath"
}

$thumbprint = $CertificateThumbprint.Replace(' ', '').ToUpperInvariant()
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$thumbprint" -ErrorAction Stop
if (-not $certificate.HasPrivateKey) {
    throw 'The selected certificate has no private key.'
}
$codeSigningOid = '1.3.6.1.5.5.7.3.3'
if (-not (@($certificate.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.ToString() }) -contains $codeSigningOid)) {
    throw 'The selected certificate is not valid for code signing.'
}
if ($certificate.NotAfter -le (Get-Date)) {
    throw 'The selected certificate has expired.'
}

$signTool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Filter signtool.exe -Recurse -ErrorAction Stop |
    Where-Object FullName -Match '\\x64\\signtool\.exe$' |
    Sort-Object FullName -Descending |
    Select-Object -First 1 -ExpandProperty FullName
if ([string]::IsNullOrWhiteSpace($signTool)) {
    throw 'signtool.exe from the Windows SDK was not found.'
}

dotnet publish $projectPath -c $Configuration -r $Runtime --self-contained true -o $OutputDirectory
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE." }

$targets = @(
    (Join-Path $OutputDirectory 'SynapseChecker.exe'),
    (Join-Path $OutputDirectory 'SynapseChecker.dll')
)
foreach ($target in $targets) {
    if (-not (Test-Path -LiteralPath $target)) { throw "Signing target is missing: $target" }
    & $signTool sign /sha1 $thumbprint /s My /fd SHA256 /tr $TimestampUrl /td SHA256 /d 'Synapse Checker' $target
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed for $target." }
    & $signTool verify /pa /all $target
    if ($LASTEXITCODE -ne 0) { throw "Authenticode verification failed for $target." }
}

$signatureLines = @(
    'Synapse Checker — Authenticode build',
    "Publisher: $($certificate.Subject)",
    "Certificate thumbprint: $thumbprint",
    "Certificate expires (UTC): $($certificate.NotAfter.ToUniversalTime().ToString('O'))",
    "Timestamp server: $TimestampUrl",
    "Executable SHA-256: $((Get-FileHash -Algorithm SHA256 -LiteralPath $targets[0]).Hash)",
    "Assembly SHA-256: $((Get-FileHash -Algorithm SHA256 -LiteralPath $targets[1]).Hash)"
)
$signatureLines | Set-Content -LiteralPath (Join-Path $OutputDirectory 'SIGNATURE.txt') -Encoding UTF8

Compress-Archive -Path (Join-Path $OutputDirectory '*') -DestinationPath $ArchivePath -CompressionLevel Optimal
$archiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ArchivePath).Hash
Write-Host "Signed archive: $ArchivePath"
Write-Host "SHA-256: $archiveHash"
