[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')]
    [string]$ReleaseId = ("lsmon-{0}" -f (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss")),

    [string]$OutputDirectory = 'artifacts',

    [switch]$RunDjangoChecks
)

$ErrorActionPreference = 'Stop'

$PortalRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
}
else {
    $OutputDirectory = [System.IO.Path]::GetFullPath((Join-Path $PortalRoot $OutputDirectory))
}
$ArchiveName = "$ReleaseId.tar.gz"
$ArchivePath = Join-Path $OutputDirectory $ArchiveName
$ChecksumPath = "$ArchivePath.sha256"
$ManifestPath = Join-Path $OutputDirectory "$ReleaseId.manifest.json"

$ExcludedDirectoryNames = @(
    '.git', '.mypy_cache', '.pytest_cache', '.venv', '__pycache__',
    'artifacts', 'node_modules', 'venv'
)
$ExcludedFilePatterns = @(
    '*.key', '*.pem', '*.pyo', '*.pyc', '*.sqlite3', '.env', '.env.*',
    'id_ed25519', 'id_rsa'
)

function Test-IsExcludedPath {
    param([System.IO.FileSystemInfo]$Item)

    $relative = [System.IO.Path]::GetRelativePath($PortalRoot, $Item.FullName)
    $segments = $relative -split '[\\/]'
    if ($segments | Where-Object { $ExcludedDirectoryNames -contains $_ }) {
        return $true
    }

    foreach ($pattern in $ExcludedFilePatterns) {
        if ($Item.Name -like $pattern) {
            return $true
        }
    }

    return $false
}

if (-not (Test-Path (Join-Path $PortalRoot 'manage.py') -PathType Leaf)) {
    throw "manage.py was not found under $PortalRoot. Run this script from the LSMON portal source tree."
}
if (-not (Test-Path (Join-Path $PortalRoot 'requirements.txt') -PathType Leaf)) {
    throw "requirements.txt was not found under $PortalRoot."
}
if (-not (Get-Command tar.exe -ErrorAction SilentlyContinue)) {
    throw 'tar.exe is required to create the release archive.'
}
if (Test-Path $ArchivePath) {
    throw "Refusing to overwrite existing archive: $ArchivePath"
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$StageRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("lsmon-release-" + [guid]::NewGuid())
$PackageRoot = Join-Path $StageRoot 'lsmon-portal'
$DjangoCheckRan = $false

try {
    New-Item -ItemType Directory -Path $PackageRoot -Force | Out-Null

    if ($RunDjangoChecks) {
        Push-Location $PortalRoot
        try {
            & python manage.py check
            if ($LASTEXITCODE -ne 0) {
                throw "Django system checks failed with exit code $LASTEXITCODE."
            }
            $DjangoCheckRan = $true
        }
        finally {
            Pop-Location
        }
    }

    Get-ChildItem -LiteralPath $PortalRoot -Recurse -Force |
        Sort-Object FullName |
        ForEach-Object {
            if (Test-IsExcludedPath $_) {
                return
            }

            $relative = [System.IO.Path]::GetRelativePath($PortalRoot, $_.FullName)
            $destination = Join-Path $PackageRoot $relative

            if ($_.PSIsContainer) {
                New-Item -ItemType Directory -Path $destination -Force | Out-Null
            }
            else {
                $parent = Split-Path -Parent $destination
                New-Item -ItemType Directory -Path $parent -Force | Out-Null
                Copy-Item -LiteralPath $_.FullName -Destination $destination -Force
            }
        }

    & tar.exe -czf $ArchivePath -C $StageRoot 'lsmon-portal'
    if ($LASTEXITCODE -ne 0) {
        throw "tar.exe failed with exit code $LASTEXITCODE."
    }

    $hash = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath $ChecksumPath -Value "$hash  $ArchiveName" -Encoding ascii -NoNewline

    [ordered]@{
        release_id       = $ReleaseId
        generated_utc    = (Get-Date).ToUniversalTime().ToString('o')
        archive          = $ArchiveName
        sha256           = $hash
        django_check_ran = $DjangoCheckRan
        excluded_directories = $ExcludedDirectoryNames
        excluded_file_patterns = $ExcludedFilePatterns
        activation       = 'Not performed. This package is for staged deployment only.'
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ManifestPath -Encoding utf8

    Write-Host "Release archive: $ArchivePath"
    Write-Host "Checksum:        $ChecksumPath"
    Write-Host "Manifest:        $ManifestPath"
    Write-Host "SHA-256:         $hash"
}
finally {
    if (Test-Path $StageRoot) {
        Remove-Item -LiteralPath $StageRoot -Recurse -Force
    }
}
