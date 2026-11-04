[CmdletBinding()]
param(
    [string]$PackageName = 'lsmon-membership-role-migration-v2',
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\artifacts\membership-role-migration-v2')
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$migration = Join-Path $repo 'lsmon_core\migrations\0041_alter_membership_role.py'
$activator = Join-Path $repo 'deployment\activate-membership-role-migration.sh'

foreach ($path in @($migration, $activator)) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required package source is missing: $path"
    }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$stage = Join-Path $OutputDirectory $PackageName
Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $stage | Out-Null

Copy-Item -LiteralPath $migration -Destination $stage
Copy-Item -LiteralPath $activator -Destination $stage

$readme = @'
LSMON membership role migration package

Purpose: apply only lsmon_core migration 0041 on vmi3626301.

Before execution:
1. Verify the accompanying SHA-256 checksum.
2. Upload and extract this folder at /home/ubuntu/lsmon-membership-role-migration-v2.
3. Run the activator as root.

The activator creates a PostgreSQL custom-format rollback dump, installs only
0041_alter_membership_role.py, runs `manage.py migrate lsmon_core 0041 --noinput`,
and verifies the portal remains active. It does not restart a service or change
Wazuh, GLPI, Acronis, Cloudflare, ports, endpoints, or credentials.
'@
Set-Content -LiteralPath (Join-Path $stage 'README.txt') -Value $readme -NoNewline

$archive = Join-Path $OutputDirectory "$PackageName.tar.gz"
$checksum = "$archive.sha256"
Remove-Item -LiteralPath $archive,$checksum -Force -ErrorAction SilentlyContinue

& tar.exe -C $OutputDirectory -czf $archive $PackageName
if ($LASTEXITCODE -ne 0) { throw 'tar archive creation failed.' }

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
Set-Content -LiteralPath $checksum -Value "$hash  $PackageName.tar.gz" -NoNewline

Write-Output "Archive: $archive"
Write-Output "Checksum: $checksum"
Write-Output "SHA256: $hash"
