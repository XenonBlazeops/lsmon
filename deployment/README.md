# LSMON release packaging and staging

This workflow separates **packaging and staging** from **activation**. It is designed to make a release available for review without changing the live portal.

## Build a release on the local workstation

From PowerShell:

```powershell
Set-Location D:\CodeX\LSMON\portal
.\deployment\Build-LsmonRelease.ps1 -RunDjangoChecks
```

The script creates these files under `artifacts\<release-id>\`:

- `<release-id>.tar.gz` — source archive
- `<release-id>.tar.gz.sha256` — SHA-256 integrity file
- `<release-id>.manifest.json` — build metadata

The source archive excludes local secrets, virtual environments, caches, local SQLite databases, and private-key files.

## Stage a verified release on the server

Copy the archive, checksum file, and `stage-lsmon-release.sh` to a temporary location on the server. Then run:

```bash
sudo bash stage-lsmon-release.sh RELEASE_ID /path/RELEASE_ID.tar.gz /path/RELEASE_ID.tar.gz.sha256
```

The script verifies the SHA-256 checksum and safely extracts the package to:

```text
/opt/lsmon-portal/releases/RELEASE_ID
```

## What staging does not do

Staging does **not**:

- switch the active release;
- restart or start services or containers;
- run database migrations;
- edit Docker, Nginx, Cloudflare, ports, or application configuration;
- modify production database or application data.

Activation must be a separately reviewed step with explicit approval. Before activation, record the current release, confirm a database backup, review migrations, and define health and rollback checks.

## Reconcile a local source tree with production

Do not package a new release from a local source tree until it has been checked
against the live portal source. This is especially important after a hotfix was
applied directly to production.

Copy `export-live-source-snapshot.sh` to the server and run it as root:

```bash
install -m 0700 export-live-source-snapshot.sh /root/export-live-source-snapshot.sh
/root/export-live-source-snapshot.sh
```

It creates a source-only archive under `/home/ubuntu/lsmon-live-source-snapshots`
with an SHA-256 checksum and a small manifest. It deliberately excludes runtime
state, the virtual environment, staged releases, local databases, environment
files, and private key material. The export changes no service, database,
container, port, or application setting.

Download all three generated files to the workstation and verify the checksum
before using that archive as the local reconciliation baseline. This export is
not a disaster-recovery artifact; the root-only restore point and Acronis are
the recovery sources.
