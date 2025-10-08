# TidyUpCat v1.1

A PowerShell 5.x script that provides a **universal, safe, and auditable cleanup and archival process** for Windows user profiles.  
It works seamlessly across both file-based and container-based profiles (FSLogix, Citrix UPM, or UPL).

---

## 🧩 Overview

`TidyUpCat.ps1` scans a target path for user profile directories, determines their **last-use age** based on defined indicators (e.g., `NTUSER.DAT` or `.vhdx` timestamps), and automatically **archives or removes** those exceeding a specified threshold.

It was designed to work hand-in-hand with [`Make-FakeProfiles`](../Make-FakeProfiles), but is fully production-ready and safe for use in real Citrix / FSLogix environments when run with administrative privileges.

---

## ⚙️ Parameters

| Parameter | Type | Default | Description |
|------------|------|----------|-------------|
| `-BaseProfilePath` | `String` | *(Required)* | Parent directory containing user profile folders. |
| `-ArchiveDir` | `String` | `"_Expired-{timestamp}"` | Destination archive directory. If omitted, a new one is auto-created under the base path. |
| `-ProfileType` | `Enum` | `File` or `Container` | Filter for file-based or container-based profiles. If omitted, both types are processed. |
| `-FileIndicator` | `Enum` | `NtUser` | Used to determine last-write timestamp for file-based profiles. Options: `NtUser`, `UsrClass`, `Temp`, `Root`. |
| `-ProfileAgeDays` | `Int` | *(Required)* | Age threshold in days; profiles older than this will be archived. |
| `-RecursiveContainer` | `Switch` | — | If set, searches subfolders recursively for container files. By default, only checks profile root. |
| `-IncludeRegex` | `String` | — | Include only profiles whose names match this regex. |
| `-ExcludeRegex` | `String` | — | Exclude profiles whose names match this regex. |
| `-ExcludeList` | `String` | — | Path to text file containing regex patterns (one per line) for profiles to skip. |
| `-Force` | `Switch` | — | Required if operating on root-like paths (e.g., `C:\Users`). Also suppresses confirmation prompts. |
| `-DryRun` | `Switch` | — | Simulate all operations without modifying the filesystem. |
| `-Verbose` | `Switch` | — | Enable detailed runtime output for debugging. |

---

## 🧠 Key Features

### Intelligent Profile Discovery
- Automatically detects both **file-based** (`NTUSER.DAT`, etc.) and **container-based** (`*.vhd*`) profiles.  
- Excludes reserved and previously archived folders (e.g., `_Expired-*`, `_DryRunLogs-*`).

### Safe & Auditable Archiving
- Uses **`robocopy /COPY:DATSO /B`** to preserve file ownership, ACLs, and timestamps.  
- Performs **two-pass verification** (counts/bytes + sampled hash comparison).  
- Automatically **cleans up destination** if verification fails.

### Elevation Enforcement
- Script requires elevation (Run as Administrator) for real operations to preserve ownership integrity.  
- **DryRun mode** can be executed without elevation for simulation or validation.

### Log & Manifest Output
- Outputs both a **CSV manifest** and **plain-text log** under the archive directory.  
- Manifest includes: profile type, indicator, timestamp, action taken, and verification result.  
- Displays compact summary in console (no whitespace bloat).

---

## 🚀 Examples

### DryRun — File Profiles, 90+ Days Old
```powershell
.\TidyUpCat.ps1 -BaseProfilePath D:\Profiles -ProfileType File -ProfileAgeDays 90 -DryRun
```

### Real Run — Both File and Container Profiles, Archive to Custom Path
```powershell
.\TidyUpCat.ps1 -BaseProfilePath D:\Profiles -ArchiveDir \\Server\Archive -ProfileAgeDays 120 -Force
```

### Container-Only Cleanup (FSLogix / Citrix UPL)
```powershell
.\TidyUpCat.ps1 -BaseProfilePath D:\Profiles -ProfileType Container -ProfileAgeDays 60
```

---

## 🧾 Output Manifest Example

| ProfileName | Type | Indicator | When | AgeDays | Action | Reason |
|--------------|------|-----------|------|----------|---------|--------|
| `jdoe` | File | NtUser | 2025-03-01 14:52 | 210 | Archived | Verified OK |
| `bsmith` | Container | ContainerVHDX | 2025-07-20 09:11 | 80 | Skip | NotExpired |
| `_Expired-20251007-162315` | Skipped | — | — | — | Skip | Filtered/Reserved |

---

## 🧰 Logging & Verification

- CSV manifest: `TidyUpCat-<timestamp>.csv`
- Plain-text log: `TidyUpCat-<timestamp>.log`
- Each includes full path, timestamps, reasons, and results.

Verification logic includes:
1. File count & total bytes match.  
2. Up to 25 sampled file hashes match (`Get-FileHash SHA256`).  
3. Destination cleaned up if verification fails.

---

## 🛠 Requirements

- **PowerShell 5.x**
- **Administrative privileges** (required for actual cleanup).  
- Windows environment with **robocopy** available in `PATH`.

---

## 🧯 Safety Features

- Root path guard (`C:\Users`, drive roots) requires `-Force`.  
- Automatic skip for archive and temporary folders.  
- DryRun mode prevents destructive actions.  
- Robust logging for post-run audit and rollback support.

---

## 🧰 Version History

| Version | Changes |
|----------|----------|
| **v1.0** | Initial release. Core profile scanning, robocopy-based archival, CSV manifest. |
| **v1.1** | Added elevation enforcement, quiet progress mode, robust verification, and container filtering fixes. |

---

© 2025 — *TidyUpCat PowerShell utility*  
Created by Steve Szuster
