<#
.SYNOPSIS
  TidyUpCatv1.1 — Universal Profile Cleanup & Archival Tool (PowerShell 5)

.DESCRIPTION
  - Identifies stale user profiles by indicator timestamps.
  - File-based profiles (default indicator NTUSER.DAT) and Container-based (*.vhd*).
  - Copy → Verify → Remove using robocopy (preserve Owner + ACLs).
  - Requires elevation for real runs (to preserve Owner/ACLs). DryRun allowed unelevated (warns).
  - Console output is kept clean: progress is suppressed unless -Verbose, final table prints directly.

.PARAMETER BaseProfilePath
  Parent directory containing user profile folders.

.PARAMETER ArchiveDir
  Destination archive root. If omitted, creates _Expired-YYYYMMDD-HHMMSS under BaseProfilePath.

.PARAMETER ProfileType
  File | Container (omit to process both)

.PARAMETER FileIndicator
  NtUser (default) | UsrClass | Temp | Root
  If omitted, ONLY NtUser is used (by design).

.PARAMETER ProfileAgeDays
  Expiry threshold in days.

.PARAMETER RecursiveContainer
  Search subdirectories for *.vhd* (default is profile-root-only).

.PARAMETER IncludeRegex / ExcludeRegex / ExcludeList
  Name filtering (case-insensitive). ExcludeList is a text file of regex patterns.

.PARAMETER Force
  Skip confirmation and allow root-like paths (e.g., C:\Users).

.PARAMETER DryRun (alias: WhatIf)
  Simulate without changing the filesystem. DryRun can run non-elevated.

.NOTES
  - Windows PowerShell 5.x
  - robocopy in PATH
  - Real runs require elevation (Administrator) to preserve Owner (/B + /COPY:DATSO).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BaseProfilePath,

    [string]$ArchiveDir,

    [ValidateSet('File', 'Container')]
    [string]$ProfileType, # optional; omit → both

    [ValidateSet('NtUser', 'UsrClass', 'Temp', 'Root')]
    [string]$FileIndicator = 'NtUser',

    [Parameter(Mandatory = $true)]
    [int]$ProfileAgeDays,

    [switch]$RecursiveContainer,

    [string]$IncludeRegex,
    [string]$ExcludeRegex,
    [string]$ExcludeList,

    [switch]$Force,

    [Alias('WhatIf')]
    [switch]$DryRun
)

#region ---- Helpers & Setup ----

$ErrorActionPreference = 'Stop'

# Keep console tidy: suppress progress unless -Verbose was provided
if (-not $PSBoundParameters.ContainsKey('Verbose')) {
    $global:ProgressPreference = 'SilentlyContinue'
}

function Write-Log {
    param([string]$Message)
    Write-Host $Message
    if ($script:TextLogPath) {
        $Message | Out-File -FilePath $script:TextLogPath -Encoding UTF8 -Append
    }
}

function Test-IsElevated {
    try {
        $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
        $wp = New-Object Security.Principal.WindowsPrincipal($wi)
        return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Test-RootLikePath {
    param([string]$Path)
    try {
        $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($fi.PSIsContainer) {
            if ($Path -match '^[A-Za-z]:\\$') { return $true } # drive root
            $full = $fi.FullName.TrimEnd('\')
            if ($full -ieq 'C:\Users') { return $true }
        }
        return $false
    }
    catch { return $false }
}

function New-EnsuredDirectory {
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$DryRun)
    if (Test-Path -LiteralPath $Path) { return }
    if ($DryRun) { Write-Log "[DryRun] Would create directory: $Path" }
    else { New-Item -Path $Path -ItemType Directory -Force | Out-Null }
}

# Quick signature: SHA256 for small files, length+timestamp as fallback
function Get-FileQuickSig {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($fi.Length -gt 0 -and $fi.Length -le 5MB) {
            $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop
            return "{0}:{1}" -f $fi.Length, $hash.Hash
        }
        else {
            return "{0}:{1}" -f $fi.Length, $fi.LastWriteTimeUtc.Ticks
        }
    }
    catch {
        return "ERR:{0}" -f $_.Exception.GetType().Name
    }
}

# Build timestamped names
$now = Get-Date
$stamp = $now.ToString('yyyyMMdd-HHmmss')

# Resolve base path
if (-not (Test-Path -LiteralPath $BaseProfilePath)) {
    throw "BaseProfilePath not found: $BaseProfilePath"
}
$BaseProfilePath = (Get-Item -LiteralPath $BaseProfilePath).FullName

# Elevation requirement
$IsElevated = Test-IsElevated
if (-not $IsElevated -and -not $DryRun) {
    throw "TidyUpCat requires an elevated PowerShell session (Run as Administrator) to preserve Owner/ACLs."
}
if (-not $IsElevated -and $DryRun) {
    Write-Warning "Running DryRun without elevation. Real runs require elevation to preserve Owner/ACLs."
}

# Guard rails
if ((Test-RootLikePath -Path $BaseProfilePath) -and -not $Force) {
    throw "Refusing to operate on root-like path '$BaseProfilePath' without -Force."
}

# Determine archive dir (real runs) and log dir
if ([string]::IsNullOrWhiteSpace($ArchiveDir)) {
    $ArchiveDir = Join-Path -Path $BaseProfilePath -ChildPath ("_Expired-{0}" -f $stamp)
}
if ($DryRun) { $LogDir = Join-Path -Path $BaseProfilePath -ChildPath ("_DryRunLogs-{0}" -f $stamp) }
else { $LogDir = $ArchiveDir }

New-EnsuredDirectory -Path $LogDir -DryRun:$DryRun
$script:CsvPath = Join-Path -Path $LogDir -ChildPath ("TidyUpCat-{0}.csv" -f $stamp)
$script:TextLogPath = Join-Path -Path $LogDir -ChildPath ("TidyUpCat-{0}.log" -f $stamp)

Write-Log "TidyUpCatv1.1 starting @ $($now.ToString('u'))"
Write-Log "BaseProfilePath : $BaseProfilePath"
Write-Log "ArchiveDir      : $ArchiveDir" 
Write-Log "LogDir          : $LogDir"
Write-Log "DryRun          : $DryRun"
Write-Log "ProfileType     : $ProfileType (blank = both)"
Write-Log "FileIndicator   : $FileIndicator"
Write-Log "ProfileAgeDays  : $ProfileAgeDays"
Write-Log "RecursiveContainer : $RecursiveContainer"
if ($IncludeRegex) { Write-Log "IncludeRegex     : $IncludeRegex" }
if ($ExcludeRegex) { Write-Log "ExcludeRegex     : $ExcludeRegex" }
if ($ExcludeList) { Write-Log "ExcludeList      : $ExcludeList" }

# Compile exclude list patterns (regex)
$excludePatterns = @()
if ($ExcludeList) {
    if (Test-Path -LiteralPath $ExcludeList) {
        $lines = Get-Content -LiteralPath $ExcludeList -ErrorAction Stop
        foreach ($ln in $lines) {
            $t = $ln.Trim()
            if ($t.Length -gt 0 -and -not $t.StartsWith('#')) { $excludePatterns += $t }
        }
        Write-Log ("Loaded {0} exclude patterns from {1}" -f $excludePatterns.Count, $ExcludeList)
    }
    else {
        Write-Log "WARNING: ExcludeList path not found: $ExcludeList"
    }
}

function Test-ProfileNameShouldSkip {
    param([string]$Name)
    if ($IncludeRegex) { if ($Name -notmatch $IncludeRegex) { return $true } }
    if ($ExcludeRegex) { if ($Name -match $ExcludeRegex) { return $true } }
    foreach ($rx in $excludePatterns) { if ($Name -match $rx) { return $true } }
    if ($Name -like '_Expired-*') { return $true }
    if ($Name -like '_DryRunLogs-*') { return $true }
    return $false
}

# Discovery helpers
function Get-ContainerIndicators {
    param([Parameter(Mandatory = $true)][string]$ProfilePath, [switch]$Recurse)
    $opt = @()
    try {
        if ($Recurse) {
            $opt = Get-ChildItem -LiteralPath $ProfilePath -Recurse -Force -File -Filter '*.vhd*' -ErrorAction SilentlyContinue
        }
        else {
            $opt = Get-ChildItem -LiteralPath $ProfilePath -Force -File -Filter '*.vhd*' -ErrorAction SilentlyContinue
        }
    }
    catch {}
    return $opt
}

function Get-FileIndicatorPath {
    param([Parameter(Mandatory = $true)][string]$ProfilePath, [Parameter(Mandatory = $true)][string]$IndicatorName)
    switch ($IndicatorName) {
        'NtUser' { return Join-Path -Path $ProfilePath -ChildPath 'NTUSER.DAT' }
        'UsrClass' { return Join-Path -Path $ProfilePath -ChildPath 'AppData\Local\Microsoft\Windows\UsrClass.dat' }
        'Temp' { return Join-Path -Path $ProfilePath -ChildPath 'AppData\Local\Temp' }
        'Root' { return $ProfilePath }
        default { return $null }
    }
}

# Robocopy copy (always preserve Owner/ACLs, use backup mode; two passes)
function Invoke-RoboCopyCopy {
    param([Parameter(Mandatory = $true)][string]$Src, [Parameter(Mandatory = $true)][string]$Dst, [switch]$DryRun)
    New-EnsuredDirectory -Path $Dst -DryRun:$DryRun
    $baseArgs = @('/E', '/COPY:DATSO', '/DCOPY:DAT', '/XJ', '/R:3', '/W:2', '/NFL', '/NDL', '/NP', '/MT:16', '/B')
    $rc1 = @($Src, $Dst) + $baseArgs
    $rc2 = @($Src, $Dst) + $baseArgs
    if ($DryRun) { $rc1 += '/L'; $rc2 += '/L' }
    $cmd1 = 'robocopy ' + ($rc1 -join ' ')
    $cmd2 = 'robocopy ' + ($rc2 -join ' ')
    Write-Log "RCOPY1: $cmd1"
    if (-not $DryRun) { & robocopy @rc1 | Out-Null }
    $exit1 = $LASTEXITCODE
    Write-Log ("Copy pass1 exit: {0}" -f $exit1)

    Write-Log "RCOPY2: $cmd2"
    if (-not $DryRun) { & robocopy @rc2 | Out-Null }
    $exit2 = $LASTEXITCODE
    Write-Log ("Copy pass2 exit: {0}" -f $exit2)

    return [pscustomobject]@{ Pass1 = $exit1; Pass2 = $exit2 }
}

function Get-TreeStats {
    param([Parameter(Mandatory = $true)][string]$Path)
    $files = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue)
    $dirs = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -Directory -ErrorAction SilentlyContinue)
    [pscustomobject]@{
        FileCount  = $files.Count
        TotalBytes = ($files | Measure-Object -Property Length -Sum).Sum
        DirCount   = $dirs.Count
        Files      = $files
    }
}

#endregion

#region ---- Scan Profiles ----

$candidates = @(Get-ChildItem -LiteralPath $BaseProfilePath -Directory -Force -ErrorAction Stop)
$results = @()

$threshold = (Get-Date).AddDays(-1 * $ProfileAgeDays)

Write-Log "Discovered $($candidates.Count) candidate profile folders."

if (-not $DryRun -and -not $Force) {
    $confirm = Read-Host "About to SCAN and potentially ARCHIVE profiles under '$BaseProfilePath'. Proceed? (Y/N)"
    if ($confirm -notin @('Y', 'y', 'Yes', 'yes')) { Write-Log "Aborted by user."; return }
}

if (-not $DryRun) { New-EnsuredDirectory -Path $ArchiveDir -DryRun:$false }

foreach ($dir in $candidates) {
    $name = $dir.Name
    if (Test-ProfileNameShouldSkip -Name $name) {
        $results += [pscustomobject]@{ ProfileName = $name; ProfilePath = $dir.FullName; Type = 'Skipped'; Indicator = ''; IndicatorPath = '';
            IndicatorTimestamp = $null; AgeDays = $null; Action = 'Skip'; Reason = 'Filtered/Reserved'; ArchivePath = '' 
        }
        continue
    }

    $containers = Get-ContainerIndicators -ProfilePath $dir.FullName -Recurse:$RecursiveContainer
    $hasContainer = ($containers -and $containers.Count -gt 0)

    $evalFile = $true; $evalContainer = $true
    if ($ProfileType) { $evalFile = ($ProfileType -eq 'File'); $evalContainer = ($ProfileType -eq 'Container') }

    # ---- File profile evaluation ----
    if ($evalFile) {
        $indPath = Get-FileIndicatorPath -ProfilePath $dir.FullName -IndicatorName $FileIndicator

        if ($hasContainer -and (-not (Test-Path -LiteralPath $indPath))) {
            # Container-only while File-only requested → skip quietly.
            $results += [pscustomobject]@{
                ProfileName = $name; ProfilePath = $dir.FullName; Type = 'File'; Indicator = $FileIndicator;
                IndicatorPath = $indPath; IndicatorTimestamp = $null; AgeDays = $null; Action = 'Skip';
                Reason = 'ContainerProfile-Filtered'; ArchivePath = ''
            }
        }
        elseif (-not (Test-Path -LiteralPath $indPath)) {
            $results += [pscustomobject]@{
                ProfileName = $name; ProfilePath = $dir.FullName; Type = 'File'; Indicator = $FileIndicator; IndicatorPath = $indPath;
                IndicatorTimestamp = $null; AgeDays = $null; Action = 'Skip'; Reason = 'MISSING-INDICATOR'; ArchivePath = ''
            }
        }
        else {
            try {
                $item = Get-Item -LiteralPath $indPath -Force -ErrorAction Stop
                $ts = $item.LastWriteTime
                $ageDays = [int]([math]::Floor(((Get-Date) - $ts).TotalDays))
                $expired = ($ts -lt $threshold)

                $act = 'Skip'; $reason = 'NotExpired'
                if ($expired) { $act = 'Archive'; $reason = '' }

                $archiveDest = Join-Path -Path $ArchiveDir -ChildPath $name
                if ($act -eq 'Archive') {
                    $pre = Get-TreeStats -Path $dir.FullName
                    $null = Invoke-RoboCopyCopy -Src $dir.FullName -Dst $archiveDest -DryRun:$DryRun

                    if ($DryRun) {
                        $reason = 'DRYRUN'
                    }
                    else {
                        $post = Get-TreeStats -Path $archiveDest
                        $countsMatch = ($pre.FileCount -eq $post.FileCount) -and ($pre.TotalBytes -eq $post.TotalBytes)

                        # Sample up to 25 random files to compare quick signatures
                        $sampleCount = [math]::Min(25, $pre.Files.Count)
                        $sample = @()
                        if ($sampleCount -gt 0) { $sample = Get-Random -InputObject $pre.Files -Count $sampleCount }
                        $sigMismatch = $false
                        foreach ($sf in $sample) {
                            $rel = $sf.FullName.Substring($dir.FullName.Length).TrimStart('\')
                            $dstFile = Join-Path -Path $archiveDest -ChildPath $rel
                            if (-not (Test-Path -LiteralPath $dstFile)) { $sigMismatch = $true; break }
                            $sSrc = Get-FileQuickSig -Path $sf.FullName
                            $sDst = Get-FileQuickSig -Path $dstFile
                            if ($sSrc -ne $sDst) { $sigMismatch = $true; break }
                        }

                        if ($countsMatch -and -not $sigMismatch) {
                            # Scope progress suppression around removal, just in case user set -Verbose
                            $prev = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
                            try {
                                Remove-Item -LiteralPath $dir.FullName -Recurse -Force -ErrorAction Stop
                                $reason = 'Archived'
                            }
                            catch {
                                $act = 'Skip'
                                $reason = 'FAILED-REMOVE: ' + $_.Exception.Message
                            }
                            finally {
                                $ProgressPreference = $prev
                            }
                        }
                        else {
                            $act = 'Skip'
                            $reason = if (-not $countsMatch) { 'FAILED-VERIFY (counts/bytes)' } else { 'FAILED-VERIFY (sample mismatch)' }
                            # cleanup destination to avoid dupes
                            try {
                                Write-Log "Verify failed; cleaning up destination: $archiveDest"
                                Remove-Item -LiteralPath $archiveDest -Recurse -Force -ErrorAction Stop
                            }
                            catch {
                                Write-Log "WARNING: Could not clean destination after failed verify: $($_.Exception.Message)"
                            }
                        }
                    }
                }

                $results += [pscustomobject]@{
                    ProfileName = $name; ProfilePath = $dir.FullName; Type = 'File'; Indicator = $FileIndicator; IndicatorPath = $indPath;
                    IndicatorTimestamp = $ts; AgeDays = $ageDays; Action = $act; Reason = $reason; ArchivePath = $archiveDest
                }
            }
            catch {
                $results += [pscustomobject]@{
                    ProfileName = $name; ProfilePath = $dir.FullName; Type = 'File'; Indicator = $FileIndicator; IndicatorPath = $indPath;
                    IndicatorTimestamp = $null; AgeDays = $null; Action = 'Skip'; Reason = ('ERROR: ' + $_.Exception.Message); ArchivePath = ''
                }
            }
        }
    }

    # ---- Container profile evaluation ----
    if ($evalContainer) {
        if ($hasContainer) {
            $chosen = $containers | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($containers.Count -gt 1) { Write-Log ("NOTICE: Multiple .vhd* files found in {0} — using {1}" -f $dir.FullName, $chosen.Name) }
            try {
                $ts = $chosen.LastWriteTime
                $ageDays = [int]([math]::Floor(((Get-Date) - $ts).TotalDays))
                $expired = ($ts -lt $threshold)

                $act = 'Skip'; $reason = 'NotExpired'
                if ($expired) { $act = 'Archive'; $reason = '' }

                $archiveDest = Join-Path -Path $ArchiveDir -ChildPath $name
                if ($act -eq 'Archive') {
                    $pre = Get-TreeStats -Path $dir.FullName
                    $null = Invoke-RoboCopyCopy -Src $dir.FullName -Dst $archiveDest -DryRun:$DryRun

                    if ($DryRun) {
                        $reason = 'DRYRUN'
                    }
                    else {
                        $post = Get-TreeStats -Path $archiveDest
                        $countsMatch = ($pre.FileCount -eq $post.FileCount) -and ($pre.TotalBytes -eq $post.TotalBytes)

                        $sampleCount = [math]::Min(25, $pre.Files.Count)
                        $sample = @()
                        if ($sampleCount -gt 0) { $sample = Get-Random -InputObject $pre.Files -Count $sampleCount }
                        $sigMismatch = $false
                        foreach ($sf in $sample) {
                            $rel = $sf.FullName.Substring($dir.FullName.Length).TrimStart('\')
                            $dstFile = Join-Path -Path $archiveDest -ChildPath $rel
                            if (-not (Test-Path -LiteralPath $dstFile)) { $sigMismatch = $true; break }
                            $sSrc = Get-FileQuickSig -Path $sf.FullName
                            $sDst = Get-FileQuickSig -Path $dstFile
                            if ($sSrc -ne $sDst) { $sigMismatch = $true; break }
                        }

                        if ($countsMatch -and -not $sigMismatch) {
                            $prev = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
                            try {
                                Remove-Item -LiteralPath $dir.FullName -Recurse -Force -ErrorAction Stop
                                $reason = 'Archived'
                            }
                            catch {
                                $act = 'Skip'
                                $reason = 'FAILED-REMOVE: ' + $_.Exception.Message
                            }
                            finally {
                                $ProgressPreference = $prev
                            }
                        }
                        else {
                            $act = 'Skip'
                            $reason = if (-not $countsMatch) { 'FAILED-VERIFY (counts/bytes)' } else { 'FAILED-VERIFY (sample mismatch)' }
                            try {
                                Write-Log "Verify failed; cleaning up destination: $archiveDest"
                                Remove-Item -LiteralPath $archiveDest -Recurse -Force -ErrorAction Stop
                            }
                            catch {
                                Write-Log "WARNING: Could not clean destination after failed verify: $($_.Exception.Message)"
                            }
                        }
                    }
                }

                $results += [pscustomobject]@{
                    ProfileName = $name; ProfilePath = $dir.FullName; Type = 'Container'; Indicator = 'ContainerVHD*';
                    IndicatorPath = $chosen.FullName; IndicatorTimestamp = $ts; AgeDays = $ageDays; Action = $act; Reason = $reason;
                    ArchivePath = $archiveDest
                }
            }
            catch {
                $results += [pscustomobject]@{
                    ProfileName = $name; ProfilePath = $dir.FullName; Type = 'Container'; Indicator = 'ContainerVHD*';
                    IndicatorPath = $chosen.FullName; IndicatorTimestamp = $null; AgeDays = $null; Action = 'Skip';
                    Reason = ('ERROR: ' + $_.Exception.Message); ArchivePath = ''
                }
            }
        }
        else {
            $results += [pscustomobject]@{
                ProfileName = $name; ProfilePath = $dir.FullName; Type = 'Container'; Indicator = 'ContainerVHD*';
                IndicatorPath = ''; IndicatorTimestamp = $null; AgeDays = $null; Action = 'Skip'; Reason = 'NoContainer-Filtered'; ArchivePath = ''
            }
        }
    }
}

#endregion

#region ---- Output & Summary ----

try {
    $results |
    Select-Object ProfileName, ProfilePath, Type, Indicator, IndicatorPath,
    @{n = 'IndicatorTimestamp'; e = { if ($_.IndicatorTimestamp) { $_.IndicatorTimestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { '' } } },
    AgeDays, Action, Reason, ArchivePath |
    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV manifest: $CsvPath"
}
catch {
    Write-Log "WARNING: Failed to write CSV: $($_.Exception.Message)"
}

# Print compact table directly (no Out-String padding)
$results |
Select-Object ProfileName, Type, Indicator,
@{n = 'When'; e = { if ($_.IndicatorTimestamp) { $_.IndicatorTimestamp.ToString('yyyy-MM-dd HH:mm') } else { '' } } },
AgeDays, Action, Reason |
Format-Table -AutoSize

$scanned = ($results | Where-Object { $_.Type -in @('File', 'Container') }).Count
$archived = ($results | Where-Object { $_.Action -eq 'Archive' }).Count
$skipped = ($results | Where-Object { $_.Action -eq 'Skip' }).Count

Write-Log "Scanned  : $scanned"
Write-Log "Archived : $archived"
Write-Log "Skipped  : $skipped"

if ($DryRun) { Write-Log "DryRun complete. Planned actions only. Logs at: $LogDir" }
else { Write-Log "Done. Archive directory: $ArchiveDir" }

#endregion
