<#
.SYNOPSIS
  Create fake Windows profile folders with realistic folder/file layout, adjustable timestamps,
  and a DryRun mode. Lets you pick a canonical "last used" indicator (NtUser, UsrClass, Temp, or Root).

.DESCRIPTION
  Supports:
    -ProfileQTY <int>        : number of profiles to create (default 30)
    -ProfileAgeDays <int>    : canonical age (in days) applied to the chosen -Indicator (default 30)
    -BasePath <string>       : where to create profiles (default current directory)
    -NameLength <int>        : randomized username length (default 8)
    -VarianceDays <int>      : +/- jitter for non-indicator items (default 3)  (alias: -Variance)
    -Indicator <enum>        : NtUser (default) | UsrClass | Temp | Root
    -DryRun                  : show actions without creating files
    -Verbose                 : standard verbose output

.EXAMPLES
  # Dry run, 20 profiles, canonical age 90 days, jitter ±7 days, default indicator NtUser
  .\Make-FakeProfiles.ps1 -ProfileQTY 20 -ProfileAgeDays 90 -VarianceDays 7 -BasePath "D:\TestProfiles" -DryRun

  # Real run, 30 profiles, use UsrClass.dat as the indicator, age 45 days
  .\Make-FakeProfiles.ps1 -ProfileQTY 30 -ProfileAgeDays 45 -Indicator UsrClass -BasePath "D:\TestProfiles"
#>

[CmdletBinding()]
param(
    [int]$ProfileQTY = 5,              # number of profiles to create
    [int]$ProfileAgeDays = 30,          # canonical age in days for chosen indicator
    [string]$BasePath = ".",            # where to create profiles
    [int]$NameLength = 8,               # length of randomized username
    [Alias('Variance')]
    [int]$VarianceDays = 3,             # +/- days jitter applied to non-indicator items
    [ValidateSet('NtUser', 'UsrClass', 'Temp', 'Root')]
    [string]$Indicator = 'NtUser',      # which item is the canonical telltale
    [switch]$DryRun                      # print actions only
)

#region ---- Top-level config ----
$ErrorActionPreference = 'Stop'

# Standard profile folders + ensure UsrClass path exists
$foldersToCreate = @(
    'Desktop', 'Documents', 'Downloads', 'Pictures', 'Music', 'Videos', 'Favorites',
    'Contacts', 'Links', 'Saved Games', 'Searches',
    'AppData\Local', 'AppData\Local\Temp', 'AppData\Roaming',
    'AppData\Local\Microsoft', 'AppData\Local\Microsoft\Windows' # for UsrClass.dat
)

# Files we want to simulate
$ntuserLikeFiles = @('ntuser.dat', 'ntuser.dat.LOG1', 'ntuser.dat.LOG2')
$usrclassRelative = 'AppData\Local\Microsoft\Windows\UsrClass.dat'
$usrclassLikeFiles = @(
    $usrclassRelative,
    'AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1',
    'AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2'
)

$minFileSizeKB = 2
$maxFileSizeKB = 64
$maxNameGenAttempts = 8
#endregion

function New-ZeroFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$SizeBytes
    )
    if ($DryRun) {
        Write-Host "[DryRun] Would create zero-file: $Path ($([math]::Round($SizeBytes/1KB,2)) KB)"
        return
    }
    try {
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        $buf = New-Object byte[] $SizeBytes
        [IO.File]::WriteAllBytes($Path, $buf)
    }
    catch {
        throw "Failed to write zero-file '$Path' : $($_.Exception.Message)"
    }
}

function Get-RandomAlphaNum([int]$len) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    -join ((1..$len) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

function Set-TimeStampsToDate {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][datetime]$DateTime
    )
    if ($DryRun) {
        Write-Host ("[DryRun] Would set timestamps on: {0} -> {1:yyyy-MM-dd HH:mm:ss}" -f $Path, $DateTime)
        return
    }
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $item.CreationTime = $DateTime
        $item.LastWriteTime = $DateTime
        $item.LastAccessTime = $DateTime
    }
    catch {
        Write-Warning "Unable to set timestamps for $Path : $($_.Exception.Message)"
    }
}

# Ensure BasePath exists (create if needed)
try {
    if (-not (Test-Path -LiteralPath $BasePath)) {
        if ($DryRun) { Write-Host "[DryRun] Would create base path: $BasePath" }
        else { New-Item -Path $BasePath -ItemType Directory -Force | Out-Null }
    }
    $BasePath = (Get-Item -LiteralPath $BasePath -ErrorAction Stop).FullName
}
catch {
    throw "BasePath check/creation failed: $($_.Exception.Message)"
}

# Quick write test (skip when DryRun)
if (-not $DryRun) {
    try {
        $testFile = Join-Path -Path $BasePath -ChildPath ".profile_create_test_$([guid]::NewGuid().ToString()).tmp"
        New-ZeroFile -Path $testFile -SizeBytes 512
        Remove-Item -LiteralPath $testFile -Force -ErrorAction SilentlyContinue
    }
    catch {
        throw "Write test failed in base path '$BasePath'. Ensure you have write permission. Error: $($_.Exception.Message)"
    }
}
else {
    Write-Host "[DryRun] Skipping write test in base path."
}

# Main create loop
$createdList = @()
for ($i = 1; $i -le $ProfileQTY; $i++) {

    # generate unique profile (username) name
    $attempt = 0
    do {
        $attempt++
        $user = Get-RandomAlphaNum -len $NameLength
        $profilePath = Join-Path -Path $BasePath -ChildPath $user
    } while ((Test-Path -LiteralPath $profilePath) -and ($attempt -lt $maxNameGenAttempts))

    if (Test-Path -LiteralPath $profilePath) {
        Write-Warning "Could not generate unique name after $maxNameGenAttempts attempts; skipping iteration $i."
        continue
    }

    Write-Host ("[{0}/{1}] Preparing profile: {2}" -f $i, $ProfileQTY, $user)

    try {
        # create root profile folder
        if ($DryRun) { Write-Host "[DryRun] Would create folder: $profilePath" }
        else { New-Item -Path $profilePath -ItemType Directory -Force | Out-Null }

        # create standard subfolders
        foreach ($f in $foldersToCreate) {
            $full = Join-Path -Path $profilePath -ChildPath $f
            if ($DryRun) { Write-Host "[DryRun] Would create folder: $full" }
            else { New-Item -Path $full -ItemType Directory -Force | Out-Null }
        }

        # create ntuser-like files (small zero-filled files)
        foreach ($nf in $ntuserLikeFiles) {
            $filePath = Join-Path -Path $profilePath -ChildPath $nf
            New-ZeroFile -Path $filePath -SizeBytes 4KB
        }

        # create usrclass-like files (small zero-filled files)
        foreach ($uf in $usrclassLikeFiles) {
            $filePath = Join-Path -Path $profilePath -ChildPath $uf
            New-ZeroFile -Path $filePath -SizeBytes 4KB
        }

        # create a few random placeholder files inside Documents and Desktop with random sizes
        $docsPath = Join-Path -Path $profilePath -ChildPath "Documents"
        $desktopPath = Join-Path -Path $profilePath -ChildPath "Desktop"
        foreach ($t in @($docsPath, $desktopPath)) {
            $fileCount = Get-Random -Minimum 1 -Maximum 4
            for ($fidx = 1; $fidx -le $fileCount; $fidx++) {
                $sizeKB = Get-Random -Minimum $minFileSizeKB -Maximum $maxFileSizeKB
                $fileName = "placeholder_{0}_{1}.bin" -f $fidx, (Get-Random -Maximum 9999)
                $filePath = Join-Path -Path $t -ChildPath $fileName
                New-ZeroFile -Path $filePath -SizeBytes ($sizeKB * 1KB)
            }
        }

        # create a small placeholder VHDX to mimic profile containers
        $vhdName = Join-Path -Path $profilePath -ChildPath ($user + ".vhdx")
        New-ZeroFile -Path $vhdName -SizeBytes 16KB

        # compute age values
        $canonicalDate = (Get-Date).AddDays(-1 * $ProfileAgeDays).Date
        $canonicalDate = $canonicalDate.AddSeconds( (Get-Random -Minimum 0 -Maximum 86399) )  # random time within the day

        $jitter = Get-Random -Minimum (-1 * $VarianceDays) -Maximum ($VarianceDays + 1)
        $ageDaysWithJitter = [math]::Max(0, $ProfileAgeDays + $jitter)
        $rootDate = (Get-Date).AddDays(-1 * $ageDaysWithJitter).AddSeconds( - (Get-Random -Maximum 86400))

        # Apply timestamps: root (jittered)
        Set-TimeStampsToDate -Path $profilePath -DateTime $rootDate

        # Apply timestamps to all children (jittered)
        $items = Get-ChildItem -LiteralPath $profilePath -Recurse -Force -ErrorAction SilentlyContinue
        foreach ($it in ($items | Where-Object { $_ -ne $null })) {
            $offsetSeconds = Get-Random -Minimum 0 -Maximum 86400
            $dt = (Get-Date).AddDays(-1 * $ageDaysWithJitter).AddSeconds(- $offsetSeconds)
            Set-TimeStampsToDate -Path $it.FullName -DateTime $dt
        }

        # Now set the chosen indicator EXACTLY to canonical age
        switch ($Indicator) {
            'NtUser' {
                foreach ($nf in $ntuserLikeFiles) {
                    $p = Join-Path -Path $profilePath -ChildPath $nf
                    Set-TimeStampsToDate -Path $p -DateTime $canonicalDate
                }
            }
            'UsrClass' {
                foreach ($uf in $usrclassLikeFiles) {
                    $p = Join-Path -Path $profilePath -ChildPath $uf
                    Set-TimeStampsToDate -Path $p -DateTime $canonicalDate
                }
            }
            'Temp' {
                $tempPath = Join-Path -Path (Join-Path -Path (Join-Path -Path $profilePath -ChildPath 'AppData') -ChildPath 'Local') -ChildPath 'Temp'
                if (-not (Test-Path -LiteralPath $tempPath)) {
                    if ($DryRun) { Write-Host "[DryRun] Would ensure Temp folder exists: $tempPath" }
                    else { New-Item -Path $tempPath -ItemType Directory -Force | Out-Null }
                }
                Set-TimeStampsToDate -Path $tempPath -DateTime $canonicalDate
            }
            'Root' {
                Set-TimeStampsToDate -Path $profilePath -DateTime $canonicalDate
            }
        }

        # record created profile info (or would-be info)
        $createdList += [pscustomobject]@{
            ProfileName      = $user
            ProfilePath      = $profilePath
            Indicator        = $Indicator
            IndicatorDate    = $canonicalDate
            RootTimestamp    = $rootDate
            AgeDaysCanonical = $ProfileAgeDays
            AgeDaysApplied   = $ageDaysWithJitter
        }

    }
    catch {
        Write-Warning "Failed creating profile $user : $($_.Exception.Message)"
        continue
    }
}

# Print manifest (or would-be manifest)
if ($DryRun) { Write-Host "`n[DryRun] Manifest of actions (sample):" }
else { Write-Host "`nCreated profiles manifest (sample):" }

$createdList |
Select-Object `
    ProfileName,
ProfilePath,
Indicator,
@{ Name = 'IndicatorDate'; Expression = { $_.IndicatorDate.ToString('yyyy-MM-dd HH:mm:ss') } },
@{ Name = 'RootTimestamp'; Expression = { $_.RootTimestamp.ToString('yyyy-MM-dd HH:mm:ss') } },
AgeDaysCanonical,
AgeDaysApplied |
Format-Table -AutoSize

Write-Host "`nDone. Profiles processed: $($createdList.Count) of $ProfileQTY. BasePath: $BasePath"
if ($DryRun) { Write-Host "[DryRun] No filesystem changes were made." }
