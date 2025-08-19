<#
.SYNOPSIS
    Windows Update Remover - Safely remove problematic Windows Updates with automatic restore point protection

.DESCRIPTION
    WinUpdateRemover is an interactive PowerShell tool designed to help Windows administrators and power users safely remove problematic Windows Updates that may cause system instability, performance issues, or hardware problems.
    
    Features:
    - Safe Removal Process: Automatic System Restore point creation before any changes
    - Targeted Removal: Remove specific problematic updates (like KB5063878 causing SSD issues)
    - Enhanced Error Handling: Improved handling for 0x800f0805 and other common errors
    - Multi-Method Removal: Four different removal approaches (DISM auto-detect, DISM standard, WUSA, Windows Update API)
    - Smart Detection: Automatically checks if updates are installed before attempting removal
    - Interactive Mode: Step-by-step guidance with confirmation prompts
    - Verification Mode: Check if specific KB updates are actually installed
    - Quick Fix Mode: Automated Windows Update repair and cache reset
    - Diagnostic Mode: Comprehensive Windows Update system analysis
    
    Usage Examples:
    - Interactive: .\WinUpdateRemover.ps1
    - Specific KB: .\WinUpdateRemover.ps1 -KBNumbers "KB5063878"
    - Force Mode: .\WinUpdateRemover.ps1 -Force
    - List Only: .\WinUpdateRemover.ps1 -ListOnly
    - Verify KB: .\WinUpdateRemover.ps1 -Verify -KBNumbers "KB5063878"
    - Quick Fix: .\WinUpdateRemover.ps1 -QuickFix
    - Diagnostic: .\WinUpdateRemover.ps1 -Diagnostic

.NOTES
    Author: @danalec
    Version: 1.0.2
    Requires: Administrator privileges
#>

# Script configuration
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [string[]]$KBNumbers,
    
    [Parameter(Mandatory=$false)]
    [switch]$ListOnly,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoRestorePoint,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verify,
    
    [Parameter(Mandatory=$false)]
    [switch]$QuickFix,
    
    [Parameter(Mandatory=$false)]
    [switch]$Diagnostic
)

$Script:ScriptName = "WinUpdateRemover"
$Script:Version = "v1.0.2"
$ErrorActionPreference = "Stop"

# Check for administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Error "This script requires administrator privileges! Please run PowerShell as Administrator and try again."
    exit 1
}

# Display header
Clear-Host
Write-Host "====================================" -ForegroundColor Cyan
Write-Host "    Windows Update Remover $($Script:Version)" -ForegroundColor White
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""

# Display system information
$osInfo = Get-CimInstance Win32_OperatingSystem
Write-Host "System Information:" -ForegroundColor Green
Write-Host "OS: $($osInfo.Caption)" -ForegroundColor White
Write-Host "Version: $($osInfo.Version)" -ForegroundColor White
Write-Host "Architecture: $env:PROCESSOR_ARCHITECTURE" -ForegroundColor White
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
Write-Host ""

# Handle new diagnostic parameters
if ($Verify -and $KBNumbers) {
    foreach ($kb in $KBNumbers) {
        $normalizedKB = Get-NormalizedKBNumber $kb
        if ($normalizedKB) {
            $null = Verify-KB -KBNumber $normalizedKB
        } else {
            Write-Warning "Invalid KB format: $kb"
        }
    }
    exit 0
} elseif ($Verify) {
    Write-Host "=== KB Verification Mode ===" -ForegroundColor Cyan
    Write-Host "Enter KB number(s) to verify (comma-separated, e.g., KB5063878,KB1234567):" -ForegroundColor Yellow
    $kbInput = Read-Host "KB Number(s)"
    $kbs = $kbInput -split ',' | ForEach-Object { $_.Trim() }
    foreach ($kb in $kbs) {
        $normalizedKB = Get-NormalizedKBNumber $kb
        if ($normalizedKB) {
            $null = Verify-KB -KBNumber $normalizedKB
        } else {
            Write-Warning "Invalid KB format: $kb"
        }
    }
    exit 0
}

if ($QuickFix) {
    Invoke-QuickFix
    exit 0
}

if ($Diagnostic) {
    Invoke-Diagnostic
    exit 0
}

# Define problematic KB updates
$problematicKBs = @(
    # Windows 11 24H2 - CRITICAL Issues (2025)
    'KB5063878',  # CRITICAL: SSD/HDD corruption during intensive writes - ACTIVE ISSUE
    'KB5055523',  # CRITICAL: BSOD SECURE_KERNEL_ERROR, CRITICAL_PROCESS_DIED - KIR Released
    'KB5053656',  # CRITICAL: System crashes and BSODs - KIR Released  
    'KB5053598',  # CRITICAL: BSOD SECURE_KERNEL_ERROR - KIR Released
    
    # Windows 11 24H2/23H2/22H2 - HIGH/MEDIUM Issues
    'KB5062660',  # HIGH: Installation failures, CertEnroll errors - Jul 2025
    'KB5055528',  # MEDIUM: Various system issues - Apr 2025 - KIR Released
    'KB5043145',  # MEDIUM: System functionality issues - Sep 2024 - KIR Released
    'KB5039302',  # MEDIUM: Script execution issues - Jul 2024 - KIR Released
    
    # Windows 10 22H2/21H2 - CRITICAL Issues
    'KB5058379',  # CRITICAL: BitLocker recovery loops (Intel TXT) - May 2025 - OOB Fix Released
    'KB5019959',  # CRITICAL: BSOD DPC_WATCHDOG_VIOLATION on boot - Nov 2022
    
    # Windows 10 22H2 - HIGH/MEDIUM Issues (2025)
    'KB5062649',  # HIGH: Emoji Panel broken, performance issues - Jul 2025 - ACTIVE ISSUE
    'KB5062554',  # HIGH: Various system issues - Jul 2025 - ACTIVE ISSUE  
    'KB5055518',  # MEDIUM: Random text when printing - Apr 2025 - Fixed
    'KB5046714',  # MEDIUM: Packaged apps update/uninstall failures - Nov 2024 - Fixed
    'KB5057589'   # LOW: Windows RE update shows as failed - Apr 2025 - Fixed
)

# Scan for installed updates
Write-Host "Scanning for installed updates..." -ForegroundColor Yellow
try {
    $installedUpdates = Get-HotFix | Where-Object { $_.HotFixID -match 'KB\d+' } | Sort-Object {[DateTime]$_.InstalledOn} -Descending
    Write-Host "Found $($installedUpdates.Count) installed updates." -ForegroundColor Green
} catch {
    Write-Error "Error scanning for updates: $($_.Exception.Message)"
    exit 1
}

# Function to normalize KB numbers
function Get-NormalizedKBNumber {
    param([string]$rawKB)
    if ($rawKB -match 'KB\s*(\d+)') {
        return $matches[1]
    }
    return $null
}

# Function to verify if a specific KB is installed (from VerifyKB5063878.ps1)
function Verify-KB {
    param([string]$KBNumber)
    
    Write-Host "=== KB$KBNumber Verification Report ===" -ForegroundColor Cyan
    Write-Host "Generated: $(Get-Date)" -ForegroundColor Gray
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host ""
    
    $found = $false
    
    # 1. Check via Get-HotFix
    Write-Host "1. Checking via Get-HotFix..." -ForegroundColor Yellow
    try {
        $hotfix = Get-HotFix -Id "KB$KBNumber" -ErrorAction SilentlyContinue
        if ($hotfix) {
            Write-Host "   [OK] FOUND: KB$KBNumber" -ForegroundColor Green
            Write-Host "   Installed on: $($hotfix.InstalledOn)" -ForegroundColor White
            Write-Host "   Description: $($hotfix.Description)" -ForegroundColor White
            $found = $true
        } else {
            Write-Host "   [X] NOT FOUND via Get-HotFix" -ForegroundColor Red
        }
    } catch {
        Write-Host "   [X] Error checking Get-HotFix: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    
    # 2. Check via DISM
    Write-Host "2. Checking via DISM..." -ForegroundColor Yellow
    try {
        $dismOutput = dism /online /get-packages | findstr /i "kb$KBNumber"
        if ($dismOutput) {
            Write-Host "   [OK] FOUND: KB$KBNumber in DISM packages" -ForegroundColor Green
            Write-Host "   Package info: $dismOutput" -ForegroundColor White
            $found = $true
        } else {
            Write-Host "   [X] NOT FOUND via DISM packages" -ForegroundColor Red
        }
    } catch {
        Write-Host "   [X] Error checking DISM: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    
    # 3. Check Windows Update API
    Write-Host "3. Checking via Windows Update API..." -ForegroundColor Yellow
    try {
        $session = New-Object -ComObject "Microsoft.Update.Session"
        $searcher = $session.CreateUpdateSearcher()
        $updates = $searcher.Search("IsInstalled=1 and Type='Software'")
        
        $wuUpdate = $updates.Updates | Where-Object { $_.KBArticleIDs -contains $KBNumber }
        if ($wuUpdate) {
            Write-Host "   [OK] FOUND: KB$KBNumber via Windows Update API" -ForegroundColor Green
            Write-Host "   Title: $($wuUpdate.Title)" -ForegroundColor White
            Write-Host "   Date: $($wuUpdate.Date)" -ForegroundColor White
            $found = $true
        } else {
            Write-Host "   [X] NOT FOUND via Windows Update API" -ForegroundColor Red
        }
    } catch {
        Write-Host "   [X] Error checking Windows Update API: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    
    # 4. Check registry
    Write-Host "4. Checking registry..." -ForegroundColor Yellow
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\*KB$KBNumber*",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*KB$KBNumber*",
        "HKLM:\SYSTEM\CurrentControlSet\Services\*KB$KBNumber*"
    )
    
    $regFound = $false
    foreach ($regPath in $regPaths) {
        try {
            $regItems = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
            if ($regItems) {
                Write-Host "   [OK] FOUND: KB$KBNumber in registry" -ForegroundColor Green
                Write-Host "   Path: $($regItems[0].Name)" -ForegroundColor White
                $regFound = $true
                $found = $true
                break
            }
        } catch {
            # Continue checking other paths
        }
    }
    if (-not $regFound) {
        Write-Host "   [X] NOT FOUND in registry" -ForegroundColor Red
    }
    Write-Host ""
    
    # 5. Check SFC (System File Checker)
    Write-Host "5. Checking system file integrity..." -ForegroundColor Yellow
    try {
        $sfcProcess = Start-Process -FilePath "sfc" -ArgumentList "/verifyonly" -Wait -PassThru -NoNewWindow
        if ($sfcProcess.ExitCode -eq 0) {
            Write-Host "   [OK] System file integrity: OK" -ForegroundColor Green
        } elseif ($sfcProcess.ExitCode -eq 1) {
            Write-Host "   [!] System file integrity issues detected" -ForegroundColor Yellow
            Write-Host "   Recommendation: Run 'sfc /scannow' as administrator" -ForegroundColor White
        } else {
            Write-Host "   [!] SFC check requires administrator privileges" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "   [X] Error running SFC check: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    
    # Summary
    Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
    if ($found) {
        Write-Host "[SEARCH] KB$KBNumber is INSTALLED on this system" -ForegroundColor Green
        Write-Host "[TIP] To remove this update, run: .\WinUpdateRemover.ps1 -KBNumbers KB$KBNumber" -ForegroundColor Yellow
    } else {
        Write-Host "[SEARCH] KB$KBNumber is NOT INSTALLED on this system" -ForegroundColor Red
        Write-Host "[TIP] If you saw 0x800f0805 error, this might be a false positive" -ForegroundColor Yellow
        Write-Host "[TIP] The update metadata may be out of sync with actual system state" -ForegroundColor Yellow
    }
    
    return $found
}

# Function to perform quick fixes (from QuickFix.bat)
function Invoke-QuickFix {
    Write-Host "=== Windows Update Quick Fix ===" -ForegroundColor Cyan
    Write-Host "Running comprehensive Windows Update repair..." -ForegroundColor Yellow
    Write-Host ""
    
    # 1. Stop Windows Update services
    Write-Host "1. Stopping Windows Update services..." -ForegroundColor Yellow
    $services = @("wuauserv", "bits", "cryptsvc", "msiserver")
    foreach ($service in $services) {
        try {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Write-Host "   [OK] Stopped $service" -ForegroundColor Green
        } catch {
            Write-Host "   [!] Could not stop $service (may already be stopped)" -ForegroundColor Yellow
        }
    }
    
    # 2. Rename SoftwareDistribution folder
    Write-Host "2. Resetting Windows Update cache..." -ForegroundColor Yellow
    $softwareDistPath = "$env:SystemRoot\SoftwareDistribution"
    $backupPath = "$env:SystemRoot\SoftwareDistribution.old"
    
    try {
        if (Test-Path $softwareDistPath) {
            if (Test-Path $backupPath) {
                Remove-Item -Path $backupPath -Recurse -Force -ErrorAction SilentlyContinue
            }
            Rename-Item -Path $softwareDistPath -NewName "SoftwareDistribution.old" -Force -ErrorAction SilentlyContinue
            Write-Host "   [OK] Renamed SoftwareDistribution folder" -ForegroundColor Green
        }
    } catch {
        Write-Host "   [!] Could not rename SoftwareDistribution folder" -ForegroundColor Yellow
    }
    
    # 3. Reset Windows Update components
    Write-Host "3. Resetting Windows Update components..." -ForegroundColor Yellow
    $catroot2Path = "$env:SystemRoot\System32\catroot2"
    $catroot2Backup = "$env:SystemRoot\System32\catroot2.old"
    
    try {
        if (Test-Path $catroot2Path) {
            if (Test-Path $catroot2Backup) {
                Remove-Item -Path $catroot2Backup -Recurse -Force -ErrorAction SilentlyContinue
            }
            Rename-Item -Path $catroot2Path -NewName "catroot2.old" -Force -ErrorAction SilentlyContinue
            Write-Host "   [OK] Reset catroot2 folder" -ForegroundColor Green
        }
    } catch {
        Write-Host "   [!] Could not reset catroot2 folder" -ForegroundColor Yellow
    }
    
    # 4. Start services
    Write-Host "4. Starting Windows Update services..." -ForegroundColor Yellow
    foreach ($service in $services) {
        try {
            Start-Service -Name $service -ErrorAction SilentlyContinue
            Write-Host "   [OK] Started $service" -ForegroundColor Green
        } catch {
            Write-Host "   [!] Could not start $service" -ForegroundColor Yellow
        }
    }
    
    # 5. Run Windows Update troubleshooter
    Write-Host "5. Running Windows Update diagnostics..." -ForegroundColor Yellow
    try {
        $troubleshooter = Get-Command "Get-TroubleshootingPack" -ErrorAction SilentlyContinue
        if ($troubleshooter) {
            Write-Host "   [OK] Windows Update troubleshooter available" -ForegroundColor Green
        } else {
            Write-Host "   [INFO] Manual troubleshooting recommended" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "   [INFO] Manual troubleshooting recommended" -ForegroundColor Cyan
    }
    
    Write-Host ""
    Write-Host "[OK] Quick fix completed!" -ForegroundColor Green
    Write-Host "[INFO] Next steps:" -ForegroundColor Cyan
    Write-Host "   1. Restart your computer" -ForegroundColor White
    Write-Host "   2. Run Windows Update to check for new updates" -ForegroundColor White
    Write-Host "   3. If issues persist, run .\WinUpdateRemover.ps1 -Diagnostic" -ForegroundColor White
}

# Function for comprehensive diagnostics
function Invoke-Diagnostic {
    try {
        Write-Host "=== Windows Update Comprehensive Diagnostics ===" -ForegroundColor Cyan
        Write-Host "Running detailed system analysis..." -ForegroundColor Yellow
        Write-Host ""
    
    # 1. Check Windows Update service status
    Write-Host "1. Checking Windows Update services..." -ForegroundColor Yellow
    $services = @("wuauserv", "bits", "cryptsvc", "msiserver")
    foreach ($service in $services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            $status = if ($svc.Status -eq "Running") { "[OK]" } else { "[WARN]" }
            Write-Host "   $status $service`: $($svc.Status) ($($svc.StartType))" -ForegroundColor $(if ($svc.Status -eq "Running") { "Green" } else { "Yellow" })
        } else {
            Write-Host "   [FAIL] $service`: Not found" -ForegroundColor Red
        }
    }
    Write-Host ""
    
    # 2. Check Windows Update settings
    Write-Host "2. Checking Windows Update configuration..." -ForegroundColor Yellow
    try {
        $wuSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
        if ($wuSettings) {
            Write-Host "   [OK] Windows Update policies found" -ForegroundColor Green
            Write-Host "   Auto Update: $($wuSettings.NoAutoUpdate)" -ForegroundColor White
        } else {
            Write-Host "   [INFO] No Windows Update policies configured" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "   [FAIL] Error checking Windows Update configuration" -ForegroundColor Red
    }
    Write-Host ""
    
    # 3. Check for pending updates
    Write-Host "3. Checking for pending Windows Updates..." -ForegroundColor Yellow
    try {
        $session = New-Object -ComObject "Microsoft.Update.Session"
        $searcher = $session.CreateUpdateSearcher()
        $pending = $searcher.Search("IsInstalled=0")
        Write-Host "   [INFO] Pending updates: $($pending.Updates.Count)" -ForegroundColor Cyan
        if ($pending.Updates.Count -gt 0) {
            foreach ($update in $pending.Updates[0..4]) {  # Show first 5
                Write-Host "   - $($update.Title)" -ForegroundColor Gray
            }
            if ($pending.Updates.Count -gt 5) {
                Write-Host "   ... and $($pending.Updates.Count - 5) more" -ForegroundColor Gray
            }
        }
    } catch {
        Write-Host "   [FAIL] Error checking pending updates: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    
    # 4. Check system file integrity
    Write-Host "4. Checking system file integrity..." -ForegroundColor Yellow
    try {
        $sfcResult = Start-Process -FilePath "sfc" -ArgumentList "/verifyonly" -Wait -PassThru -NoNewWindow
        if ($sfcResult.ExitCode -eq 0) {
            Write-Host "   [OK] System file integrity: OK" -ForegroundColor Green
        } elseif ($sfcResult.ExitCode -eq 1) {
            Write-Host "   [WARN] System file integrity issues detected" -ForegroundColor Yellow
            Write-Host "   Recommendation: Run 'sfc /scannow' as administrator" -ForegroundColor White
        } else {
            Write-Host "   [WARN] SFC check requires administrator privileges" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "   [FAIL] Error running SFC check" -ForegroundColor Red
    }
    Write-Host ""
    
    # 5. Check disk space
    Write-Host "5. Checking disk space..." -ForegroundColor Yellow
    $systemDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
    $freeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
    $totalSpaceGB = [math]::Round($systemDrive.Size / 1GB, 2)
    $percentFree = [math]::Round(($systemDrive.FreeSpace / $systemDrive.Size) * 100, 1)
    
    $status = if ($percentFree -ge 15) { "[OK]" } elseif ($percentFree -ge 10) { "[WARN]" } else { "[FAIL]" }
    $diskColor = if ($percentFree -ge 15) { "Green" } elseif ($percentFree -ge 10) { "Yellow" } else { "Red" }
    $percentageDisplay = "$percentFree%"
    Write-Host "   $status System drive ($env:SystemDrive): $freeSpaceGB GB free of $totalSpaceGB GB ($percentageDisplay)" -ForegroundColor $diskColor
    Write-Host ""
    
    # 6. Check Event Viewer for Windows Update errors
    Write-Host "6. Checking Windows Update error logs..." -ForegroundColor Yellow
    try {
        $wuErrors = Get-WinEvent -LogName "Microsoft-Windows-WindowsUpdateClient/Operational" -MaxEvents 50 -ErrorAction SilentlyContinue | 
                   Where-Object { $_.LevelDisplayName -eq "Error" } | 
                   Select-Object -First 5
        
        if ($wuErrors) {
            Write-Host "   [WARN] Found $($wuErrors.Count) recent Windows Update errors" -ForegroundColor Yellow
            foreach ($error in $wuErrors) {
                Write-Host "   - $($error.TimeCreated): $($error.Message)" -ForegroundColor Gray
            }
        } else {
            Write-Host "   [OK] No recent Windows Update errors found" -ForegroundColor Green
        }
    } catch {
        Write-Host "   [INFO] Could not access Windows Update logs" -ForegroundColor Cyan
    }
    Write-Host ""
    
    Write-Host "[OK] Diagnostic completed!" -ForegroundColor Green
    Write-Host "[INFO] Review the results above and take appropriate action" -ForegroundColor Cyan
    }
    catch {
        Write-Host "Error during diagnostic: $($_.Exception.Message)" -ForegroundColor Red
    }
}

if ($installedUpdates.Count -eq 0) {
    Write-Host "No updates found to remove." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 0
}

# Display updates
Write-Host "`n--- Installed Updates ---" -ForegroundColor Cyan
$problematicCount = 0
for ($i = 0; $i -lt $installedUpdates.Count; $i++) {
    $update = $installedUpdates[$i]
    $installDate = if ($update.InstalledOn) { $update.InstalledOn.ToString("yyyy-MM-dd") } else { "Unknown" }
    
    # Check if this is a problematic KB
    $normalizedKB = Get-NormalizedKBNumber $update.HotFixID
    $isProblematic = $normalizedKB -and ($problematicKBs -contains "KB$normalizedKB")
    
    if ($isProblematic) {
        Write-Host "[$($i+1)] $($update.HotFixID) - $($update.Description) (Installed: $installDate)" -ForegroundColor Red -BackgroundColor Yellow
        Write-Host "      *** PROBLEMATIC UPDATE DETECTED ***" -ForegroundColor Red -BackgroundColor Yellow
        $problematicCount++
    } else {
        Write-Host "[$($i+1)] $($update.HotFixID) - $($update.Description) (Installed: $installDate)" -ForegroundColor White
    }
}

if ($problematicCount -gt 0) {
    Write-Host "`n*** WARNING: $problematicCount problematic update(s) found! ***" -ForegroundColor Red -BackgroundColor Yellow
    Write-Host "These updates are known to cause issues and should be prioritized for removal." -ForegroundColor Yellow
}

# Handle KBNumbers parameter
if ($KBNumbers) {
    $normalizedKBNumbers = $KBNumbers | ForEach-Object { Get-NormalizedKBNumber $_ }
    $updatesToProcess = $installedUpdates | Where-Object { 
        $normalizedKB = Get-NormalizedKBNumber $_.HotFixID
        $normalizedKB -and ($normalizedKBNumbers -contains $normalizedKB)
    }
    if ($updatesToProcess.Count -eq 0) {
        Write-Warning "None of the specified KB numbers were found installed."
        exit 0
    }
} elseif ($ListOnly) {
    Write-Host "List-only mode: displaying updates without removal option" -ForegroundColor Cyan
    exit 0
} else {
    # Interactive selection
    Write-Host ""
    Write-Host "Select updates to remove:" -ForegroundColor Yellow
    Write-Host "- Enter numbers separated by commas (e.g., 1,3,5)" -ForegroundColor Gray
    Write-Host "- Enter 'all' to select all updates" -ForegroundColor Gray
    Write-Host "- Enter 'quit' to exit" -ForegroundColor Gray

    $selection = Read-Host "Your selection"

    if ($selection -eq 'quit') {
        Write-Host "Exiting..." -ForegroundColor Yellow
        exit 0
    }

    # Parse selection
    $updatesToProcess = @()
    if ($selection -eq 'all') {
        $updatesToProcess = $installedUpdates
    } else {
        $indices = $selection -split ',' | ForEach-Object { $_.Trim() }
        foreach ($index in $indices) {
            if ($index -match '^\d+$' -and [int]$index -ge 1 -and [int]$index -le $installedUpdates.Count) {
                $updatesToProcess += $installedUpdates[[int]$index - 1]
            } else {
                Write-Warning "Invalid selection: $index"
            }
        }
    }
}

if ($updatesToProcess.Count -eq 0) {
    Write-Host "No valid updates selected." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 0
}

Write-Host "`nSelected $($updatesToProcess.Count) update(s) for removal." -ForegroundColor Green

# Create restore point
if (-not $NoRestorePoint) {
    Write-Host "`nCreating a restore point before making changes..." -ForegroundColor Yellow
    
    $rpName = "${Script:ScriptName}_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $Script:rpCreated = $false
    
    try {
        $systemDrive = $env:SystemDrive
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
        $disableSR = Get-ItemProperty -Path $regPath -Name "DisableSR" -ErrorAction SilentlyContinue
        
        if ($disableSR -and $disableSR.DisableSR -eq 1) {
            Write-Warning "System Restore appears to be disabled"
            if (-not $Force) {
                $enable = Read-Host "Would you like to enable it? (y/n)"
                if ($enable -eq 'y') {
                    Enable-ComputerRestore -Drive $systemDrive -ErrorAction Stop
                    Write-Host "System Restore enabled" -ForegroundColor Green
                    Start-Sleep -Seconds 3
                }
            }
        }
        
        Checkpoint-Computer -Description $rpName -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Host "Restore point created successfully!" -ForegroundColor Green
        $Script:rpCreated = $true
    } catch {
        Write-Warning "Failed to create restore point: $($_.Exception.Message)"
        if (-not $Force) {
            $continue = Read-Host "Continue without restore point? (y/n)"
            if ($continue -ne 'y') {
                exit 1
            }
        }
    }
} else {
    Write-Warning "Skipping restore point creation (-NoRestorePoint specified)"
}

# Process updates
Write-Host "`n--- Processing Updates ---" -ForegroundColor Cyan
$processedCount = 0
$failedUpdates = [System.Collections.Generic.List[string]]::new()

foreach ($update in $updatesToProcess) {
    $kb = Get-NormalizedKBNumber $update.HotFixID
    $desc = $update.Description
    
    if (-not $kb) {
        Write-Warning "Could not extract KB number from: $($update.HotFixID)"
        continue
    }
    
    # Check if this is a problematic KB
    $isProblematicKB = $problematicKBs -contains "KB$kb"
    
    if ($isProblematicKB) {
        Write-Host "`nProcessing KB$kb... [PROBLEMATIC UPDATE]" -ForegroundColor Red -BackgroundColor Yellow
        Write-Host "*** This update is known to cause issues! ***" -ForegroundColor Red -BackgroundColor Yellow
    } else {
        Write-Host "`nProcessing KB$kb..." -ForegroundColor Yellow
    }
    Write-Host "Description: $desc" -ForegroundColor Gray
    
    if (-not $Force) {
        $remove = Read-Host "Remove this update? (y/n/skip all) [Default: y]"
        
        if ($remove -eq 'skip all') {
            Write-Host "Skipping all remaining updates." -ForegroundColor Gray
            break
        }
        
        if ($remove -eq 'n' -or $remove -eq 'N') {
            Write-Host "KB$kb skipped by user choice." -ForegroundColor Gray
            continue
        }
    }
    
    Write-Host "Removing KB$kb..." -ForegroundColor Red
    
    $removeSuccess = $false
    $removalMethods = @()
    $errorDetails = @()
    
    try {
        # Pre-check: Verify if update is actually installed
        Write-Host "Verifying update installation status..." -ForegroundColor Gray
        $installedCheck = Get-HotFix -Id "KB$kb" -ErrorAction SilentlyContinue
        if (-not $installedCheck) {
            Write-Host "KB$kb appears to already be removed or was never installed" -ForegroundColor Yellow
            $errorDetails += "Update not found via Get-HotFix"
            continue
        }
        
        # Check Windows Update history for more details
        try {
            $updateHistory = Get-WindowsUpdateLog -ErrorAction SilentlyContinue
            if ($updateHistory -like "*$kb*") {
                Write-Host "Found update in Windows Update history" -ForegroundColor Gray
            }
        } catch {
            # Silently continue if Windows Update log access fails
        }
        
        # Method 1: Try to find actual package name using DISM
        Write-Host "Searching for package information..." -ForegroundColor Gray
        $packageInfo = dism /online /get-packages | findstr /i "kb$kb"
        if ($packageInfo) {
            $packageName = ($packageInfo -split '\s+')[-1]
            if ($packageName -match "Package_for_KB$kb") {
                Write-Host "Found package: $packageName" -ForegroundColor Green
                $dismArgs = "/Online /Remove-Package /PackageName:$packageName /quiet /norestart"
                $process = Start-Process -FilePath "dism.exe" -ArgumentList $dismArgs -Wait -PassThru -NoNewWindow
                if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
                    $removeSuccess = $true
                    $removalMethods += "DISM (auto-detected package)"
                } else {
                    $errorDetails += "DISM auto-detect exit code: $($process.ExitCode)"
                    if ($process.ExitCode -eq 0x800f0805) {
                        Write-Host "Error 0x800f0805: Package not found or corrupted" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "Package found but format doesn't match expected pattern" -ForegroundColor Yellow
                $errorDetails += "Package format mismatch"
            }
        } else {
            Write-Host "No package found with KB$kb in DISM" -ForegroundColor Yellow
            $errorDetails += "Package not found in DISM"
        }
        
        # Method 2: Try standard DISM package name format
        if (-not $removeSuccess) {
            Write-Host "Trying standard DISM package format..." -ForegroundColor Gray
            $dismArgs = "/Online /Remove-Package /PackageName:Package_for_KB$kb~31bf3856ad364e35~amd64~~ /quiet /norestart"
            $process = Start-Process -FilePath "dism.exe" -ArgumentList $dismArgs -Wait -PassThru -NoNewWindow
            if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
                $removeSuccess = $true
                $removalMethods += "DISM (standard format)"
            } else {
                $errorDetails += "DISM standard format exit code: $($process.ExitCode)"
            }
        }
        
        # Method 3: Try WUSA with KB number
        if (-not $removeSuccess) {
            Write-Host "Trying Windows Update Standalone Installer..." -ForegroundColor Gray
            $wusaArgs = "/uninstall /kb:$kb /quiet /norestart"
            $process2 = Start-Process -FilePath "wusa.exe" -ArgumentList $wusaArgs -Wait -PassThru -NoNewWindow
            if ($process2.ExitCode -eq 0 -or $process2.ExitCode -eq 3010) {
                $removeSuccess = $true
                $removalMethods += "WUSA"
            } else {
                $errorDetails += "WUSA exit code: $($process2.ExitCode)"
            }
        }
        
        # Method 4: Try PowerShell Windows Update API
        if (-not $removeSuccess) {
            Write-Host "Trying Windows Update API..." -ForegroundColor Gray
            try {
                $session = New-Object -ComObject "Microsoft.Update.Session"
                $searcher = $session.CreateUpdateSearcher()
                $updates = $searcher.Search("IsInstalled=1 and Type='Software'")
                
                foreach ($update in $updates.Updates) {
                    if ($update.KBArticleIDs -contains $kb) {
                        $installer = $update.CreateUpdateInstaller()
                        $installationResult = $installer.Uninstall()
                        if ($installationResult.ResultCode -eq 2) {
                            $removeSuccess = $true
                            $removalMethods += "Windows Update API"
                            break
                        }
                    }
                }
            } catch {
                $errorDetails += "Windows Update API error: $($_.Exception.Message)"
            }
        }
        
    } catch {
        $errorDetails += "Exception during removal: $($_.Exception.Message)"
        Write-Error "Exception during removal: $($_.Exception.Message)"
        $removeSuccess = $false
    }
    
    if ($removeSuccess) {
        $methodUsed = if ($removalMethods.Count -gt 0) { " using $($removalMethods[-1])" } else { "" }
        Write-Host "KB$kb removal initiated successfully$methodUsed!" -ForegroundColor Green
        $processedCount++
    } else {
        Write-Error "Failed to remove KB$kb"
        Write-Host "Attempted methods: $($removalMethods -join ', ')" -ForegroundColor Gray
        Write-Host "Error details: $($errorDetails -join '; ')" -ForegroundColor Gray
        
        # Provide specific guidance for common errors
        if ($errorDetails -like "*0x800f0805*" -or $errorDetails -like "*invalid*package*") {
            Write-Host "`n--- 0x800f0805 Error Analysis ---" -ForegroundColor Red
            Write-Host "This error indicates the update package is not found in the Windows component store." -ForegroundColor Yellow
            Write-Host "Possible causes:" -ForegroundColor Yellow
            Write-Host "1. Update already removed but still appears in Get-HotFix" -ForegroundColor White
            Write-Host "2. Windows Update cache is corrupted" -ForegroundColor White
            Write-Host "3. Package database is out of sync" -ForegroundColor White
            Write-Host "`nRecommended actions:" -ForegroundColor Cyan
            Write-Host "1. Run: sfc /scannow" -ForegroundColor White
            Write-Host "2. Run: DISM /Online /Cleanup-Image /RestoreHealth" -ForegroundColor White
            Write-Host "3. Restart Windows Update service" -ForegroundColor White
            Write-Host "4. Check Windows Update troubleshooter" -ForegroundColor White
            Write-Host "5. Try Safe Mode if issue persists" -ForegroundColor White
            
            # Add specific Windows Update troubleshooting commands
            Write-Host "`nQuick fixes to try:" -ForegroundColor Cyan
            Write-Host "- Reset Windows Update components:" -ForegroundColor White
            Write-Host "  Stop-Service wuauserv,bits,cryptsvc" -ForegroundColor Gray
            Write-Host "  Remove-Item `"`$env:SystemRoot\SoftwareDistribution\*`" -Recurse -Force" -ForegroundColor Gray
            Write-Host "  Start-Service wuauserv,bits,cryptsvc" -ForegroundColor Gray
            Write-Host "- Check Windows Update history: Settings > Windows Update > Update History" -ForegroundColor White
        }
        
        $failedUpdates.Add($kb)
    }
}

# Final summary
Write-Host "`n--- Summary ---" -ForegroundColor Cyan
Write-Host "Updates processed: $processedCount" -ForegroundColor Green

if ($failedUpdates.Count -gt 0) {
    Write-Host "Failed removals: $($failedUpdates -join ', ')" -ForegroundColor Red
}

# Create detailed log file
$logPath = Join-Path -Path $env:TEMP -ChildPath "WinUpdateRemover_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$logContent = @"
Windows Update Remover Log
=========================
Date: $(Get-Date)
Computer: $env:COMPUTERNAME
OS: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
Version: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Version)

Updates processed: $processedCount
Failed removals: $($failedUpdates -join ', ')
Restore point created: $($Script:rpCreated)

Selected Updates:
$($updatesToProcess | ForEach-Object { $normalizedKB = Get-NormalizedKBNumber $_.HotFixID; "KB$($_.HotFixID -replace 'KB', '') [Normalized: KB$normalizedKB] - $($_.Description)" } | Out-String)

System Information:
- PowerShell Version: $($PSVersionTable.PSVersion)
- Execution Policy: $(Get-ExecutionPolicy)
- User: $env:USERNAME
- Is Admin: $isAdmin

Error Summary:
$(if ($failedUpdates.Count -gt 0) { "Failed updates: $($failedUpdates -join ', ')" } else { "No failures detected" })

Detailed Process Log:
$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Script started
$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Found $($installedUpdates.Count) installed updates
$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Selected $($updatesToProcess.Count) updates for removal
$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Restore point creation: $($Script:rpCreated)
"@
$logContent | Out-File -FilePath $logPath -Encoding UTF8
Write-Host "Log saved to: $logPath" -ForegroundColor Cyan

if ($processedCount -gt 0) {
    Write-Host "`nA system restart may be required to complete the removal process." -ForegroundColor Yellow
    
    if (-not $Force) {
        $restart = Read-Host "Restart now? (y/n)"
        if ($restart -eq 'y') {
            Write-Host "Restarting system in 10 seconds..." -ForegroundColor Red
            Start-Sleep -Seconds 10
            Restart-Computer -Force
        }
    } else {
        Write-Host "Restart suppressed (-Force specified)" -ForegroundColor Yellow
    }
}

Write-Host "`nThank you for using Windows Update Remover!" -ForegroundColor Green
Write-Host "GitHub: https://github.com/danalec/WinUpdateRemover" -ForegroundColor Cyan

if ($failedUpdates.Count -gt 0) {
    Write-Host "`n--- Troubleshooting Guide ---" -ForegroundColor Cyan
    Write-Host "For failed update removals, try these steps:" -ForegroundColor Yellow
    Write-Host "1. Run Windows Update Troubleshooter: Settings > System > Troubleshoot > Other troubleshooters" -ForegroundColor White
    Write-Host "2. Check Windows Update service: Run 'services.msc' and ensure Windows Update is running" -ForegroundColor White
    Write-Host "3. Run System File Checker: Open Command Prompt as admin and run 'sfc /scannow'" -ForegroundColor White
    Write-Host "4. Use DISM to repair Windows: 'DISM /Online /Cleanup-Image /RestoreHealth'" -ForegroundColor White
    Write-Host "5. For 0x800f0805 errors: The update may already be removed or corrupted" -ForegroundColor White
    Write-Host "6. Check Windows Update history for more details about the failure" -ForegroundColor White
    Write-Host "7. Consider using Windows 10/11 built-in rollback feature if recent update" -ForegroundColor White
    Write-Host "8. Try Safe Mode: Restart in Safe Mode and run the script again" -ForegroundColor White
    Write-Host "9. Reset Windows Update components:" -ForegroundColor White
    Write-Host "   - Run: net stop wuauserv && net stop bits && net stop cryptsvc" -ForegroundColor Gray
    Write-Host "   - Run: ren %systemroot%\SoftwareDistribution SoftwareDistribution.old" -ForegroundColor Gray
    Write-Host "   - Run: net start wuauserv && net start bits && net start cryptsvc" -ForegroundColor Gray
    Write-Host "10. Check Event Viewer: Applications and Services Logs > Microsoft > Windows > WindowsUpdateClient" -ForegroundColor White
}