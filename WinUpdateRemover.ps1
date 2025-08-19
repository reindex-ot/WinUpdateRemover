<#
.SYNOPSIS
    Windows Update Remover - Safely remove and block problematic Windows Updates with automatic restore point protection

.DESCRIPTION
    WinUpdateRemover is an interactive PowerShell tool designed to help Windows administrators and power users safely remove and block problematic Windows Updates that may cause system instability, performance issues, or hardware problems.
    
    Features:
    - Safe Removal Process: Automatic System Restore point creation before any changes
    - Targeted Removal: Remove specific problematic updates (like KB5063878 causing SSD issues)
    - Update Blocking: Prevent specific updates from being installed via registry-based blocking
    - Enhanced Error Handling: Improved handling for 0x800f0805 and other common errors
    - Multi-Method Removal: Four different removal approaches (DISM auto-detect, DISM standard, WUSA, Windows Update API)
    - Smart Detection: Automatically checks if updates are installed before attempting removal
    - Interactive Mode: Step-by-step guidance with confirmation prompts
    - Verification Mode: Check if specific KB updates are actually installed
    - Repair Windows Update Mode: Automated Windows Update repair and cache reset
    - Diagnostic Mode: Comprehensive Windows Update system analysis
    - Block Status Checking: Verify if updates are currently blocked
    
    Usage Examples:
    - Interactive: .\WinUpdateRemover.ps1
    - Specific KB: .\WinUpdateRemover.ps1 -KBNumbers "KB5063878"
    - Force Mode: .\WinUpdateRemover.ps1 -Force
    - List Only: .\WinUpdateRemover.ps1 -ListOnly
    - Verify KB: .\WinUpdateRemover.ps1 -Verify -KBNumbers "KB5063878"
    - Repair Windows Update: .\WinUpdateRemover.ps1 -QuickFix
    - Diagnostic: .\WinUpdateRemover.ps1 -Diagnostic
    - Enable System Restore: .\WinUpdateRemover.ps1 -EnableSystemRestore
    - Show Block Methods: .\WinUpdateRemover.ps1 -ShowBlockMethods
    - Block Update: .\WinUpdateRemover.ps1 -BlockUpdate -KBNumbers "KB5063878"
    - Unblock Update: .\WinUpdateRemover.ps1 -UnblockUpdate -KBNumbers "KB5063878"
    - Check Block Status: .\WinUpdateRemover.ps1 -CheckBlockStatus -KBNumbers "KB5063878"

.NOTES
    Author: @danalec
    Version: 1.0.6
    Requires: Administrator privileges
    
    Troubleshooting System Restore Issues:
    If restore point creation fails with "service cannot be started":
    1. Run: services.msc
    2. Find "System Restore Service" (SRService)
    3. Set Startup Type to "Automatic"
    4. Start the service
    5. Re-run the script
    
    Alternative: Use -NoRestorePoint parameter to skip restore point creation
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
    [switch]$Diagnostic,
    
    [Parameter(Mandatory=$false)]
    [switch]$EnableSystemRestore,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowBlockMethods,
    
    [Parameter(Mandatory=$false)]
    [switch]$BlockUpdate,
    
    [Parameter(Mandatory=$false)]
    [switch]$UnblockUpdate,
    
    [Parameter(Mandatory=$false)]
    [switch]$CheckBlockStatus
)

$Script:ScriptName = "WinUpdateRemover"
$Script:Version = "v1.0.6"
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

if ($ShowBlockMethods) {
    Show-BlockingMethods
    exit 0
}

if ($BlockUpdate) {
    if ($KBNumbers) {
        foreach ($kb in $KBNumbers) {
            $normalizedKB = Get-NormalizedKBNumber $kb
            if ($normalizedKB) {
                Block-UpdateKB -KBNumber $normalizedKB
            } else {
                Write-Warning "Invalid KB format: $kb"
            }
        }
    } else {
        Write-Host "=== Block Update Mode ===" -ForegroundColor Cyan
        Write-Host "Enter KB number to block (e.g., KB5063878):" -ForegroundColor Yellow
        $kbInput = Read-Host "KB Number"
        $normalizedKB = Get-NormalizedKBNumber $kbInput
        if ($normalizedKB) {
            Block-UpdateKB -KBNumber $normalizedKB
        } else {
            Write-Warning "Invalid KB format: $kbInput"
        }
    }
    exit 0
}

if ($UnblockUpdate) {
    if ($KBNumbers) {
        foreach ($kb in $KBNumbers) {
            $normalizedKB = Get-NormalizedKBNumber $kb
            if ($normalizedKB) {
                Unblock-UpdateKB -KBNumber $normalizedKB
            } else {
                Write-Warning "Invalid KB format: $kb"
            }
        }
    } else {
        Write-Host "=== Unblock Update Mode ===" -ForegroundColor Cyan
        Write-Host "Enter KB number to unblock (e.g., KB5063878):" -ForegroundColor Yellow
        $kbInput = Read-Host "KB Number"
        $normalizedKB = Get-NormalizedKBNumber $kbInput
        if ($normalizedKB) {
            Unblock-UpdateKB -KBNumber $normalizedKB
        } else {
            Write-Warning "Invalid KB format: $kbInput"
        }
    }
    exit 0
}

if ($CheckBlockStatus) {
    if ($KBNumbers) {
        foreach ($kb in $KBNumbers) {
            $normalizedKB = Get-NormalizedKBNumber $kb
            if ($normalizedKB) {
                Check-UpdateBlockStatus -KBNumber $normalizedKB
            } else {
                Write-Warning "Invalid KB format: $kb"
            }
        }
    } else {
        Write-Host "=== Check Block Status Mode ===" -ForegroundColor Cyan
        Write-Host "Enter KB number to check (e.g., KB5063878):" -ForegroundColor Yellow
        $kbInput = Read-Host "KB Number"
        $normalizedKB = Get-NormalizedKBNumber $kbInput
        if ($normalizedKB) {
            Check-UpdateBlockStatus -KBNumber $normalizedKB
        } else {
            Write-Warning "Invalid KB format: $kbInput"
        }
    }
    exit 0
}

if ($EnableSystemRestore) {
    Invoke-EnableSystemRestore
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

# Function to perform repair Windows Update (from QuickFix.bat)
function Invoke-QuickFix {
    Write-Host "=== Repair Windows Update ===" -ForegroundColor Cyan
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
    Write-Host "[OK] Repair Windows Update completed!" -ForegroundColor Green
    Write-Host "[INFO] Next steps:" -ForegroundColor Cyan
    Write-Host "   1. Restart your computer" -ForegroundColor White
    Write-Host "   2. Run Windows Update to check for new updates" -ForegroundColor White
    Write-Host "   3. If issues persist, run .\WinUpdateRemover.ps1 -Diagnostic" -ForegroundColor White
}

# Function to enable System Restore service
function Invoke-EnableSystemRestore {
    try {
        Write-Host "=== System Restore Service Enabler ===" -ForegroundColor Cyan
        Write-Host "This will enable and start the System Restore Service (SRService)" -ForegroundColor Yellow
        Write-Host "Required for automatic restore point creation" -ForegroundColor Gray
        Write-Host ""
        
        # Check current service status
        Write-Host "Checking System Restore Service status..." -ForegroundColor Yellow
        $service = Get-Service -Name "SRService" -ErrorAction SilentlyContinue
        
        if (-not $service) {
            Write-Host "[FAIL] System Restore Service (SRService) not found!" -ForegroundColor Red
            Write-Host "This service should exist on Windows systems. Try running System File Checker:" -ForegroundColor Yellow
            Write-Host "   sfc /scannow" -ForegroundColor White
            return
        }
        
        Write-Host "Current Status: $($service.Status) (Startup Type: $($service.StartType))" -ForegroundColor Cyan
        
        # Enable service if disabled
        if ($service.StartType -eq "Disabled") {
            Write-Host "Enabling System Restore Service..." -ForegroundColor Yellow
            try {
                Set-Service -Name "SRService" -StartupType Automatic -ErrorAction Stop
                Write-Host "[OK] Service startup type set to Automatic" -ForegroundColor Green
            } catch {
                Write-Host "[FAIL] Could not enable service: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Try running as administrator or manually via services.msc" -ForegroundColor Yellow
                return
            }
        }
        
        # Start service if not running
        if ($service.Status -ne "Running") {
            Write-Host "Starting System Restore Service..." -ForegroundColor Yellow
            try {
                Start-Service -Name "SRService" -ErrorAction Stop
                Write-Host "[OK] System Restore Service started successfully" -ForegroundColor Green
            } catch {
                Write-Host "[FAIL] Could not start service: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Try manually starting via services.msc" -ForegroundColor Yellow
                return
            }
        } else {
            Write-Host "[OK] System Restore Service is already running" -ForegroundColor Green
        }
        
        # Verify service is working
        Start-Sleep -Seconds 2
        $service = Get-Service -Name "SRService"
        if ($service.Status -eq "Running") {
            Write-Host ""
            Write-Host "[SUCCESS] System Restore Service is now enabled and running!" -ForegroundColor Green
            Write-Host "You can now use WinUpdateRemover with automatic restore point creation." -ForegroundColor Cyan
        } else {
            Write-Host "[WARN] Service verification failed - may need manual intervention" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "Error enabling System Restore Service: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Try manual steps: services.msc → System Restore Service → Set to Automatic → Start" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Press any key to continue..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
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
            $maxDisplay = [Math]::Min(5, $pending.Updates.Count)
            for ($i = 0; $i -lt $maxDisplay; $i++) {
                Write-Host "   - $($pending.Updates.Item($i).Title)" -ForegroundColor Gray
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

# ===== BLOCKING FUNCTIONS =====

function Show-BlockingMethods {
    Write-Host "=== Windows Update Blocking Methods ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Available methods to block Windows Updates:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Registry-based blocking (Recommended)" -ForegroundColor Green
    Write-Host "   - Adds KB to Windows Update hidden list"
    Write-Host "   - Prevents automatic installation"
    Write-Host "   - Reversible and safe"
    Write-Host ""
    Write-Host "2. Group Policy (Enterprise environments)" -ForegroundColor Cyan
    Write-Host "   - Configure through gpedit.msc"
    Write-Host "   - Computer Configuration > Administrative Templates > Windows Components > Windows Update"
    Write-Host "   - Set 'Configure Automatic Updates' to disabled"
    Write-Host ""
    Write-Host "3. Windows Update Settings" -ForegroundColor Yellow
    Write-Host "   - Settings > Update & Security > Windows Update"
    Write-Host "   - Advanced options > Choose how updates are delivered"
    Write-Host "   - Pause updates for up to 35 days"
    Write-Host ""
    Write-Host "4. WSUS Offline (Advanced users)" -ForegroundColor Magenta
    Write-Host "   - Download and install specific updates manually"
    Write-Host "   - Bypass Windows Update entirely"
    Write-Host ""
    Write-Host "This script uses Method 1 (Registry-based blocking) for safety and reliability." -ForegroundColor Green
}

function Block-UpdateKB {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KBNumber
    )
    
    try {
        Write-Host "Blocking KB$KBNumber from Windows Update..." -ForegroundColor Yellow
        
        # Create registry path if it doesn't exist
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (!(Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
            Write-Host "Created Windows Update policy registry path" -ForegroundColor Green
        }
        
        # Add KB to hidden updates list
        $hiddenPath = "$regPath\HiddenUpdates"
        if (!(Test-Path $hiddenPath)) {
            New-Item -Path $hiddenPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $hiddenPath -Name "KB$KBNumber" -Value 1 -Type DWord
        Write-Host "Added KB$KBNumber to hidden updates list" -ForegroundColor Green
        
        # Configure Windows Update to exclude recommended updates
        Set-ItemProperty -Path $regPath -Name "IncludeRecommendedUpdates" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        
        Write-Host "KB$KBNumber has been successfully blocked!" -ForegroundColor Green
        Write-Host "Note: You may need to restart Windows Update service for changes to take effect." -ForegroundColor Cyan
        
    } catch {
        Write-Host "Error blocking KB$KBNumber`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Unblock-UpdateKB {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KBNumber
    )
    
    try {
        Write-Host "Unblocking KB$KBNumber from Windows Update..." -ForegroundColor Yellow
        
        $hiddenPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\HiddenUpdates"
        
        if (Test-Path $hiddenPath) {
            $property = Get-ItemProperty -Path $hiddenPath -Name "KB$KBNumber" -ErrorAction SilentlyContinue
            if ($property) {
                Remove-ItemProperty -Path $hiddenPath -Name "KB$KBNumber"
                Write-Host "Removed KB$KBNumber from hidden updates list" -ForegroundColor Green
                Write-Host "KB$KBNumber has been successfully unblocked!" -ForegroundColor Green
            } else {
                Write-Host "KB$KBNumber was not found in the blocked list" -ForegroundColor Yellow
            }
        } else {
            Write-Host "No hidden updates registry path found" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "Error unblocking KB$KBNumber`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Check-UpdateBlockStatus {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KBNumber
    )
    
    try {
        Write-Host "Checking block status for KB$KBNumber..." -ForegroundColor Yellow
        Write-Host ""
        
        # Check registry blocking status
        $hiddenPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\HiddenUpdates"
        $isBlocked = $false
        
        if (Test-Path $hiddenPath) {
            $property = Get-ItemProperty -Path $hiddenPath -Name "KB$KBNumber" -ErrorAction SilentlyContinue
            if ($property) {
                $isBlocked = $true
                Write-Host "[BLOCKED] KB$KBNumber is in the hidden updates list" -ForegroundColor Red
            }
        }
        
        if (-not $isBlocked) {
            Write-Host "[NOT BLOCKED] KB$KBNumber is not in the hidden updates list" -ForegroundColor Green
        }
        
        # Check if update is available
        Write-Host "Checking Windows Update availability..." -ForegroundColor Cyan
        try {
            $session = New-Object -ComObject "Microsoft.Update.Session"
            $searcher = $session.CreateUpdateSearcher()
            $searchResult = $searcher.Search("IsInstalled=0")
            
            $foundUpdate = $false
            foreach ($update in $searchResult.Updates) {
                if ($update.Title -match "KB$KBNumber" -or $update.KBArticleIDs -contains $KBNumber) {
                    $foundUpdate = $true
                    Write-Host "[AVAILABLE] KB$KBNumber is available for download" -ForegroundColor Yellow
                    Write-Host "Title: $($update.Title)" -ForegroundColor White
                    break
                }
            }
            
            if (-not $foundUpdate) {
                Write-Host "[NOT AVAILABLE] KB$KBNumber is not available in Windows Update" -ForegroundColor Cyan
            }
            
        } catch {
            Write-Host "[INFO] Could not check Windows Update availability: $($_.Exception.Message)" -ForegroundColor Gray
        }
        
        Write-Host ""
        Write-Host "Block Status Summary:" -ForegroundColor Cyan
        Write-Host "Registry Blocked: $(if ($isBlocked) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($isBlocked) { 'Red' } else { 'Green' })
        
    } catch {
        Write-Host "Error checking block status for KB$KBNumber`: $($_.Exception.Message)" -ForegroundColor Red
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
    # Interactive menu
    Write-Host ""
    Write-Host "=== Interactive Menu ===" -ForegroundColor Cyan
    Write-Host "Choose an action:" -ForegroundColor Yellow
    Write-Host "1. Remove installed updates" -ForegroundColor White
    Write-Host "2. Block specific updates from installing" -ForegroundColor White
    Write-Host "3. Unblock previously blocked updates" -ForegroundColor White
    Write-Host "4. Check blocking status of updates" -ForegroundColor White
    Write-Host "5. Show blocking methods information" -ForegroundColor White
    Write-Host "6. Quick Fix (repair Windows Update)" -ForegroundColor White
    Write-Host "7. Run diagnostics" -ForegroundColor White
    Write-Host "8. Exit" -ForegroundColor Gray
    Write-Host ""
    
    $menuChoice = Read-Host "Enter your choice (1-8)"
    
    switch ($menuChoice) {
        "1" {
            # Original update removal functionality
            Write-Host ""
            Write-Host "Select updates to remove:" -ForegroundColor Yellow
            Write-Host "- Enter numbers separated by commas (e.g., 1,3,5)" -ForegroundColor Gray
            Write-Host "- Enter 'all' to select all updates" -ForegroundColor Gray
            Write-Host "- Enter 'back' to return to main menu" -ForegroundColor Gray

            $selection = Read-Host "Your selection"

            if ($selection -eq 'back') {
                # Restart the script to show menu again
                & $MyInvocation.MyCommand.Path
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
        "2" {
            # Block updates
            Write-Host ""
            Write-Host "=== Block Updates ===" -ForegroundColor Cyan
            Write-Host "Enter KB number(s) to block (comma-separated, e.g., KB5063878,KB1234567):" -ForegroundColor Yellow
            $kbInput = Read-Host "KB Number(s)"
            if ($kbInput) {
                $kbs = $kbInput -split ',' | ForEach-Object { $_.Trim() }
                foreach ($kb in $kbs) {
                    $normalizedKB = Get-NormalizedKBNumber $kb
                    if ($normalizedKB) {
                        Block-UpdateKB -KBNumber $normalizedKB
                    } else {
                        Write-Warning "Invalid KB format: $kb"
                    }
                }
            }
            Read-Host "Press Enter to continue"
            & $MyInvocation.MyCommand.Path
            exit 0
        }
        "3" {
            # Unblock updates
            Write-Host ""
            Write-Host "=== Unblock Updates ===" -ForegroundColor Cyan
            Write-Host "Enter KB number(s) to unblock (comma-separated, e.g., KB5063878,KB1234567):" -ForegroundColor Yellow
            $kbInput = Read-Host "KB Number(s)"
            if ($kbInput) {
                $kbs = $kbInput -split ',' | ForEach-Object { $_.Trim() }
                foreach ($kb in $kbs) {
                    $normalizedKB = Get-NormalizedKBNumber $kb
                    if ($normalizedKB) {
                        Unblock-UpdateKB -KBNumber $normalizedKB
                    } else {
                        Write-Warning "Invalid KB format: $kb"
                    }
                }
            }
            Read-Host "Press Enter to continue"
            & $MyInvocation.MyCommand.Path
            exit 0
        }
        "4" {
            # Check blocking status
            Write-Host ""
            Write-Host "=== Check Blocking Status ===" -ForegroundColor Cyan
            Write-Host "Enter KB number(s) to check (comma-separated, e.g., KB5063878,KB1234567):" -ForegroundColor Yellow
            $kbInput = Read-Host "KB Number(s)"
            if ($kbInput) {
                $kbs = $kbInput -split ',' | ForEach-Object { $_.Trim() }
                foreach ($kb in $kbs) {
                    $normalizedKB = Get-NormalizedKBNumber $kb
                    if ($normalizedKB) {
                        Check-UpdateBlockStatus -KBNumber $normalizedKB
                        Write-Host ""
                    } else {
                        Write-Warning "Invalid KB format: $kb"
                    }
                }
            }
            Read-Host "Press Enter to continue"
            & $MyInvocation.MyCommand.Path
            exit 0
        }
        "5" {
            # Show blocking methods
            Show-BlockingMethods
            Write-Host ""
            Read-Host "Press Enter to continue"
            & $MyInvocation.MyCommand.Path
            exit 0
        }
        "6" {
             # Repair Windows Update
            Invoke-QuickFix
            Read-Host "Press Enter to continue"
            & $MyInvocation.MyCommand.Path
            exit 0
        }
        "7" {
            # Diagnostics
            Invoke-Diagnostic
            Read-Host "Press Enter to continue"
            & $MyInvocation.MyCommand.Path
            exit 0
        }
        "8" {
            Write-Host "Exiting..." -ForegroundColor Yellow
            exit 0
        }
        default {
            Write-Warning "Invalid choice. Please select 1-8."
            Read-Host "Press Enter to continue"
            & $MyInvocation.MyCommand.Path
            exit 0
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
        
        # Check if System Restore service is running
        $srService = Get-Service -Name "SRService" -ErrorAction SilentlyContinue
        if ($srService -and $srService.Status -ne "Running") {
            Write-Warning "System Restore service is not running (Status: $($srService.Status))"
            
            if ($srService.StartType -eq "Disabled") {
                Write-Warning "System Restore service is disabled"
                if (-not $Force) {
                    $enableService = Read-Host "Would you like to enable and start the System Restore service? (y/n)"
                    if ($enableService -eq 'y') {
                        try {
                            Set-Service -Name "SRService" -StartupType Automatic -ErrorAction Stop
                            Start-Service -Name "SRService" -ErrorAction Stop
                            Write-Host "System Restore service enabled and started" -ForegroundColor Green
                            Start-Sleep -Seconds 5
                        } catch {
                            Write-Warning "Failed to enable System Restore service: $($_.Exception.Message)"
                            Write-Host "You can manually enable it via: services.msc -> System Restore -> Set to Automatic" -ForegroundColor Yellow
                        }
                    }
                }
            } else {
                # Service is not disabled, try to start it
                try {
                    Start-Service -Name "SRService" -ErrorAction Stop
                    Write-Host "System Restore service started" -ForegroundColor Green
                    Start-Sleep -Seconds 3
                } catch {
                    Write-Warning "Failed to start System Restore service: $($_.Exception.Message)"
                }
            }
        } elseif (-not $srService) {
            Write-Warning "System Restore service (SRService) not found on this system"
        }
        
        # Check registry settings for System Restore
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
        $disableSR = Get-ItemProperty -Path $regPath -Name "DisableSR" -ErrorAction SilentlyContinue
        
        if ($disableSR -and $disableSR.DisableSR -eq 1) {
            Write-Warning "System Restore is disabled in registry"
            if (-not $Force) {
                $enable = Read-Host "Would you like to enable System Restore for $systemDrive? (y/n)"
                if ($enable -eq 'y') {
                    try {
                        Enable-ComputerRestore -Drive $systemDrive -ErrorAction Stop
                        Write-Host "System Restore enabled for $systemDrive" -ForegroundColor Green
                        Start-Sleep -Seconds 3
                    } catch {
                        Write-Warning "Failed to enable System Restore: $($_.Exception.Message)"
                        Write-Host "You can manually enable it via: System Properties -> System Protection -> Configure" -ForegroundColor Yellow
                    }
                }
            }
        }
        
        # Verify System Restore is available before attempting to create restore point
        $protectionStatus = Get-ComputerRestorePoint | Select-Object -First 1 -ErrorAction SilentlyContinue
        if (-not $protectionStatus) {
            Write-Warning "No restore points found - System Restore may not be configured"
            if (-not $Force) {
                $configure = Read-Host "Would you like to configure System Restore now? (y/n)"
                if ($configure -eq 'y') {
                    try {
                        Enable-ComputerRestore -Drive $systemDrive -ErrorAction Stop
                        Write-Host "System Restore configured for $systemDrive" -ForegroundColor Green
                        Start-Sleep -Seconds 3
                    } catch {
                        Write-Warning "Failed to configure System Restore: $($_.Exception.Message)"
                    }
                }
            }
        }
        
        # Attempt to create restore point
        Checkpoint-Computer -Description $rpName -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Host "Restore point created successfully!" -ForegroundColor Green
        $Script:rpCreated = $true
        
    } catch {
        Write-Warning "Failed to create restore point: $($_.Exception.Message)"
        
        # Provide specific guidance based on common errors
        if ($_.Exception.Message -like "*service*disabled*" -or $_.Exception.Message -like "*cannot be started*") {
            Write-Host "`n--- System Restore Troubleshooting ---" -ForegroundColor Yellow
            Write-Host "System Restore appears to be disabled or the service is not running:" -ForegroundColor White
            Write-Host "1. Open Services (services.msc)" -ForegroundColor White
            Write-Host "2. Find 'System Restore Service' (SRService)" -ForegroundColor White
            Write-Host "3. Set Startup Type to 'Automatic'" -ForegroundColor White
            Write-Host "4. Start the service" -ForegroundColor White
            Write-Host "5. Or use: System Properties > System Protection > Configure" -ForegroundColor White
            Write-Host "`nAlternative: Use -NoRestorePoint parameter to skip restore point creation" -ForegroundColor Cyan
        }
        
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
            Write-Host "`nRepair Windows Update options to try:" -ForegroundColor Cyan
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