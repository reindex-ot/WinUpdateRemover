<#
.SYNOPSIS
    Windows Update Remover - Remove specific Windows updates

.DESCRIPTION
    This script allows you to view and selectively remove Windows updates.
    It creates a system restore point before making changes for safety.

.NOTES
    Author: @danalec
    Version: 1.0
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
    [switch]$NoRestorePoint
)

$Script:ScriptName = "WinUpdateRemover"
$Script:Version = "1.1"
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
Write-Host "    Windows Update Remover v$($Script:Version)" -ForegroundColor White
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
    $installedUpdates = Get-HotFix | Sort-Object {[DateTime]$_.InstalledOn} -Descending
    Write-Host "Found $($installedUpdates.Count) installed updates." -ForegroundColor Green
} catch {
    Write-Error "Error scanning for updates: $($_.Exception.Message)"
    exit 1
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
    $isProblematic = $problematicKBs -contains $update.HotFixID
    
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
    $updatesToProcess = $installedUpdates | Where-Object { $KBNumbers -contains $_.HotFixID }
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
    $kb = $update.HotFixID -replace 'KB', ''
    $desc = $update.Description
    
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
    try {
        # Try DISM first
        $dismArgs = "/Online /Remove-Package /PackageName:Package_for_KB$kb~31bf3856ad364e35~amd64~~ /quiet /norestart"
        $process = Start-Process -FilePath "dism.exe" -ArgumentList $dismArgs -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
            $removeSuccess = $true
        } else {
            # Fallback to WUSA
            $wusaArgs = "/uninstall /kb:$kb /quiet /norestart"
            $process2 = Start-Process -FilePath "wusa.exe" -ArgumentList $wusaArgs -Wait -PassThru -NoNewWindow
            $removeSuccess = ($process2.ExitCode -eq 0 -or $process2.ExitCode -eq 3010)
        }
    } catch {
        Write-Error "Exception during removal: $($_.Exception.Message)"
        $removeSuccess = $false
    }
    
    if ($removeSuccess) {
        Write-Host "KB$kb removal initiated successfully!" -ForegroundColor Green
        $processedCount++
    } else {
        Write-Error "Failed to remove KB$kb"
        $failedUpdates.Add($kb)
    }
}

# Final summary
Write-Host "`n--- Summary ---" -ForegroundColor Cyan
Write-Host "Updates processed: $processedCount" -ForegroundColor Green

if ($failedUpdates.Count -gt 0) {
    Write-Host "Failed removals: $($failedUpdates -join ', ')" -ForegroundColor Red
}

# Create log file
$logPath = Join-Path -Path $env:TEMP -ChildPath "WinUpdateRemover_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$logContent = @"
Windows Update Remover Log
=========================
Date: $(Get-Date)
Computer: $env:COMPUTERNAME
Updates processed: $processedCount
Failed removals: $($failedUpdates -join ', ')
Restore point created: $($Script:rpCreated)
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