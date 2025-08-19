<#
.SYNOPSIS
    Windows Update Remover - Remove specific Windows updates

.DESCRIPTION
    This script allows you to view and selectively remove Windows updates.
    It creates a system restore point before making changes for safety.

.NOTES
    Author: @danalec
    Version: 1.0.1
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
$Script:Version = "1.0.1"
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
        # Method 1: Try to find actual package name using DISM
        Write-Host "Searching for package information..." -ForegroundColor Gray
        $packageInfo = dism /online /get-packages | findstr /i "kb$kb"
        if ($packageInfo) {
            $packageName = ($packageInfo -split '\s+')[-1]
            if ($packageName -match "Package_for_KB$kb") {
                $dismArgs = "/Online /Remove-Package /PackageName:$packageName /quiet /norestart"
                $process = Start-Process -FilePath "dism.exe" -ArgumentList $dismArgs -Wait -PassThru -NoNewWindow
                if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
                    $removeSuccess = $true
                    $removalMethods += "DISM (auto-detected package)"
                } else {
                    $errorDetails += "DISM auto-detect exit code: $($process.ExitCode)"
                }
            }
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
            Write-Host "This error typically means the update package is not found or corrupted." -ForegroundColor Yellow
            Write-Host "Try running Windows Update Troubleshooter or manually check Windows Update settings." -ForegroundColor Yellow
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
}