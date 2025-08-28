<#
.SYNOPSIS
    Windows Update Remover - Safely remove and block Windows Updates with automatic restore point protection

.DESCRIPTION
    WinUpdateRemover is an interactive PowerShell tool designed to help Windows administrators and power users safely remove and block problematic Windows Updates that may cause system instability, performance issues, or hardware problems.

    Features:
    - Safe Removal Process: Automatic System Restore point creation before any changes
    - Targeted Removal: Remove specifi updates
    - Update Blocking: Prevent specific updates from being installed via registry-based blocking
    - Enhanced Error Handling: Improved handling for 0x800f0805 and other common errors
    - Multi-Method Removal: Enhanced removal approaches including PSWindowsUpdate module support
    - Smart Detection: Automatically checks if updates are installed before attempting removal
    - Interactive Mode: Step-by-step guidance with confirmation prompts
    - Verification Mode: Check if specific KB updates are actually installed
    - Repair Windows Update Mode: Automated Windows Update repair and cache reset
    - Diagnostic Mode: Comprehensive Windows Update system analysis
    - Block Status Checking: Verify if updates are currently blocked
    - PSWindowsUpdate Integration: Optional PowerShell module support for enhanced reliability
    - Date-Based Removal: Remove updates installed within specific date ranges
    - Remote Computer Support: Process updates on remote computers via PowerShell remoting
    - Update Hiding: Hide updates from Windows Update to prevent reinstallation

    Usage Examples:
    - Interactive: .\WinUpdateRemover.ps1
    - Specific KB: .\WinUpdateRemover.ps1 -KBNumbers "KB5055523"
    - Force Mode: .\WinUpdateRemover.ps1 -Force
    - List Only: .\WinUpdateRemover.ps1 -ListOnly
    - Verify KB: .\WinUpdateRemover.ps1 -Verify -KBNumbers "KB5055523"
    - Repair Windows Update: .\WinUpdateRemover.ps1 -QuickFix
    - Diagnostic: .\WinUpdateRemover.ps1 -Diagnostic
    - Enable System Restore: .\WinUpdateRemover.ps1 -EnableSystemRestore
    - Show Block Methods: .\WinUpdateRemover.ps1 -ShowBlockMethods
    - Block Update: .\WinUpdateRemover.ps1 -BlockUpdate -KBNumbers "KB5055523"
    - Unblock Update: .\WinUpdateRemover.ps1 -UnblockUpdate -KBNumbers "KB5055523"
    - Check Block Status: .\WinUpdateRemover.ps1 -CheckBlockStatus -KBNumbers "KB5055523"
    - Use PSWindowsUpdate: .\WinUpdateRemover.ps1 -KBNumbers "KB5055523" -UsePSWindowsUpdate
    - Hide Update: .\WinUpdateRemover.ps1 -KBNumbers "KB5055523" -HideUpdate
    - Date Range: .\WinUpdateRemover.ps1 -DateRange "2024-01-01:2024-12-31"
    - Remote Computer: .\WinUpdateRemover.ps1 -KBNumbers "KB5055523" -RemoteComputer "SERVER01"

.PARAMETER UsePSWindowsUpdate
    Use the PSWindowsUpdate PowerShell module for enhanced update removal reliability.
    This module provides better error handling and update hiding capabilities.
    Usage: -UsePSWindowsUpdate

.PARAMETER HideUpdate
    Hide the specified update from Windows Update to prevent reinstallation.
    This requires the PSWindowsUpdate module to be available.
    Usage: -HideUpdate

.PARAMETER DateRange
    Remove updates installed within a specific date range.
    Format: "YYYY-MM-DD:YYYY-MM-DD" (start:end)
    Usage: -DateRange "2024-01-01:2024-12-31"

.PARAMETER RemoteComputer
    Process updates on a remote computer via PowerShell remoting.
    Requires WinRM to be enabled on the remote computer.
    Usage: -RemoteComputer "SERVER01"

.NOTES
    Author: @danalec
    Version: 1.0.19
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
    [string]$CheckBlockStatus,

    [Parameter(Mandatory=$false)]
    [switch]$UsePSWindowsUpdate,

    [Parameter(Mandatory=$false)]
    [switch]$HideUpdate,

    [Parameter(Mandatory=$false)]
    [string]$DateRange,

    [Parameter(Mandatory=$false)]
    [string]$RemoteComputer
)

$Script:ScriptName = "WinUpdateRemover"
$Script:Version = "v1.0.19"
$ErrorActionPreference = "Stop"

# Enhanced DISM Functions for Advanced Package Management
function Get-DISMPackages {
    param(
        [Parameter(Mandatory=$false)]
        [string]$KBFilter,

        [Parameter(Mandatory=$false)]
        [switch]$FormatTable,

        [Parameter(Mandatory=$false)]
        [switch]$Clipboard
    )

    Write-Host "Retrieving DISM package information..." -ForegroundColor Yellow

    try {
        $dismCmd = if ($FormatTable) {
            "dism /online /get-packages /format:table"
        } else {
            "dism /online /get-packages"
        }

        $packages = & cmd /c $dismCmd 2>$null

        if ($KBFilter) {
            $packages = $packages | Where-Object { $_ -match "(?i)kb$KBFilter" }
        }

        if ($Clipboard) {
            $packages | clip
            Write-Host "Package list copied to clipboard!" -ForegroundColor Green
        }

        return $packages
    } catch {
        Write-Error "Failed to retrieve DISM packages: $($_.Exception.Message)"
        return $null
    }
}

function Test-DISMPackage {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PackageName
    )

    try {
        Write-Host "Testing DISM package: $PackageName" -ForegroundColor Gray
        $packageInfo = & dism /online /get-packageinfo /packagename:"$PackageName" 2>$null

        if ($packageInfo) {
            $isPermanent = $packageInfo | Where-Object { $_ -match "Permanent : Yes" }
            $canRemove = -not $isPermanent

            return [PSCustomObject]@{
                PackageName = $PackageName
                Exists = $true
                IsRemovable = $canRemove
                IsPermanent = [bool]$isPermanent
                Details = ($packageInfo -join "`n")
            }
        }

        return [PSCustomObject]@{
            PackageName = $PackageName
            Exists = $false
            IsRemovable = $false
            IsPermanent = $false
            Details = "Package not found"
        }
    } catch {
        return [PSCustomObject]@{
            PackageName = $PackageName
            Exists = $false
            IsRemovable = $false
            IsPermanent = $false
            Details = $_.Exception.Message
        }
    }
}

function Remove-DISMPackage {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PackageName,

        [Parameter(Mandatory=$false)]
        [switch]$Quiet,

        [Parameter(Mandatory=$false)]
        [switch]$NoRestart
    )

    $args = "/Online /Remove-Package /PackageName:`"$PackageName`""

    if ($Quiet) { $args += " /quiet" }
    if ($NoRestart) { $args += " /norestart" }

    Write-Host "Executing: dism $args" -ForegroundColor Cyan

    $process = Start-Process -FilePath "dism.exe" -ArgumentList $args -Wait -PassThru -NoNewWindow

    # Enhanced error mapping
    $exitCode = $process.ExitCode
    $errorMessage = switch ($exitCode) {
        0 { "Success" }
        3010 { "Success - restart required" }
        -2146498555 { "Package not found (0x800f0805)" }
        -2146498553 { "Package is permanent (0x800f0807)" }
        -2146498552 { "Restart required (0x800f0808)" }
        87 { "Invalid parameter" }
        5 { "Access denied" }
        112 { "Insufficient disk space" }
                            default { "Unknown error (Exit code: $exitCode)" }
    }

    return [PSCustomObject]@{
        Success = ($exitCode -eq 0 -or $exitCode -eq 3010)
        ExitCode = $exitCode
        Message = $errorMessage
        PackageName = $PackageName
    }
}

# Enhanced SSU detection and warning function
function Test-SSUDetection {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KBNumber
    )

    $ssuUpdates = @(
        "KB5063878", "KB5062839", "KB5062978", "KB5034441", "KB5034127",
        "KB5031356", "KB5029331", "KB5028166", "KB5027231", "KB5025221"
    )

    $criticalKB5063878 = @("KB5063878")

    $normalizedKB = $KBNumber -replace "KB", ""
    $fullKB = "KB$normalizedKB"

    if ($criticalKB5063878 -contains $fullKB) {
        Write-Host "`n================================================================================" -ForegroundColor Red
        Write-Host "[!] CRITICAL ALERT: KB5063878 DETECTED! [!]" -ForegroundColor Black -BackgroundColor Red
        Write-Host "================================================================================" -ForegroundColor Red
        Write-Host "SEVERITY: CRITICAL - SSD/HDD CORRUPTION RISK" -ForegroundColor Red
        Write-Host "IMPACT: This update has been reported to cause SSD and HDD corruption issues" -ForegroundColor Yellow
        Write-Host "REMOVAL: Combined SSU/LCU package - CANNOT be removed via automated methods" -ForegroundColor Yellow
        Write-Host "MANUAL REMOVAL REQUIRED:" -ForegroundColor Cyan
        Write-Host "   1. Settings -> Windows Update -> Update History -> Uninstall updates" -ForegroundColor White
        Write-Host "   2. Select KB5063878 and click Uninstall" -ForegroundColor White
        Write-Host "   3. Restart when prompted" -ForegroundColor White
        Write-Host "BACKUP: Consider backing up important data before removal" -ForegroundColor Magenta
        Write-Host "================================================================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "Opening Windows Settings -> Update History..." -ForegroundColor Cyan
        Start-Process "explorer.exe" "shell:::{d450a8a1-9568-45c7-9c0e-b4f9fb4537bd}"
        return $true
    }

    if ($ssuUpdates -contains $fullKB) {
        Write-Host "`n[SSU WARNING] $fullKB contains Servicing Stack Updates (SSU)" -ForegroundColor Black -BackgroundColor Yellow
        Write-Host "SSU components are permanent system updates and cannot be removed via standard methods." -ForegroundColor Yellow
        Write-Host "This update may require manual removal via Windows Settings > Update & Security > Update History > Uninstall updates" -ForegroundColor Cyan
        Write-Host "For more information, see: https://learn.microsoft.com/en-us/windows/deployment/update/servicing-stack-updates" -ForegroundColor Blue
        return $true
    }

    return $false
}

# Enhanced WUSA error handling for Windows 10 1507+
function Test-WUSAQuietMode {
    $osVersion = [System.Environment]::OSVersion.Version
    return ($osVersion.Major -ge 10 -and $osVersion.Build -ge 10240)
}

# PSWindowsUpdate module support functions
function Test-PSWindowsUpdateModule {
    try {
        $module = Get-Module -ListAvailable -Name PSWindowsUpdate
        if ($module) {
            Import-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

function Install-PSWindowsUpdateModule {
    Write-Host "Installing PSWindowsUpdate module..." -ForegroundColor Yellow
    try {
        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber
        Import-Module PSWindowsUpdate -Force
        Write-Host "PSWindowsUpdate module installed successfully!" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "Failed to install PSWindowsUpdate module: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Remove-UpdateWithPSWindowsUpdate {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KBNumber,

        [Parameter(Mandatory=$false)]
        [switch]$HideUpdate,

        [Parameter(Mandatory=$false)]
        [string]$ComputerName
    )

    $params = @{
        KBArticleID = $KBNumber
        AcceptAll = $true
        AutoReboot = $false
    }

    if ($ComputerName) {
        $params.ComputerName = $ComputerName
    }

    try {
        if ($HideUpdate) {
            Hide-WindowsUpdate @params
            Write-Host "Update $KBNumber hidden from Windows Update" -ForegroundColor Green
        } else {
            Remove-WindowsUpdate @params
            Write-Host "Update $KBNumber removed successfully via PSWindowsUpdate" -ForegroundColor Green
        }
        return $true
    } catch {
        Write-Host "PSWindowsUpdate failed: $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

# Date-based removal function
function Remove-UpdatesByDateRange {
    param(
        [Parameter(Mandatory=$true)]
        [datetime]$StartDate,
        [Parameter(Mandatory=$false)]
        [datetime]$EndDate = (Get-Date),
        [Parameter(Mandatory=$false)]
        [switch]$WhatIf
    )

    Write-Host "Searching for updates installed between $StartDate and $EndDate..." -ForegroundColor Cyan

    try {
        $updates = Get-CimInstance -ClassName Win32_QuickFixEngineering |
                   Where-Object {
                       $_.InstalledOn -and
                       ([datetime]$_.InstalledOn -ge $StartDate) -and
                       ([datetime]$_.InstalledOn -le $EndDate)
                   }

        if ($updates.Count -eq 0) {
            Write-Host "No updates found in the specified date range." -ForegroundColor Yellow
            return $false
        }

        Write-Host "Found $($updates.Count) updates to remove:" -ForegroundColor Green
        $updates | Format-Table HotFixID, Description, InstalledOn -AutoSize

        if ($WhatIf) {
            Write-Host "WhatIf: Would remove the above updates" -ForegroundColor Cyan
            return $true
        }

        $results = @()
        foreach ($update in $updates) {
            $kbNumber = $update.HotFixID -replace "KB", ""
            $result = Remove-WindowsUpdate -KBArticleID $kbNumber -AcceptAll -AutoReboot:$false
            $results += $result
        }

        return $results
    } catch {
        Write-Host "Date-based removal failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Remote computer support
function Invoke-RemoteUpdateRemoval {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        [Parameter(Mandatory=$true)]
        [string]$KBNumber,
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential
    )

    try {
        $sessionParams = @{
            ComputerName = $ComputerName
            ScriptBlock = {
                param($KB)
                try {
                    Remove-WindowsUpdate -KBArticleID $KB -AcceptAll -AutoReboot:$false
                    return @{Success = $true; Message = "Update $KB removed successfully"}
                } catch {
                    return @{Success = $false; Message = $_.Exception.Message}
                }
            }
            ArgumentList = $KBNumber
            ErrorAction = "Stop"
        }

        if ($Credential) {
            $sessionParams.Credential = $Credential
        }

        $result = Invoke-Command @sessionParams
        return $result
    } catch {
        Write-Host "Remote removal failed: $($_.Exception.Message)" -ForegroundColor Red
        return @{Success = $false; Message = $_.Exception.Message}
    }
}

# Enhanced WUSA error handling
function Remove-UpdateWithWUSA {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KBNumber,
        [Parameter(Mandatory=$false)]
        [switch]$Quiet
    )

    $cleanKB = $KBNumber -replace "^KB", ""
    $wusaArgs = "/uninstall", "/kb:$cleanKB", "/norestart"

    # Check if quiet mode is supported
    if ($Quiet -and (Test-WUSAQuietMode)) {
        Write-Host "Note: /quiet parameter may be ignored on Windows 10 1507+" -ForegroundColor Yellow
    }

    if ($Quiet) {
        $wusaArgs += "/quiet"
    }

    Write-Host "Executing: wusa.exe $wusaArgs" -ForegroundColor Cyan

    $process = Start-Process -FilePath "wusa.exe" -ArgumentList $wusaArgs -Wait -PassThru -NoNewWindow
    $exitCode = $process.ExitCode

    # Enhanced error mapping
    $errorMessage = switch ($exitCode) {
        0 { "Success" }
        3010 { "Success - restart required" }
        2 { "Invalid KB number or update not found" }
        5 { "Access denied" }
        2359302 { "Combined SSU/LCU package - cannot be removed via WUSA" }
        2147942487 { "Invalid parameter - quiet mode ignored" }
        -2145124318 { "Update cannot be removed" }
        default { "WUSA error code: $exitCode" }
    }

    return [PSCustomObject]@{
        Success = ($exitCode -eq 0 -or $exitCode -eq 3010)
        ExitCode = $exitCode
        Message = $errorMessage
        Method = "WUSA"
    }
}

# Check for administrator privileges (skip for read-only operations)
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
$requiresAdmin = -not ($ListOnly -or $ShowBlockMethods -or $CheckBlockStatus -or $Verify)
if (-not $isAdmin -and $requiresAdmin) {
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host "  ADMINISTRATOR PRIVILEGES REQUIRED" -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "This script requires administrator privileges to perform the following operations:" -ForegroundColor Yellow
    Write-Host "• Create system restore points" -ForegroundColor White
    Write-Host "• Remove Windows updates via DISM/WUSA" -ForegroundColor White
    Write-Host "• Modify Windows registry (HKLM)" -ForegroundColor White
    Write-Host "• Start/stop Windows services" -ForegroundColor White
    Write-Host "• Access Windows Update API" -ForegroundColor White
    Write-Host ""
    Write-Host "To run as administrator:" -ForegroundColor Cyan
    Write-Host "1. Right-click PowerShell and select 'Run as administrator'" -ForegroundColor White
    Write-Host "2. Or use: Start-Process powershell -Verb RunAs" -ForegroundColor White
    Write-Host ""
    Write-Host "Read-only operations (list, verify, check status) work without admin rights." -ForegroundColor Green
    Write-Host ""
    exit 1
}

# Display header
Clear-Host
Write-Host "====================================" -ForegroundColor Cyan
Write-Host "    Windows Update Remover $($Script:Version)" -ForegroundColor White
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""

$osInfo = Get-CimInstance Win32_OperatingSystem
Write-Host "System Information:" -ForegroundColor Green
Write-Host "OS: $($osInfo.Caption)" -ForegroundColor White
Write-Host "Version: $($osInfo.Version)" -ForegroundColor White
Write-Host "Architecture: $env:PROCESSOR_ARCHITECTURE" -ForegroundColor White
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
Write-Host ""

# All functions are now defined, proceed with parameter handling

# Define problematic KB updates (including combined SSU/LCU packages)
$problematicKBs = @(
    # Windows 11 24H2 - CRITICAL Issues (2025)
    'KB5063878',  # CRITICAL: SSD/HDD corruption + Combined SSU/LCU - requires manual removal via Windows Settings > Update & Security > Update History > Uninstall updates
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

    # Additional Combined SSU/LCU packages - Cannot be removed via WUSA
    # MANUAL REMOVAL REQUIRED: Settings -> Windows Update -> Update History -> Uninstall updates
    'KB5063878',  # CRITICAL: SSD/HDD CORRUPTION RISK - MANUAL REMOVAL ONLY via Windows Settings
    'KB5062839',  # Combined SSU/LCU - MANUAL REMOVAL ONLY via Windows Settings
    'KB5062978',  # Combined SSU/LCU - MANUAL REMOVAL ONLY via Windows Settings
    'KB5034441',  # Combined SSU/LCU - MANUAL REMOVAL ONLY via Windows Settings
    'KB5034127',  # Combined SSU/LCU - MANUAL REMOVAL ONLY via Windows Settings
    'KB5031356',  # Combined SSU/LCU - MANUAL REMOVAL ONLY via Windows Settings
    'KB5029331',  # Combined SSU/LCU - MANUAL REMOVAL ONLY via Windows Settings
    'KB5028166',  # Combined SSU/LCU - MANUAL REMOVAL ONLY via Windows Settings
    'KB5027231',  # Combined SSU/LCU - MANUAL REMOVAL ONLY via Windows Settings
    'KB5025221'   # Combined SSU/LCU - MANUAL REMOVAL ONLY via Windows Settings
)

# Scan for installed updates
try {
    $installedUpdates = Get-HotFix | Where-Object { $_.HotFixID -match 'KB\d+' } | Sort-Object {[DateTime]$_.InstalledOn} -Descending
} catch {
    Write-Host "Error scanning for updates: $($_.Exception.Message)" -ForegroundColor Red
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

# Function to get comprehensive list of all installed updates
function Get-AllInstalledUpdates {
    $allUpdates = @()
    $processedKBs = @{}

    # Scan Get-HotFix first (most reliable for removable updates)
    Write-Host "Scanning Get-HotFix..." -ForegroundColor Gray
    try {
        $hotfixes = Get-HotFix | Where-Object { $_.HotFixID -match 'KB\d+' } | Sort-Object {[DateTime]$_.InstalledOn} -Descending
        foreach ($hotfix in $hotfixes) {
            $kbNumber = $hotfix.HotFixID
            if (-not $processedKBs.ContainsKey($kbNumber)) {
                $allUpdates += [PSCustomObject]@{
                    KB = $kbNumber
                    Description = $hotfix.Description
                    InstallDate = $hotfix.InstalledOn
                    Source = "Get-HotFix"
                    Notes = "Removable via WUSA/DISM"
                    Removable = $true
                }
                $processedKBs[$kbNumber] = $true
            }
        }
    } catch {
        Write-Host "Error scanning Get-HotFix: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Host "Scanning DISM packages..." -ForegroundColor Gray
    try {
        $dismOutput = & dism /online /get-packages 2>$null
        if ($dismOutput) {
            $packageLines = $dismOutput -join "`n" -split "Package Identity :"
            foreach ($package in $packageLines) {
                if ($package -match "KB(\d+)") {
                    $kbNumber = "KB$($matches[1])"
                    if (-not $processedKBs.ContainsKey($kbNumber)) {
                        # Extract package name and state
                        $packageName = ($package -split "`n" | Where-Object { $_ -match "Package_" } | Select-Object -First 1).Trim()
                        $state = ($package -split "`n" | Where-Object { $_ -match "State :" } | Select-Object -First 1) -replace "State :", "" | ForEach-Object { $_.Trim() }

                        if ($state -eq "Installed") {
                            # Test DISM package removability using actual DISM test
                            $isRemovable = $false
                            $removabilityNotes = "Component Package"

                            try {
                                # Test actual removability using DISM
                                $testResult = Test-DISMPackage -PackageName $packageName
                                $isRemovable = $testResult.Removable
                                $removabilityNotes = if ($isRemovable) { "[DISM] Removable" } else { "[DISM] Permanent" }

                                # Get additional package details
                                $installTime = ($package -split "`n" | Where-Object { $_ -match "Install Time :" } | Select-Object -First 1) -replace "Install Time :", "" | ForEach-Object { $_.Trim() }

                                # Parse install date from install time if available
                                $installDate = $null
                                if ($installTime -match "(\d{1,2}/\d{1,2}/\d{4})") {
                                    $installDate = [DateTime]::Parse($matches[1])
                                }

                            } catch {
                                # Fallback to heuristic if test fails
                                $packageDetails = ($package -split "`n" | Where-Object { $_ -match "Release Type :" } | Select-Object -First 1) -replace "Release Type :", "" | ForEach-Object { $_.Trim() }

                                # Most DISM packages are removable unless they're permanent system components
                                if ($packageDetails -notmatch "Permanent|OnDemand" -and $packageName -notmatch "LanguagePack|FeatureOnDemand") {
                                    $isRemovable = $true
                                    $removabilityNotes = "[DISM] Removable"
                                } else {
                                    $isRemovable = $false
                                    $removabilityNotes = "[DISM] Permanent"
                                }
                            }

                            $allUpdates += [PSCustomObject]@{
                                KB = $kbNumber
                                Description = if ($packageName) { $packageName } else { "DISM Package" }
                                InstallDate = $installDate
                                Source = "DISM"
                                Notes = $removabilityNotes
                                Removable = $isRemovable
                            }
                            $processedKBs[$kbNumber] = $true
                        }
                    }
                }
            }
        }
    } catch {
        Write-Host "Error scanning DISM: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Host "Scanning Windows Update API..." -ForegroundColor Gray
    try {
        $session = New-Object -ComObject "Microsoft.Update.Session"
        $searcher = $session.CreateUpdateSearcher()
        $updates = $searcher.Search("IsInstalled=1 and Type='Software'")

        foreach ($update in $updates.Updates) {
            if ($update.KBArticleIDs.Count -gt 0) {
                foreach ($kbId in $update.KBArticleIDs) {
                    $kbNumber = "KB$kbId"
                    if (-not $processedKBs.ContainsKey($kbNumber)) {
                        $allUpdates += [PSCustomObject]@{
                            KB = $kbNumber
                            Description = $update.Title
                            InstallDate = $update.LastDeploymentChangeTime
                            Source = "Windows Update API"
                            Notes = "Informational only"
                            Removable = $false
                        }
                        $processedKBs[$kbNumber] = $true
                    }
                }
            }
        }
    } catch {
        Write-Host "Error scanning Windows Update API: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    return $allUpdates
}


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
        # Check if DISM is available
        $dismAvailable = Get-Command "dism.exe" -ErrorAction SilentlyContinue
        if (-not $dismAvailable) {
            Write-Host "   [X] DISM command not available" -ForegroundColor Red
        } else {
            $dismOutput = & dism /online /get-packages 2>$null | Where-Object { $_ -match "kb$KBNumber" -and $_ -match "Package" }
            if ($dismOutput) {
                Write-Host "   [OK] FOUND: KB$KBNumber in DISM packages" -ForegroundColor Green
                Write-Host "   Package info: $dismOutput" -ForegroundColor White
                $found = $true
            } else {
                Write-Host "   [X] NOT FOUND via DISM packages" -ForegroundColor Red
            }
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

    # Final summary
    if ($found) {
        Write-Host "=== SUMMARY: KB$KBNumber IS INSTALLED ===" -ForegroundColor Black -BackgroundColor Yellow
        Write-Host "This update is currently installed on your system." -ForegroundColor Yellow
        Write-Host "Use WinUpdateRemover to remove it if needed." -ForegroundColor Cyan
    } else {
        Write-Host "=== SUMMARY: KB$KBNumber IS NOT INSTALLED ===" -ForegroundColor Green
        Write-Host "This update is not currently installed on your system." -ForegroundColor Green
    }

    return $found
}

# Function to analyze Windows Update system health
function Invoke-Diagnostic {
    Write-Host "=== Windows Update System Diagnostic ===" -ForegroundColor Cyan
    Write-Host "Running comprehensive Windows Update health check..." -ForegroundColor Yellow
    Write-Host ""

    # 1. Check Windows Update service status
    Write-Host "1. Checking Windows Update services..." -ForegroundColor Yellow
    $services = @("wuauserv", "bits", "cryptsvc", "msiserver")
    foreach ($service in $services) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                $status = if ($svc.Status -eq "Running") { "[OK] Running" } else { "[X] Stopped" }
                Write-Host "   ${service}: $status" -ForegroundColor $(if ($svc.Status -eq "Running") { "Green" } else { "Red" })
            } else {
                Write-Host "   ${service}: Not found" -ForegroundColor Gray
            }
        } catch {
            Write-Host "   ${service}: Error checking - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host ""

    # 2. Check Windows Update registry keys
    Write-Host "2. Checking Windows Update registry..." -ForegroundColor Yellow
    $regKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing"
    )

    foreach ($regKey in $regKeys) {
        try {
            if (Test-Path $regKey) {
                Write-Host "   [OK] $regKey" -ForegroundColor Green
            } else {
                Write-Host "   [X] $regKey (missing)" -ForegroundColor Red
            }
        } catch {
            Write-Host "   [X] $regKey (error)" -ForegroundColor Red
        }
    }
    Write-Host ""

    # 3. Check Windows Update cache
    Write-Host "3. Checking Windows Update cache..." -ForegroundColor Yellow
    $cachePaths = @(
        "$env:SystemRoot\SoftwareDistribution",
        "$env:SystemRoot\System32\catroot2"
    )

    foreach ($cachePath in $cachePaths) {
        try {
            if (Test-Path $cachePath) {
                $size = (Get-ChildItem -Path $cachePath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                $sizeMB = [math]::Round($size / 1MB, 2)
                Write-Host "   [OK] $cachePath ($sizeMB MB)" -ForegroundColor Green
            } else {
                Write-Host "   [X] $cachePath (missing)" -ForegroundColor Red
            }
        } catch {
            Write-Host "   [X] $cachePath (error: $($_.Exception.Message))" -ForegroundColor Red
        }
    }
    Write-Host ""

    # 4. Check Windows Update history
    Write-Host "4. Checking Windows Update history..." -ForegroundColor Yellow
    try {
        $session = New-Object -ComObject "Microsoft.Update.Session"
        $searcher = $session.CreateUpdateSearcher()
        $history = $searcher.QueryHistory(0, 50) | Where-Object { $_.ResultCode -eq 2 }

        if ($history.Count -gt 0) {
            Write-Host "   [OK] Found $($history.Count) successful updates" -ForegroundColor Green
            $lastUpdate = $history[0]
            Write-Host "   Last update: $($lastUpdate.Title)" -ForegroundColor White
            Write-Host "   Date: $($lastUpdate.Date)" -ForegroundColor White
        } else {
            Write-Host "   [X] No update history found" -ForegroundColor Red
        }
    } catch {
        Write-Host "   [X] Error checking update history: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""

    # 5. Check system file integrity
    Write-Host "5. Checking system file integrity..." -ForegroundColor Yellow
    try {
        $sfcResult = & sfc /verifyonly 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "   [OK] System file integrity: OK" -ForegroundColor Green
        } else {
            Write-Host "   [X] System file integrity issues detected" -ForegroundColor Red
        }
    } catch {
        Write-Host "   [X] Error checking system files: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""

    Write-Host "=== Diagnostic Complete ===" -ForegroundColor Cyan
    Write-Host "Run 'sfc /scannow' or 'DISM /Online /Cleanup-Image /RestoreHealth' to fix issues" -ForegroundColor Yellow
}

# Function to enable System Restore
function Invoke-EnableSystemRestore {
    Write-Host "=== Enabling System Restore ===" -ForegroundColor Cyan
    Write-Host "Attempting to enable System Restore..." -ForegroundColor Yellow
    Write-Host ""

    # [FIX]: The original function was incomplete. This is a placeholder for the missing code.
    Write-Host "[!] Incomplete function - The original script ended here." -ForegroundColor Red
    Write-Host "[!] Please consult the script author for the complete implementation." -ForegroundColor Red

    # [Original script ended here]
}

function Show-BlockMethods {
    Write-Host "=== Update Blocking Methods ===" -ForegroundColor Cyan
    Write-Host "Windows updates can be blocked using a few methods:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Registry-based Blocking (Used by this script)" -ForegroundColor Cyan
    Write-Host ' - HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\HiddenUpdates'
    Write-Host " - This method is simple and effective for preventing a specific KB from being offered."
    Write-Host ""
    Write-Host "2. Group Policy (Enterprise environments)" -ForegroundColor Cyan
    Write-Host " - Configure through gpedit.msc"
    Write-Host ' - Computer Configuration > Administrative Templates > Windows Components > Windows Update'
    Write-Host " - Set 'Configure Automatic Updates' to disabled"
    Write-Host ""
    Write-Host "3. Windows Update Settings" -ForegroundColor Yellow
    Write-Host ' - Settings > Update and Security > Windows Update'
    Write-Host ' - Advanced options > Choose how updates are delivered'
    Write-Host " - Pause updates for up to 35 days"
    Write-Host ""
    Write-Host "4. WSUS Offline (Advanced users)" -ForegroundColor Magenta
    Write-Host " - Download and install specific updates manually"
    Write-Host " - Bypass Windows Update entirely"
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
        if ($KBNumber -eq "all" -or $KBNumber -eq "ALL") {
            Write-Host "Checking block status for ALL updates..." -ForegroundColor Yellow
            Write-Host ""
            # Scan all blocked updates in registry
            $hiddenPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\HiddenUpdates"
            $blockedUpdates = @()
            if (Test-Path $hiddenPath) {
                $properties = Get-ItemProperty -Path $hiddenPath -ErrorAction SilentlyContinue
                foreach ($prop in $properties.PSObject.Properties) {
                    if ($prop.Name -match "^KB(\d+)$") {
                        $blockedUpdates += $prop.Name
                    }
                }
            }
            if ($blockedUpdates.Count -gt 0) {
                Write-Host "=== Currently Blocked Updates ===" -ForegroundColor Red
                foreach ($blocked in $blockedUpdates | Sort-Object) {
                    Write-Host "[BLOCKED] $blocked" -ForegroundColor Red
                }
                Write-Host ""
                Write-Host "Total blocked: $($blockedUpdates.Count) updates" -ForegroundColor Yellow
            } else {
                Write-Host "[INFO] No updates are currently blocked" -ForegroundColor Green
            }
            Write-Host ""
            return
        }
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
                Write-Host '[NOT AVAILABLE] KB$KBNumber is not available in Windows Update' -ForegroundColor Cyan
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
    # Check if this is a combined SSU/LCU update
    $combinedSSUUpdates = @("5063878", "5062839", "5062978", "5034441", "5034127", "5031356", "5029331", "5028166", "5027231", "5025221")
    $isCombinedSSU = $normalizedKB -and ($combinedSSUUpdates -contains $normalizedKB)
    if ($isCombinedSSU) {
        Write-Host "[$($i+1)] $($update.HotFixID) - $($update.Description) $installDate" -ForegroundColor Red -BackgroundColor Yellow
        Write-Host " *** COMBINED SSU/LCU UPDATE - MANUAL REMOVAL ONLY ***" -ForegroundColor Red -BackgroundColor Yellow
        $problematicCount++
    } elseif ($isProblematic) {
        Write-Host "[$($i+1)] $($update.HotFixID) - $($update.Description) $installDate" -ForegroundColor Red -BackgroundColor Yellow
        Write-Host " *** PROBLEMATIC UPDATE DETECTED ***" -ForegroundColor Red -BackgroundColor Yellow
        $problematicCount++
    } else {
        Write-Host "[$($i+1)] $($update.HotFixID) - $($update.Description) $installDate" -ForegroundColor White
    }
}
if ($problematicCount -gt 0) {
    Write-Host "`n*** WARNING: $problematicCount problematic update(s) found! ***" -ForegroundColor Red -BackgroundColor Yellow
    Write-Host "Some updates may require manual removal via Settings GUI." -ForegroundColor Yellow
}
# Handle KBNumbers parameter
if ($KBNumbers) {
    # Validate KB input for combined SSU/LCU packages
    if (-not (Validate-KBInput -KBNumbers $KBNumbers)) {
        exit 0
    }
    $normalizedKBNumbers = $KBNumbers | ForEach-Object { Get-NormalizedKBNumber $_ }
    $updatesToProcess = $installedUpdates | Where-Object { $normalizedKB = Get-NormalizedKBNumber $_.HotFixID; $normalizedKB -and ($normalizedKBNumbers -contains $normalizedKB) }
    if ($updatesToProcess.Count -eq 0) {
        Write-Warning 'None of the specified KB numbers were found installed.'
        exit 0
    }
}
# Handle ListOnly parameter - display comprehensive listing
if ($ListOnly) {
    Write-Host "=== Comprehensive Update Listing ===" -ForegroundColor Cyan
    Write-Host "Scanning all update sources..." -ForegroundColor Yellow
    Write-Host ""
    # Get comprehensive update list
    $allUpdates = Get-AllInstalledUpdates
    if ($allUpdates.Count -eq 0) {
        Write-Host "No updates found." -ForegroundColor Yellow
        Read-Host "Press Enter to exit"
        exit 0
    } else {
        Write-Host "Found $($allUpdates.Count) installed updates:" -ForegroundColor Green
        Write-Host ""
        # Group by source for better organization
        $groupedUpdates = $allUpdates | Group-Object Source
        foreach ($group in $groupedUpdates) {
            Write-Host "--- $($group.Name) Updates ---" -ForegroundColor Cyan
            foreach ($update in $group.Group | Sort-Object InstallDate -Descending) {
                $installDate = if ($update.InstallDate) { $update.InstallDate.ToString("yyyy-MM-dd") } else { "Unknown" }
                # Determine removability indicator based on source and Removable property
                $removabilityIndicator = ""
                $textColor = "White"
                if ($update.Source -eq "Get-HotFix") {
                    $removabilityIndicator = "[Get-HotFix] Removable"
                    $textColor = "White"
                } elseif ($update.Source -eq "DISM") {
                    if ($update.Removable) {
                        $removabilityIndicator = "[DISM] Removable"
                        $textColor = "White"
                    } else {
                        $removabilityIndicator = "[DISM] Permanent"
                        $textColor = "Gray"
                    }
                } else {
                    $removabilityIndicator = "[Info Only]"
                    $textColor = "Gray"
                }
                Write-Host "$($update.KB) - $($update.Description) [$installDate] $removabilityIndicator" -ForegroundColor $textColor
                if ($update.Notes) { Write-Host " Note: $($update.Notes)" -ForegroundColor Gray }
            }
            Write-Host ""
        }
        Write-Host "Note: Updates marked as 'Removable' can be removed using this tool (Get-HotFix and DISM sources)." -ForegroundColor Yellow
        Write-Host "Continuing to interactive menu for removal options..." -ForegroundColor Green
        Write-Host ""
        Read-Host "Press Enter to continue to interactive menu"
    }
}
if ($CheckBlockStatus) {
    # Handle CheckBlockStatus parameter
    Write-Host "Checking blocking status of updates..." -ForegroundColor Yellow
    Write-Host ""
    # Check if CheckBlockStatus has a value
    if ($CheckBlockStatus -eq "all" -or $CheckBlockStatus -eq "A") {
        Check-UpdateBlockStatus -KBNumber "all"
    } elseif ($CheckBlockStatus) {
        # Handle specific KB number
        $normalizedKB = Get-NormalizedKBNumber $CheckBlockStatus
        if ($normalizedKB) {
            Check-UpdateBlockStatus -KBNumber $normalizedKB
        } else {
            Write-Warning "Invalid KB format: $CheckBlockStatus"
        }
    } else {
        Write-Host "Usage: -CheckBlockStatus -a (to check all blocked updates)" -ForegroundColor Cyan
        Write-Host "Or use: -CheckBlockStatus \"all\" or -CheckBlockStatus \"A\"" -ForegroundColor Cyan
        Write-Host "Or use: -CheckBlockStatus \"KB1234567\" (for specific KB)" -ForegroundColor Cyan
    }
    exit 0
}
if ($BlockUpdate) {
    # Handle BlockUpdate parameter
    if ($KBNumbers) {
        Write-Host "Blocking specified updates..." -ForegroundColor Yellow
        Write-Host ""
        foreach ($kb in $KBNumbers) {
            $normalizedKB = Get-NormalizedKBNumber $kb
            if ($normalizedKB) {
                Block-UpdateKB -KBNumber $normalizedKB
            } else {
                Write-Warning "Invalid KB format: $kb"
            }
        }
    } else {
        Write-Host "Usage: -BlockUpdate -KBNumbers \"KB1234567\"" -ForegroundColor Cyan
        Write-Host "Or use: -BlockUpdate -KBNumbers \"KB1234567\",\"KB2345678\"" -ForegroundColor Cyan
    }
    exit 0
}
if ($UnblockUpdate) {
    # Handle UnblockUpdate parameter
    if ($KBNumbers) {
        Write-Host "Unblocking specified updates..." -ForegroundColor Yellow
        Write-Host ""
        foreach ($kb in $KBNumbers) {
            $normalizedKB = Get-NormalizedKBNumber $kb
            if ($normalizedKB) {
                Unblock-UpdateKB -KBNumber $normalizedKB
            } else {
                Write-Warning "Invalid KB format: $kb"
            }
        }
    } else {
        Write-Host "Usage: -UnblockUpdate -KBNumbers \"KB1234567\"" -ForegroundColor Cyan
        Write-Host "Or use: -UnblockUpdate -KBNumbers \"KB1234567\",\"KB2345678\"" -ForegroundColor Cyan
    }
    exit 0
}
# Interactive menu - run if no other parameters were specified, or if ListOnly was used
if (-not ($KBNumbers -or $CheckBlockStatus -or $BlockUpdate -or $UnblockUpdate) -or $ListOnly) {
    # Interactive menu - loop until user exits
    do {
        Clear-Host
        Write-Host "===========================================" -ForegroundColor Cyan
        Write-Host " Windows Update Remover $($Script:Version) - JP" -ForegroundColor White
        Write-Host "===========================================" -ForegroundColor Cyan
        Write-Host ""
        $osInfo = Get-CimInstance Win32_OperatingSystem
        Write-Host "システム情報:" -ForegroundColor Green
        Write-Host "OS: $($osInfo.Caption)" -ForegroundColor White
        Write-Host "バージョン: $($osInfo.Version)" -ForegroundColor White
        Write-Host "アーキテクチャ: $env:PROCESSOR_ARCHITECTURE" -ForegroundColor White
        Write-Host "コンピューター: $env:COMPUTERNAME" -ForegroundColor White
        Write-Host ""
        Write-Host "=== インタラクティブメニュー ===" -ForegroundColor Cyan
        Write-Host "アクションを選択してください:" -ForegroundColor Yellow
        Write-Host "1. インストール済みの更新を一覧で表示" -ForegroundColor White
        Write-Host "2. 特定の更新のインストールをブロック" -ForegroundColor White
        Write-Host "3. 更新のブロックを解除" -ForegroundColor White
        Write-Host "4. 更新のブロックの状態を確認" -ForegroundColor White
        Write-Host "5. ブロック方法の情報を表示" -ForegroundColor White
        Write-Host "6. Windows Update を修復" -ForegroundColor White
        Write-Host "7. 診断を実行" -ForegroundColor White
        Write-Host "0. 終了 (または「q」を入力で終了)" -ForegroundColor Gray
        Write-Host ""
        $menuChoice = Read-Host "数字で選択してください (0-7 または q で終了)"
        switch ($menuChoice) {
            "1" {
                # Enhanced update listing and removal functionality
                Write-Host ""
                Write-Host "=== 包括的な更新の一覧 ===" -ForegroundColor Cyan
                Write-Host "すべての更新ソースをスキャン中です..." -ForegroundColor Yellow
                Write-Host ""
                try {
                    # Get comprehensive update list
                    $allUpdates = Get-AllInstalledUpdates
                    # Build list of removable updates (Get-HotFix and DISM removable)
                    $installedUpdates = @()
                    $removableUpdates = @()
                    foreach ($update in $allUpdates) {
                        if ($update.Source -eq "Get-HotFix") {
                            # Use original HotFix object for removal compatibility
                            $hotfixUpdate = Get-HotFix -Id $update.KB -ErrorAction SilentlyContinue
                            if ($hotfixUpdate) {
                                $installedUpdates += $hotfixUpdate
                                $removableUpdates += $update
                            }
                        } elseif ($update.Source -eq "DISM" -and $update.Removable) {
                            # Create HotFix-like object for DISM removable updates
                            $dismUpdate = [PSCustomObject]@{
                                HotFixID = $update.KB
                                Description = $update.Description
                                InstalledOn = $update.InstallDate
                                Source = "DISM"
                            }
                            $installedUpdates += $dismUpdate
                            $removableUpdates += $update
                        }
                    }
                    Write-Host "インストールされた更新プログラムの合計数は $($allUpdates.Count) 個です。このツールで削除可能な更新プログラムは ($($installedUpdates.Count 個存在します。" -ForegroundColor Green
                    Write-Host ""
                    # Display comprehensive list grouped by source
                    $groupedUpdates = $allUpdates | Group-Object Source
                    foreach ($group in $groupedUpdates) {
                        Write-Host "--- $($group.Name) の更新 ---" -ForegroundColor Cyan
                        foreach ($update in $group.Group | Sort-Object InstallDate -Descending) {
                            $installDate = if ($update.InstallDate) { $update.InstallDate.ToString("yyyy-MM-dd") } else { "Unknown" }
                            # Use pre-formatted removability indicators from Notes
                            $removabilityIndicator = $update.Notes
                            $textColor = "White"
                            # Determine text color based on removability
                            if ($removabilityIndicator -like "*DISM*Removable*" -or $removabilityIndicator -like "*Get-HotFix*Removable*") {
                                $textColor = "White"
                            } elseif ($removabilityIndicator -like "*DISM*Permanent*" -or $removabilityIndicator -like "*Info Only*") {
                                $textColor = "Gray"
                            } else {
                                $textColor = "White"
                            }
                            Write-Host "$($update.KB) - $($update.Description) [$installDate] $removabilityIndicator" -ForegroundColor $textColor
                            if ($update.Notes) { Write-Host " Note: $($update.Notes)" -ForegroundColor Gray }
                        }
                        Write-Host ""
                    }
                    Write-Host "注意: 「削除可能」とマークされた更新は、このツール (Get-HotFix と DISM ソース) を使用して削除できます。" -ForegroundColor Yellow
                    Write-Host "その他の更新は情報提供のみを目的として表示されます。" -ForegroundColor Yellow
                    Write-Host ""
                    if ($installedUpdates.Count -eq 0) {
                        Write-Host "削除する更新が見つかりません。" -ForegroundColor Yellow
                        Read-Host "Enter を押して続行"
                        continue
                    }
                    # Cache removability results to avoid redundant checks
                    $removabilityCache = @{}
                    Write-Host "インストール済みの更新:" -ForegroundColor Cyan
                    Write-Host "==================" -ForegroundColor Cyan
                    Write-Host "削除可能状態: [OK] 削除可能 [!] 削除可能な可能性あり [X] 削除不可" -ForegroundColor Gray
                    Write-Host ""
                    # Pre-calculate all removability results
                    $removabilityResults = @()
                    for ($i = 0; $i -lt $installedUpdates.Count; $i++) {
                        $update = $installedUpdates[$i]
                        $kbNumber = Get-NormalizedKBNumber $update.HotFixID
                        if (-not $removabilityCache.ContainsKey($kbNumber)) {
                            $removabilityCache[$kbNumber] = Test-KBRemovability -KBNumber $kbNumber
                        }
                        $removabilityResults += $removabilityCache[$kbNumber]
                    }
                    # Display updates with cached removability results
                    for ($i = 0; $i -lt $installedUpdates.Count; $i++) {
                        $update = $installedUpdates[$i]
                        $installedDate = if ($update.InstalledOn) { $update.InstalledOn.ToString("yyyy-MM-dd") } else { "Unknown" }
                        $kbNumber = Get-NormalizedKBNumber $update.HotFixID
                        $removability = $removabilityResults[$i]
                        # Determine display based on removability
                        switch ($removability.Removability) {
                            'Removable' { $status = "[OK]" $color = "Green" }
                            'Potentially Removable' { $status = "[!]" $color = "Yellow" }
                            'Not Removable' { $status = "[X]" $color = "Red" }
                            default { $status = "[?]" $color = "White" }
                        }
                        # Add reason if not removable
                        $reason = ""
                        if ($removability.Removability -eq 'Not Removable' -and $removability.Reason) {
                            $reason = " - $($removability.Reason)"
                        } elseif ($removability.Removability -eq 'Potentially Removable' -and $removability.Reason) {
                            $reason = " - $($removability.Reason)"
                        }
                        Write-Host "$($i+1). $status $($update.HotFixID) - $($update.Description) $installedDate$reason" -ForegroundColor $color
                    }
                    Write-Host ""
                    # Use all installed updates without filtering
                    $filteredUpdates = $installedUpdates
                    Write-Host "Select updates to remove:" -ForegroundColor Yellow
                    Write-Host '- 数字をコンマで区切って入力してください (例: 1,3,5)' -ForegroundColor Yellow
                    Write-Host "- すべての更新を選択するには「all」または「A」を入力してください" -ForegroundColor Gray
                    Write-Host "- メインメニューに戻るには「back」または「b」を入力してください" -ForegroundColor Gray
                    $selection = Read-Host "あなたの選択"
                    if ($selection -eq 'back' -or $selection -eq 'b') { continue }
                    # Parse selection
                    $updatesToProcess = @()
                    if ($selection -eq 'all' -or $selection -eq 'A') {
                        $updatesToProcess = $filteredUpdates
                    } else {
                        $indices = $selection -split ',' | ForEach-Object { $_.Trim() }
                        foreach ($index in $indices) {
                            if ($index -match '^\d+$') {
                                $idx = [int]$index - 1
                                if ($idx -ge 0 -and $idx -lt $filteredUpdates.Count) {
                                    $updatesToProcess += $filteredUpdates[$idx]
                                }
                            }
                        }
                    }
                    if ($updatesToProcess.Count -eq 0) {
                        Write-Host "無効な選択です。メインメニューに戻ります。" -ForegroundColor Red
                        Read-Host "Enter を押して続行"
                        continue
                    }
                    # Prompt for confirmation
                    Write-Host "`n以下の更新を削除しようとしています:" -ForegroundColor Yellow
                    $updatesToProcess | Format-Table HotFixID, Description, InstalledOn
                    $confirm = Read-Host "続行しますか？ (y/n)"
                    if ($confirm -ne 'y') {
                        Write-Host "削除はキャンセルされました。メインメニューに戻ります。" -ForegroundColor Red
                        Read-Host "Enter を押して続行"
                        continue
                    }
                    # Create restore point
                    if (-not $NoRestorePoint) {
                        Write-Host "`nシステム復元ポイントを作成しています..." -ForegroundColor Cyan
                        try {
                            Checkpoint-Computer -Description "WinUpdateRemover - Removing updates" -Force
                            Write-Host "復元ポイントが正常に作成されました。" -ForegroundColor Green
                        } catch {
                            Write-Host "復元ポイントの作成に失敗しました: $($_.Exception.Message)" -ForegroundColor Red
                            Write-Host "続行しますか？ (y/n) - 復元ポイントなしで実行します" -ForegroundColor Yellow
                            $confirmNoRestore = Read-Host
                            if ($confirmNoRestore -ne 'y') {
                                Write-Host "削除はキャンセルされました。メインメニューに戻ります。" -ForegroundColor Red
                                Read-Host "Enter を押して続行"
                                continue
                            }
                        }
                    }
                    # Process removal
                    foreach ($update in $updatesToProcess) {
                        Write-Host "`n更新 $($update.HotFixID) の削除を開始しています..." -ForegroundColor Cyan
                        $kbNumber = Get-NormalizedKBNumber $update.HotFixID
                        # Check for combined SSU/LCU updates that need manual removal
                        if (Test-SSUDetection -KBNumber $kbNumber) {
                            Write-Host "この更新は手動でのみ削除できます。スキップします。" -ForegroundColor Red
                            continue
                        }
                        # Use DISM or WUSA to remove
                        $removalResult = $null
                        if ($update.Source -eq "DISM") {
                            $removalResult = Remove-DISMPackage -PackageName $update.Description
                        } else {
                            $removalResult = Remove-UpdateWithWUSA -KBNumber $kbNumber -Quiet
                        }
                        if ($removalResult.Success) {
                            Write-Host "更新 $($update.HotFixID) が正常に削除されました。" -ForegroundColor Green
                        } else {
                            Write-Host "更新 $($update.HotFixID) の削除に失敗しました: $($removalResult.Message)" -ForegroundColor Red
                        }
                    }
                    Write-Host "`nすべての更新の処理が完了しました。" -ForegroundColor Green
                    Read-Host "Enter を押して続行"
                } catch {
                    Write-Host "エラーが発生しました: $($_.Exception.Message)" -ForegroundColor Red
                    Read-Host "Enter を押して続行"
                }
            }
            "2" {
                # Block update
                $kbToBlock = Read-Host "ブロックするKB番号を入力してください (例: KB1234567)"
                if ($kbToBlock) {
                    $normalizedKB = Get-NormalizedKBNumber $kbToBlock
                    if ($normalizedKB) {
                        Block-UpdateKB -KBNumber $normalizedKB
                    } else {
                        Write-Warning "無効なKB形式です。"
                    }
                }
                Read-Host "Enter を押して続行"
            }
            "3" {
                # Unblock update
                $kbToUnblock = Read-Host "ブロックを解除するKB番号を入力してください (例: KB1234567)"
                if ($kbToUnblock) {
                    $normalizedKB = Get-NormalizedKBNumber $kbToUnblock
                    if ($normalizedKB) {
                        Unblock-UpdateKB -KBNumber $normalizedKB
                    } else {
                        Write-Warning "無効なKB形式です。"
                    }
                }
                Read-Host "Enter を押して続行"
            }
            "4" {
                # Check block status
                $kbToCheck = Read-Host "確認するKB番号を入力するか、「all」と入力してすべて表示してください"
                if ($kbToCheck) {
                    if ($kbToCheck -eq "all") {
                        Check-UpdateBlockStatus -KBNumber "all"
                    } else {
                        $normalizedKB = Get-NormalizedKBNumber $kbToCheck
                        if ($normalizedKB) {
                            Check-UpdateBlockStatus -KBNumber $normalizedKB
                        } else {
                            Write-Warning "無効なKB形式です。"
                        }
                    }
                }
                Read-Host "Enter を押して続行"
            }
            "5" {
                Show-BlockMethods
                Read-Host "Enter を押して続行"
            }
            "6" {
                Write-Host "Windows Updateコンポーネントをリセットして修復しています..." -ForegroundColor Yellow
                Write-Host "サービスを停止しています..." -ForegroundColor Cyan
                net stop wuauserv | Out-Null
                net stop bits | Out-Null
                net stop cryptsvc | Out-Null
                Write-Host "キャッシュフォルダの名前を変更しています..." -ForegroundColor Cyan
                if (Test-Path "$env:SystemRoot\SoftwareDistribution") {
                    Rename-Item -Path "$env:SystemRoot\SoftwareDistribution" -NewName "SoftwareDistribution.old" -Force
                }
                if (Test-Path "$env:SystemRoot\System32\catroot2") {
                    Rename-Item -Path "$env:SystemRoot\System32\catroot2" -NewName "catroot2.old" -Force
                }
                Write-Host "サービスを再開しています..." -ForegroundColor Cyan
                net start wuauserv | Out-Null
                net start bits | Out-Null
                net start cryptsvc | Out-Null
                Write-Host "リセットが完了しました。更新を再スキャンしてください。" -ForegroundColor Green
                Read-Host "Enter を押して続行"
            }
            "7" {
                Invoke-Diagnostic
                Read-Host "Enter を押して続行"
            }
            "0", "q" {
                Write-Host "スクリプトを終了します。さようなら！" -ForegroundColor Cyan
                Read-Host "Enter を押して終了"
                exit 0
            }
            default {
                Write-Host "無効な選択です。もう一度お試しください。" -ForegroundColor Red
                Read-Host "Enter を押して続行"
            }
        }
    } while ($true)
}
# End of interactive menu
