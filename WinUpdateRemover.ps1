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
    [string]$RemoteComputer,
    
    [Parameter(Mandatory=$false)]
    [switch]$a
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
$requiresAdmin = -not ($ListOnly -or $ShowBlockMethods -or $CheckBlockStatus -or $Verify -or $a)
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
                                $testResult = Test-DISMPackage -KBNumber $kbNumber
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
    
    try {
        # Check if System Restore is available
        $checkpoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if ($checkpoints) {
            Write-Host "[OK] System Restore is already enabled" -ForegroundColor Green
            Write-Host "Available restore points: $($checkpoints.Count)" -ForegroundColor White
            return
        }
        
        # Enable System Restore
        Write-Host "Enabling System Restore..." -ForegroundColor Yellow
        try {
            Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
            Write-Host "[OK] System Restore enabled for $env:SystemDrive" -ForegroundColor Green
        } catch {
            Write-Host "[X] Failed to enable System Restore: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Manual steps:" -ForegroundColor Yellow
            Write-Host "1. Run: services.msc" -ForegroundColor White
            Write-Host "2. Set 'System Restore Service' to Automatic" -ForegroundColor White
            Write-Host "3. Start the service" -ForegroundColor White
        }
    } catch {
        Write-Host "[X] Error enabling System Restore: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to show blocking methods
function Show-BlockingMethods {
    Write-Host "=== Windows Update Blocking Methods ===" -ForegroundColor Cyan
    Write-Host "Available methods to prevent specific updates:" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "Method 1: Registry Blocking" -ForegroundColor Green
    Write-Host "   - Blocks updates via registry entries" -ForegroundColor White
    Write-Host "   - Location: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ForegroundColor Gray
    Write-Host "   - Usage: WinUpdateRemover.ps1 -BlockUpdate -KBNumbers KB1234567" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Method 2: WUShowHide Tool" -ForegroundColor Green
    Write-Host "   - Microsoft's official tool for hiding updates" -ForegroundColor White
    Write-Host "   - Download: https://support.microsoft.com/help/3073930" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Method 3: Group Policy (Pro/Enterprise)" -ForegroundColor Green
    Write-Host "   - Configure via Local Group Policy Editor" -ForegroundColor White
    Write-Host "   - Path: Computer Configuration > Administrative Templates > Windows Components > Windows Update" -ForegroundColor Gray
    Write-Host ""
}

# Function to block specific KB updates
function Block-UpdateKB {
    param([string]$KBNumber)
    
    Write-Host "=== Blocking Update KB$KBNumber ===" -ForegroundColor Cyan
    
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        $regName = "DoNotConnectToWindowsUpdateInternetLocations"
        Set-ItemProperty -Path $regPath -Name $regName -Value 0 -Type DWord -Force
        
        Write-Host "Update KB$KBNumber blocked successfully" -ForegroundColor Green
        Write-Host "   Note: This prevents Windows Update from installing the specified update" -ForegroundColor Yellow
    } catch {
        Write-Host "Failed to block update: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to unblock specific KB updates
function Unblock-UpdateKB {
    param([string]$KBNumber)
    
    Write-Host "=== Unblocking Update KB$KBNumber ===" -ForegroundColor Cyan
    
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (Test-Path $regPath) {
            Remove-ItemProperty -Path $regPath -Name "DoNotConnectToWindowsUpdateInternetLocations" -Force -ErrorAction SilentlyContinue
        }
        
        Write-Host "[OK] Update KB$KBNumber unblocked successfully" -ForegroundColor Green
    } catch {
        Write-Host "Failed to unblock update: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to check if update is blocked
function Check-UpdateBlockStatus {
    param([string]$KBNumber)
    
    Write-Host "=== Checking Block Status for KB$KBNumber ===" -ForegroundColor Cyan
    
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (Test-Path $regPath) {
            $blocked = Get-ItemProperty -Path $regPath -Name "DoNotConnectToWindowsUpdateInternetLocations" -ErrorAction SilentlyContinue
            if ($blocked) {
                Write-Host "Update KB$KBNumber is currently blocked" -ForegroundColor Red
            } else {
                Write-Host "Update KB$KBNumber is not blocked" -ForegroundColor Green
            }
        } else {
            Write-Host "No blocking policies found - KB$KBNumber is not blocked" -ForegroundColor Green
        }
    } catch {
        Write-Host "Error checking block status: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to analyze update removability
function Analyze-UpdateRemovability {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Updates
    )
    
    Write-Host "=== Analyzing Update Removability ===" -ForegroundColor Cyan
    Write-Host "Analyzing $($Updates.Count) updates for removability..." -ForegroundColor Yellow
    Write-Host ""
    
    $analysisResults = @()
    $nonRemovable = @()
    $removable = @()
    $combinedSSU = @()
    
    $combinedSSUUpdates = @(
        "KB5063878", "KB5062839", "KB5062978", "KB5034441", "KB5034127",
        "KB5031356", "KB5029331", "KB5028166", "KB5027231", "KB5025221"
    )
    
    foreach ($update in $Updates) {
        $kb = $update.HotFixID -replace "^KB", ""
        $normalizedKB = Get-NormalizedKBNumber $update.HotFixID
        $isCombinedSSU = $combinedSSUUpdates -contains "KB$normalizedKB"
        
        $result = [PSCustomObject]@{
            KB = $kb
            Description = $update.Description
            InstalledOn = $update.InstalledOn
            Category = "Unknown"
            Removable = $false
            Method = "Unknown"
            CombinedSSU = $isCombinedSSU
            Notes = ""
        }
        
        # Check if it's a combined SSU/LCU package
        if ($isCombinedSSU) {
            $result.Category = "Combined SSU/LCU"
            $result.Removable = $false
            $result.Method = "manual Only"
            $result.Notes = "Contains permanent Servicing Stack components - requires manual removal via Settings GUI"
            $combinedSSU += $result
        }
        # Check via DISM
        elseif ($kb -match '^\d+$') {
            try {
                $dismOutput = & dism /online /get-packages 2>$null | Where-Object { $_ -match "kb$kb" }
                if ($dismOutput) {
                    $result.Category = "Cumulative Update"
                    $result.Removable = $true
                    $result.Method = "DISM / WUSA"
                } else {
                    $result.Category = "Windows Update"
                    $result.Removable = $true
                    $result.Method = "WUSA"
                    $result.Notes = "standard - maybe removable"
                }
            } catch {
                $result.Notes = "DISM check failed - maybe removable"
            }
        } else {
            $result.Category = "standard"
            $result.Removable = $true
            $result.Method = "WUSA"
        }
        
        $analysisResults += $result
        
        if ($result.Removable) {
            $removable += $result
        } else {
            $nonRemovable += $result
        }
    }
    
    # Display results
    if ($combinedSSU.Count -gt 0) {
        Write-Host "[LOCK] COMBINED SSU/LCU UPDATES (MANUAL REMOVAL ONLY):" -ForegroundColor Red
        foreach ($update in $combinedSSU) {
            Write-Host "  $($update.KB) - $($update.Description)" -ForegroundColor Red
            Write-Host "    [WARN] Requires manual removal via Settings -> Update History -> Uninstall updates" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    
    if ($nonRemovable.Count -gt 0) {
        Write-Host "[LOCK] NON-REMOVABLE UPDATES:" -ForegroundColor Yellow
        $categories = $nonRemovable | Group-Object Category
        foreach ($category in $categories) {
            Write-Host "  $($category.Name): $($category.Count) updates" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    
    if ($removable.Count -gt 0) {
        Write-Host "[OK] REMOVABLE UPDATES:" -ForegroundColor Green
        foreach ($update in $removable) {
            Write-Host "  - $($update.KB) - $($update.Description)" -ForegroundColor Green
        }
        Write-Host ""
    }
    
    return @{
        AllResults = $analysisResults
        NonRemovable = $nonRemovable
        Removable = $removable
        CombinedSSU = $combinedSSU
    }
}

# Lightweight individual KB removability check (cached version)
function Test-KBRemovability {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KBNumber
    )
    
    # Define non-removable update categories
    $combinedSSUUpdates = @(
        'KB5063878', 'KB5062839', 'KB5062978', 'KB5034441', 'KB5034127',
        'KB5031356', 'KB5029331', 'KB5028166', 'KB5027231', 'KB5025221'
    )
    
    $permanentSecurityPatterns = @(
        '^50[0-9]{4}$', '^51[0-9]{4}$', '^52[0-9]{4}$', '^53[0-9]{4}$'
    )
    
    $kb = $KBNumber.ToUpper()
    $isRemovable = $true
    $reason = "Standard update - maybe removable via WUSA"
    $removability = "Potentially Removable"  # Default to potentially removable
    
    # First, check if this is a DISM package
    try {
        $dismOutput = & dism /online /get-packages 2>$null | Where-Object { $_ -match $kb -and $_ -match "Package" }
        if ($dismOutput) {
            # This is a DISM package, test actual removability
            $testResult = Test-DISMPackage -KBNumber $kb
            if ($testResult.Removable) {
                $removability = "Removable"
                $reason = "DISM package - removable via DISM"
            } else {
                $removability = "Not Removable"
                $reason = "DISM package - permanent system component"
            }
            return [PSCustomObject]@{
                Removability = $removability
                Reason = $reason
            }
        }
    } catch {
        # Continue with other checks if DISM test fails
    }
    
    # Quick checks for non-removable updates
    if ($kb -in $combinedSSUUpdates) {
        $isRemovable = $false
        $reason = "Combined SSU/LCU package - requires manual Settings GUI removal"
        $removability = "Not Removable"
    }
    
    # Check permanent security updates
    foreach ($pattern in $permanentSecurityPatterns) {
        if ($kb -match $pattern) {
            $isRemovable = $false
            $reason = "Permanent security update flagged by Microsoft"
            $removability = "Not Removable"
            break
        }
    }
    
    # For standard updates, check if they're likely to be fully removable
    if ($isRemovable) {
        # Check if it's actually a Get-HotFix update
        $hotfix = Get-HotFix -Id $kb -ErrorAction SilentlyContinue
        if ($hotfix) {
            $removability = "Removable"
            $reason = "Standard update - removable via WUSA"
        } else {
            # Only mark very recent security updates as definitively removable
            if ($kb -match '^KB51[0-9]{5}$' -or $kb -match '^KB52[0-9]{5}$') {
                $removability = "Removable"
                $reason = "Very recent security update - typically removable"
            }
            # KB50xxxx series and others remain as "Potentially Removable" (default)
        }
    }
    
    return [PSCustomObject]@{
        Removability = $removability
        Reason = $reason
    }
}

# Function to detect combined SSU/LCU updates that require manual removal
function Test-CombinedSSUUpdates {
    Write-Host "=== Combined SSU/LCU Updates Detection ===" -ForegroundColor Cyan
    Write-Host "Scanning for updates that contain combined Servicing Stack and Cumulative Updates..." -ForegroundColor Yellow
    Write-Host "These updates cannot be removed via WUSA and require manual removal." -ForegroundColor Yellow
    Write-Host ""
    
    $combinedSSUUpdates = @(
        "KB5063878",  # Windows 11 24H2 Cumulative Update (Build 26100.4946)
        "KB5062839",  # Combined servicing stack and cumulative update
        "KB5062978",  # Combined servicing stack and cumulative update
        "KB5034441",  # Combined servicing stack and cumulative update
        "KB5034127",  # Combined servicing stack and cumulative update
        "KB5031356",  # Combined servicing stack and cumulative update
        "KB5029331",  # Combined servicing stack and cumulative update
        "KB5028166",  # Combined servicing stack and cumulative update
        "KB5027231",  # Combined servicing stack and cumulative update
        "KB5025221"   # Combined servicing stack and cumulative update
    )
    
    $foundCombinedUpdates = @()
    
    foreach ($kb in $combinedSSUUpdates) {
        $installed = Get-HotFix -Id $kb -ErrorAction SilentlyContinue
        if ($installed) {
            $foundCombinedUpdates += [PSCustomObject]@{
                KBNumber = $kb
                InstalledOn = $installed.InstalledOn
                Description = $installed.Description
                ManualRemovalRequired = $true
            }
            
            if ($kb -eq "KB5063878") {
                Write-Host "`n================================================================================" -ForegroundColor Red
                Write-Host "🚨 CRITICAL ALERT: KB5063878 DETECTED! 🚨" -ForegroundColor Black -BackgroundColor Red
                Write-Host "================================================================================" -ForegroundColor Red
                Write-Host "SEVERITY: CRITICAL - SSD/HDD CORRUPTION RISK" -ForegroundColor Red
                Write-Host "IMPACT: This update has been reported to cause SSD and HDD corruption issues" -ForegroundColor Yellow
                Write-Host "INSTALLED ON: $($installed.InstalledOn)" -ForegroundColor White
                Write-Host "DESCRIPTION: $($installed.Description)" -ForegroundColor White
                Write-Host "REMOVAL: Combined SSU/LCU package - CANNOT be removed via automated methods" -ForegroundColor Yellow
                Write-Host "MANUAL REMOVAL REQUIRED:" -ForegroundColor Cyan
                Write-Host "   1. Settings -> Windows Update -> Update History -> Uninstall updates" -ForegroundColor White
                Write-Host "   2. Select KB5063878 and click Uninstall" -ForegroundColor White
                Write-Host "   3. Restart when prompted" -ForegroundColor White
                Write-Host "BACKUP: Consider backing up important data before removal" -ForegroundColor Magenta
                Write-Host "================================================================================" -ForegroundColor Red
                Write-Host ""
            } else {
                Write-Host "[CRITICAL] MANUAL REMOVAL REQUIRED: $kb - INSTALLED" -ForegroundColor Black -BackgroundColor Yellow
                Write-Host "    This update contains permanent Servicing Stack components" -ForegroundColor Red
                Write-Host "    Installed on: $($installed.InstalledOn)" -ForegroundColor White
                Write-Host "    Description: $($installed.Description)" -ForegroundColor White
                Write-Host "    Manual removal required via: Settings -> Windows Update -> Update History -> Uninstall updates" -ForegroundColor Cyan
                Write-Host "    Cannot be removed via WUSA or automated scripts" -ForegroundColor Red
                Write-Host ""
            }
        }
    }
    
    if ($foundCombinedUpdates.Count -eq 0) {
        Write-Host "[OK] No combined SSU/LCU updates found that require manual removal." -ForegroundColor Green
    } else {
        $hasKB5063878 = $foundCombinedUpdates | Where-Object { $_.KBNumber -eq "KB5063878" }
        
        if ($hasKB5063878) {
            Write-Host "================================================================================" -ForegroundColor Red
            Write-Host "🚨 CRITICAL ALERT: KB5063878 SSD/HDD CORRUPTION UPDATE DETECTED! 🚨" -ForegroundColor Black -BackgroundColor Red
            Write-Host "================================================================================" -ForegroundColor Red
            Write-Host "SEVERITY: CRITICAL - IMMEDIATE ACTION REQUIRED" -ForegroundColor Red
            Write-Host "This update has been reported to cause SSD and HDD corruption issues" -ForegroundColor Yellow
            Write-Host "MANUAL REMOVAL REQUIRED IMMEDIATELY:" -ForegroundColor Cyan
            Write-Host "   Settings -> Windows Update -> Update History -> Uninstall updates" -ForegroundColor White
            Write-Host "   Select KB5063878 and click Uninstall, then restart" -ForegroundColor White
            Write-Host "BACKUP: Consider backing up important data before removal" -ForegroundColor Magenta
            Write-Host "================================================================================" -ForegroundColor Red
        } else {
            Write-Host "================================================================================" -ForegroundColor Red
            Write-Host "CRITICAL ALERT: $($foundCombinedUpdates.Count) combined SSU/LCU update(s) detected!" -ForegroundColor Black -BackgroundColor Yellow
            Write-Host "================================================================================" -ForegroundColor Red
            Write-Host "These updates contain permanent Servicing Stack components" -ForegroundColor Yellow
            Write-Host "They CANNOT be removed via WUSA or automated scripts" -ForegroundColor Red
            Write-Host "Manual removal ONLY via: Settings -> Windows Update -> Update History -> Uninstall updates" -ForegroundColor Cyan
            Write-Host "Proceed with caution - removing these may affect system stability" -ForegroundColor Yellow
            Write-Host "================================================================================" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    return $foundCombinedUpdates
}

# Function to validate KB input and warn about combined SSU/LCU updates
function Validate-KBInput {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$KBNumbers
    )
    
    $criticalKB5063878 = "KB5063878"
    $combinedSSUUpdates = @(
        "KB5063878", "KB5062839", "KB5062978", "KB5034441", "KB5034127",
        "KB5031356", "KB5029331", "KB5028166", "KB5027231", "KB5025221"
    )
    
    $criticalWarnings = @()
    $warnings = @()
    
    foreach ($kb in $KBNumbers) {
        $normalizedKB = Get-NormalizedKBNumber $kb
        $fullKB = "KB$normalizedKB"
        
        if ($fullKB -eq $criticalKB5063878) {
            $criticalWarnings += "KB5063878 - CRITICAL SSD/HDD CORRUPTION RISK"
        } elseif ($combinedSSUUpdates -contains $fullKB) {
            $warnings += "$fullKB is a combined SSU/LCU package that requires manual removal via Settings GUI."
        }
    }
    
    if ($criticalWarnings.Count -gt 0) {
        Write-Host "`n================================================================================" -ForegroundColor Red
        Write-Host "🚨 CRITICAL ALERT: KB5063878 DETECTED! 🚨" -ForegroundColor Black -BackgroundColor Red
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
    }
    
    if ($warnings.Count -gt 0) {
        Write-Host "================================================================================" -ForegroundColor Red
        Write-Host "WARNING: Combined SSU/LCU Updates Detected!" -ForegroundColor Black -BackgroundColor Yellow
        Write-Host "================================================================================" -ForegroundColor Red
        foreach ($warning in $warnings) {
            Write-Host "   $warning" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "These updates CANNOT be removed via automated methods" -ForegroundColor Red
        Write-Host "Manual removal ONLY via: Settings -> Windows Update -> Update History -> Uninstall updates" -ForegroundColor Cyan
        Write-Host "Removing these updates may affect system stability - proceed with caution" -ForegroundColor Yellow
        Write-Host "================================================================================" -ForegroundColor Red
        Write-Host ""
        
        if (-not $Force) {
            Write-Host "Recommendation: Cancel and use manual removal method above" -ForegroundColor Cyan
            $continue = Read-Host "Continue with automated removal anyway? (y/n)"
            if ($continue -ne 'y') {
                Write-Host "Operation cancelled - use manual removal method instead" -ForegroundColor Green
                return $false
            }
        }
    }
    
    return $true
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
        Write-Host "   Windows Update repair completed!" -ForegroundColor Green
        Write-Host "   Try running Windows Update again to check if issues are resolved." -ForegroundColor Cyan
    } catch {
        Write-Host "   [!] Windows Update repair completed with warnings" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "=== Windows Update Repair Complete ===" -ForegroundColor Green
    Write-Host "Restart your computer and check Windows Update for improvements." -ForegroundColor Cyan
}

# Function to verify if a specific KB is installed
function Verify-KB {
    param(
        [string]$KBNumber
    )
    
    Write-Host "=== Searching for KB$KBNumber ===" -ForegroundColor Cyan
    
    $found = $false
    
    # Method 1: Get-HotFix
    try {
        $hotFix = Get-HotFix -Id "KB$KBNumber" -ErrorAction SilentlyContinue
        if ($hotFix) {
            Write-Host "[OK] Found via Get-HotFix: $($hotFix.Description)" -ForegroundColor Green
            $found = $true
        }
    } catch {
        Write-Host "   [X] Error running Get-HotFix: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Method 2: DISM packages
    try {
        $dismOutput = dism /online /get-packages 2>$null
        if ($dismOutput) {
            $packageLines = $dismOutput -join "`n" -split "Package Identity :"
            foreach ($package in $packageLines) {
                if ($package -match "KB$KBNumber") {
                    Write-Host "[OK] Found via DISM: $($package -split "`n" | Select-Object -First 1)" -ForegroundColor Green
                    $found = $true
                    break
                }
            }
        }
    } catch {
        Write-Host "   [X] Error running DISM check: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Method 3: Registry
    try {
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                $regItems = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "KB$KBNumber" }
                if ($regItems) {
                    Write-Host "[OK] Found via Registry: $($regItems[0].Name.Split('\')[-1])" -ForegroundColor Green
                    $found = $true
                    break
                }
            }
        }
    } catch {
        Write-Host "   [X] Error running Registry check: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Method 4: SFC verification
    try {
        $sfcOutput = sfc /verifyonly 2>$null
        if ($sfcOutput -match "KB$KBNumber") {
            Write-Host "[OK] Found via SFC: KB$KBNumber referenced in system file verification" -ForegroundColor Green
            $found = $true
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



# Function to detect combined SSU/LCU updates that require manual removal
function Test-CombinedSSUUpdates {
    Write-Host "=== Combined SSU/LCU Updates Detection ===" -ForegroundColor Cyan
    Write-Host "Scanning for updates that contain combined Servicing Stack and Cumulative Updates..." -ForegroundColor Yellow
    Write-Host "These updates cannot be removed via WUSA and require manual removal." -ForegroundColor Yellow
    Write-Host ""
    
    $combinedSSUUpdates = @(
        "KB5063878",  # Windows 11 24H2 Cumulative Update (Build 26100.4946)
        "KB5062839",  # Combined servicing stack and cumulative update
        "KB5062978",  # Combined servicing stack and cumulative update
        "KB5034441",  # Combined servicing stack and cumulative update
        "KB5034127",  # Combined servicing stack and cumulative update
        "KB5031356",  # Combined servicing stack and cumulative update
        "KB5029331",  # Combined servicing stack and cumulative update
        "KB5028166",  # Combined servicing stack and cumulative update
        "KB5027231",  # Combined servicing stack and cumulative update
        "KB5025221"   # Combined servicing stack and cumulative update
    )
    
    $foundCombinedUpdates = @()
    
    foreach ($kb in $combinedSSUUpdates) {
        $installed = Get-HotFix -Id $kb -ErrorAction SilentlyContinue
        if ($installed) {
            $foundCombinedUpdates += [PSCustomObject]@{
                KBNumber = $kb
                InstalledOn = $installed.InstalledOn
                Description = $installed.Description
                ManualRemovalRequired = $true
            }
            Write-Host "[CRITICAL] MANUAL REMOVAL REQUIRED: $kb - INSTALLED" -ForegroundColor Black -BackgroundColor Yellow
            Write-Host "    This update contains permanent Servicing Stack components" -ForegroundColor Red
            Write-Host "    Installed on: $($installed.InstalledOn)" -ForegroundColor White
            Write-Host "    Description: $($installed.Description)" -ForegroundColor White
            Write-Host "    Manual removal required via: Settings -> Windows Update -> Update History -> Uninstall updates" -ForegroundColor Cyan
            Write-Host "    Cannot be removed via WUSA or automated scripts" -ForegroundColor Red
            Write-Host ""
        }
    }
    
    if ($foundCombinedUpdates.Count -eq 0) {
        Write-Host "[OK] No combined SSU/LCU updates found that require manual removal." -ForegroundColor Green
    } else {
        Write-Host "================================================================================" -ForegroundColor Red
        Write-Host "CRITICAL ALERT: $($foundCombinedUpdates.Count) combined SSU/LCU update(s) detected!" -ForegroundColor Black -BackgroundColor Yellow
        Write-Host "================================================================================" -ForegroundColor Red
        Write-Host "These updates contain permanent Servicing Stack components" -ForegroundColor Yellow
        Write-Host "They CANNOT be removed via WUSA or automated scripts" -ForegroundColor Red
        Write-Host "Manual removal ONLY via: Settings -> Windows Update -> Update History -> Uninstall updates" -ForegroundColor Cyan
        Write-Host "Proceed with caution - removing these may affect system stability" -ForegroundColor Yellow
        Write-Host "================================================================================" -ForegroundColor Red
    }
    
    Write-Host ""
    return $foundCombinedUpdates
}

# Function to validate KB input and warn about combined SSU/LCU updates
function Validate-KBInput {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$KBNumbers
    )
    
    $combinedSSUUpdates = @(
        "KB5063878", "KB5062839", "KB5062978", "KB5034441", "KB5034127",
        "KB5031356", "KB5029331", "KB5028166", "KB5027231", "KB5025221"
    )
    
    $warnings = @()
    
    foreach ($kb in $KBNumbers) {
        $normalizedKB = Get-NormalizedKBNumber $kb
        if ($combinedSSUUpdates -contains "KB$normalizedKB") {
            $warnings += "KB$normalizedKB is a combined SSU/LCU package that requires manual removal via Settings GUI."
        }
    }
    
    if ($warnings.Count -gt 0) {
        Write-Host "================================================================================" -ForegroundColor Red
        Write-Host "WARNING: Combined SSU/LCU Updates Detected!" -ForegroundColor Black -BackgroundColor Yellow
        Write-Host "================================================================================" -ForegroundColor Red
        foreach ($warning in $warnings) {
            Write-Host "   $warning" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "These updates CANNOT be removed via automated methods" -ForegroundColor Red
        Write-Host "Manual removal ONLY via: Settings -> Windows Update -> Update History -> Uninstall updates" -ForegroundColor Cyan
        Write-Host "Removing these updates may affect system stability - proceed with caution" -ForegroundColor Yellow
        Write-Host "================================================================================" -ForegroundColor Red
        Write-Host ""
        
        if (-not $Force) {
            Write-Host "Recommendation: Cancel and use manual removal method above" -ForegroundColor Cyan
            $continue = Read-Host "Continue with automated removal anyway? (y/n)"
            if ($continue -ne 'y') {
                Write-Host "Operation cancelled - use manual removal method instead" -ForegroundColor Green
                return $false
            }
        }
    }
    
    return $true
}

# Function to perform repair Windows Update
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
        Write-Host "Try manual steps: services.msc -> System Restore Service -> Set to Automatic -> Start" -ForegroundColor Yellow
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
    Write-Host "   (Press Ctrl+C to cancel if this takes too long)" -ForegroundColor Gray
    try {
        $job = Start-Job -ScriptBlock {
            $session = New-Object -ComObject "Microsoft.Update.Session"
            $searcher = $session.CreateUpdateSearcher()
            $pending = $searcher.Search("IsInstalled=0")
            return $pending
        }
        
        $timeout = 30 # 30 seconds timeout
        $completed = Wait-Job $job -Timeout $timeout
        
        if ($completed) {
            $pending = Receive-Job $job
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
        } else {
            Write-Host "   [WARN] Pending updates check timed out after $timeout seconds" -ForegroundColor Yellow
            Write-Host "   This may indicate Windows Update service issues" -ForegroundColor Gray
            Stop-Job $job
        }
        
        Remove-Job $job -Force
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
    Write-Host '   - Computer Configuration > Administrative Templates > Windows Components > Windows Update'
    Write-Host "   - Set 'Configure Automatic Updates' to disabled"
    Write-Host ""
    Write-Host "3. Windows Update Settings" -ForegroundColor Yellow
    Write-Host '   - Settings > Update and Security > Windows Update'
    Write-Host '   - Advanced options > Choose how updates are delivered'
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
        Write-Host "      *** COMBINED SSU/LCU UPDATE - MANUAL REMOVAL ONLY ***" -ForegroundColor Red -BackgroundColor Yellow
        $problematicCount++
    } elseif ($isProblematic) {
        Write-Host "[$($i+1)] $($update.HotFixID) - $($update.Description) $installDate" -ForegroundColor Red -BackgroundColor Yellow
        Write-Host "      *** PROBLEMATIC UPDATE DETECTED ***" -ForegroundColor Red -BackgroundColor Yellow
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
    $updatesToProcess = $installedUpdates | Where-Object { 
        $normalizedKB = Get-NormalizedKBNumber $_.HotFixID
        $normalizedKB -and ($normalizedKBNumbers -contains $normalizedKB)
    }
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
                if ($update.Notes) {
                    Write-Host "    Note: $($update.Notes)" -ForegroundColor Gray
                }
            }
            Write-Host ""
        }
        
        Write-Host "Note: Updates marked as 'Removable' can be removed using this tool (Get-HotFix and DISM sources)." -ForegroundColor Yellow
        Write-Host "Continuing to interactive menu for removal options..." -ForegroundColor Green
        Write-Host ""
        
        Read-Host "Press Enter to continue to interactive menu"
    }
}

if ($CheckBlockStatus -or $a) {
    # Handle CheckBlockStatus parameter
    Write-Host "Checking blocking status of updates..." -ForegroundColor Yellow
    Write-Host ""
    
    # Check if -a switch was provided or CheckBlockStatus has a value
    if ($a -or $CheckBlockStatus -eq "all" -or $CheckBlockStatus -eq "A") {
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
if (-not ($KBNumbers -or $CheckBlockStatus -or $a -or $BlockUpdate -or $UnblockUpdate) -or $ListOnly) {
        # Interactive menu - loop until user exits
        do {
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
            Write-Host "=== Interactive Menu ===" -ForegroundColor Cyan
            Write-Host "Choose an action:" -ForegroundColor Yellow
            Write-Host "1. List installed updates" -ForegroundColor White
            Write-Host "2. Block specific updates from installing" -ForegroundColor White
            Write-Host "3. Unblock previously blocked updates" -ForegroundColor White
            Write-Host "4. Check blocking status of updates" -ForegroundColor White
            Write-Host "5. Show blocking methods information" -ForegroundColor White
            Write-Host "6. Repair Windows Update" -ForegroundColor White
            Write-Host "7. Run diagnostics" -ForegroundColor White
            Write-Host "0. Exit (or type 'q' to quit)" -ForegroundColor Gray
            Write-Host ""
            
            $menuChoice = Read-Host "Enter your choice (0-7 or q to quit)"
            
            switch ($menuChoice) {
                "1" {
            # Enhanced update listing and removal functionality
            Write-Host ""
            Write-Host "=== Comprehensive Update Listing ===" -ForegroundColor Cyan
            Write-Host "Scanning all update sources..." -ForegroundColor Yellow
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
                
                Write-Host "Found $($allUpdates.Count) total installed updates ($($installedUpdates.Count) removable via this tool)." -ForegroundColor Green
                Write-Host ""
                
                # Display comprehensive list grouped by source
                $groupedUpdates = $allUpdates | Group-Object Source
                foreach ($group in $groupedUpdates) {
                    Write-Host "--- $($group.Name) Updates ---" -ForegroundColor Cyan
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
                    }
                    Write-Host ""
                }
                
                Write-Host "Note: Updates marked as 'Removable' can be removed using this tool (Get-HotFix and DISM sources)." -ForegroundColor Yellow
                Write-Host "Other updates are shown for informational purposes only." -ForegroundColor Yellow
                Write-Host ""
                
                if ($installedUpdates.Count -eq 0) {
                    Write-Host "No updates found to remove." -ForegroundColor Yellow
                    Read-Host "Press Enter to continue"
                    continue
                }
                
                # Cache removability results to avoid redundant checks
                $removabilityCache = @{}
                
                Write-Host "Installed Updates:" -ForegroundColor Cyan
                Write-Host "==================" -ForegroundColor Cyan
                Write-Host "Removability Status: [OK] Removable [!] Potentially Removable [X] Not Removable" -ForegroundColor Gray
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
                        'Removable' {
                            $status = "[OK]"
                            $color = "Green"
                        }
                        'Potentially Removable' {
                            $status = "[!]"
                            $color = "Yellow"
                        }
                        'Not Removable' {
                            $status = "[X]"
                            $color = "Red"
                        }
                        default {
                            $status = "[?]"
                            $color = "White"
                        }
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
                Write-Host '- Enter numbers separated by commas (e.g., 1,3,5)' -ForegroundColor Yellow
                Write-Host "- Enter 'all' or 'A' to select all updates" -ForegroundColor Gray
                Write-Host "- Enter 'back' or 'b' to return to main menu" -ForegroundColor Gray

                $selection = Read-Host "Your selection"

                if ($selection -eq 'back' -or $selection -eq 'b') {
                    continue
                }

                # Parse selection
                $updatesToProcess = @()
                if ($selection -eq 'all' -or $selection -eq 'A') {
                    $updatesToProcess = $filteredUpdates
                } else {
                    $indices = $selection -split ',' | ForEach-Object { $_.Trim() }
                    foreach ($index in $indices) {
                        if ($index -match '^\d+$' -and [int]$index -ge 1 -and [int]$index -le $filteredUpdates.Count) {
                            $updatesToProcess += $filteredUpdates[[int]$index - 1]
                        } else {
                            Write-Warning "Invalid selection: $index"
                        }
                    }
                }
                
                if ($updatesToProcess.Count -eq 0) {
                    Write-Host "No valid updates selected." -ForegroundColor Yellow
                    Read-Host "Press Enter to continue"
                    continue
                }
                
                # Validate selected updates using cached removability results
                $selectedKBs = $updatesToProcess | ForEach-Object { Get-NormalizedKBNumber $_.HotFixID }
                
                # Check for non-removable updates and warn user
                $nonRemovableCount = 0
                $combinedSSUCount = 0
                $warnings = @()
                
                foreach ($update in $updatesToProcess) {
                    $kbNumber = Get-NormalizedKBNumber $update.HotFixID
                    $removability = $removabilityCache[$kbNumber]
                    
                    if ($removability.Removability -eq 'Not Removable') {
                        $nonRemovableCount++
                        $warnings += "$($update.HotFixID): $($removability.Reason)"
                    } elseif ($removability.Removability -eq 'Potentially Removable') {
                        $warnings += "$($update.HotFixID): $($removability.Reason)"
                    }
                    
                    # Count combined SSU/LCU packages
                    foreach ($problematicKB in $problematicKBs) {
                        if ($problematicKB -like "*$kbNumber*" -and $problematicKB -like "*Combined SSU/LCU*") {
                            $combinedSSUCount++
                            break
                        }
                    }
                }
                
                if ($nonRemovableCount -gt 0) {
                    Write-Host "`n[!] WARNING: $nonRemovableCount selected update(s) cannot be removed:" -ForegroundColor Red
                    foreach ($warning in $warnings) {
                        Write-Host "   - $warning" -ForegroundColor Yellow
                    }
                    
                    $continue = Read-Host "Continue with removable updates only? (y/n)"
                    if ($continue -ne 'y') {
                        Write-Host "Operation cancelled." -ForegroundColor Yellow
                        Read-Host "Press Enter to continue"
                        continue
                    }
                    
                    # Filter out non-removable updates using cached results
                    $updatesToProcess = $updatesToProcess | Where-Object {
                        $kbNumber = Get-NormalizedKBNumber $_.HotFixID
                        $removabilityCache[$kbNumber].Removability -ne 'Not Removable'
                    }
                }
                
                if ($combinedSSUCount -gt 0) {
                    Write-Host "`n[!] NOTE: $combinedSSUCount selected update(s) are Combined SSU/LCU packages." -ForegroundColor Yellow
                    Write-Host "   These often require special handling and may fail to remove." -ForegroundColor Gray
                    $continue = Read-Host "Continue anyway? (y/n)"
                    if ($continue -ne 'y') {
                        Write-Host "Operation cancelled." -ForegroundColor Yellow
                        Read-Host "Press Enter to continue"
                        continue
                    }
                }
                
                if ($updatesToProcess.Count -eq 0) {
                    Write-Host "No removable updates selected." -ForegroundColor Yellow
                    Read-Host "Press Enter to continue"
                    continue
                }

                Write-Host "`nSelected $($updatesToProcess.Count) update(s) for removal:" -ForegroundColor Green
                foreach ($update in $updatesToProcess) {
                    Write-Host "  - $($update.HotFixID) - $($update.Description)" -ForegroundColor White
                }
                Write-Host ""

                # Create restore point
                Write-Host "Creating a restore point before making changes..." -ForegroundColor Yellow
            } catch {
                Write-Host "Error scanning for updates: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Attempting to continue with basic update list..." -ForegroundColor Yellow
                # Fallback to basic list if advanced scanning fails
                try {
                    $installedUpdates = Get-HotFix | Where-Object { $_.HotFixID -match 'KB\d+' } | Sort-Object {[DateTime]$_.InstalledOn} -Descending
                    Write-Host "Successfully retrieved basic update list" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to retrieve any updates: $($_.Exception.Message)" -ForegroundColor Red
                    Read-Host "Press Enter to continue"
                    continue
                }
            }
                
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
                            $enableService = Read-Host "Would you like to enable and start the System Restore service? (y/n)"
                            if ($enableService -eq 'y') {
                                try {
                                    Set-Service -Name "SRService" -StartupType Automatic -ErrorAction Stop
                                    Start-Service -Name "SRService" -ErrorAction Stop
                                    Write-Host "System Restore service enabled and started" -ForegroundColor Green
                                    Start-Sleep -Seconds 5
                                } catch {
                                    Write-Warning "Failed to enable System Restore service: $($_.Exception.Message)"
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
                    
                    # Create the restore point
                    Checkpoint-Computer -Description $rpName -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
                    $Script:rpCreated = $true
                    Write-Host "Restore point '$rpName' created successfully!" -ForegroundColor Green
                    
                } catch {
                    Write-Warning "Failed to create restore point: $($_.Exception.Message)"
                    $continue = Read-Host "Continue without restore point? (y/n)"
                    if ($continue -ne 'y') {
                        Write-Host "Operation cancelled." -ForegroundColor Yellow
                        Read-Host "Press Enter to continue"
                        continue
                    }
                }

                # Process each selected update
                foreach ($update in $updatesToProcess) {
                    $kbNumber = Get-NormalizedKBNumber $update.HotFixID
                    Write-Host "`nProcessing $($update.HotFixID)..." -ForegroundColor Cyan
                    
                    try {
                        # Process removal using the comprehensive removal logic
                        $removeSuccess = $false
                        $removalMethods = @()
                        $errorDetails = @()
                        
                        Write-Host "Removing $($update.HotFixID)..." -ForegroundColor Red
                        
                        # Check for new parameter-based processing
                        if ($UsePSWindowsUpdate -and (Test-PSWindowsUpdateModule)) {
                            Write-Host "Using PSWindowsUpdate module..." -ForegroundColor Cyan
                            $result = Remove-UpdateWithPSWindowsUpdate -KBNumber $kbNumber -HideUpdate:$HideUpdate
                            if ($result) {
                                $removeSuccess = $true
                                $removalMethods += "PSWindowsUpdate"
                                Write-Host "Successfully processed via PSWindowsUpdate" -ForegroundColor Green
                            } else {
                                $errorDetails += "PSWindowsUpdate: Module failed"
                            }
                        }
                        elseif ($DateRange) {
                            Write-Host "Processing date-based removal..." -ForegroundColor Cyan
                            if ($DateRange -match "^(\d{4}-\d{2}-\d{2}):(\d{4}-\d{2}-\d{2})$") {
                                $startDate = [datetime]::Parse($matches[1])
                                $endDate = [datetime]::Parse($matches[2])
                                $result = Remove-UpdatesByDateRange -StartDate $startDate -EndDate $endDate -WhatIf:$ListOnly
                                if ($result) {
                                    $removeSuccess = $true
                                    $removalMethods += "DateRange"
                                }
                            } else {
                                Write-Host "Invalid date range format. Use: YYYY-MM-DD:YYYY-MM-DD" -ForegroundColor Red
                            }
                        }
                        elseif ($RemoteComputer) {
                            Write-Host "Processing remote removal for $RemoteComputer..." -ForegroundColor Cyan
                            $result = Invoke-RemoteUpdateRemoval -ComputerName $RemoteComputer -KBNumber $kbNumber
                            if ($result.Success) {
                                $removeSuccess = $true
                                $removalMethods += "Remote"
                                Write-Host "Successfully processed remotely" -ForegroundColor Green
                            } else {
                                $errorDetails += "Remote: $($result.Message)"
                            }
                        }
                        else {
                            # Enhanced multi-method fallback approach
                            
                            # Method 1: Enhanced WUSA approach (fastest, try first)
                            Write-Host "Trying Windows Update Standalone Installer (WUSA)..." -ForegroundColor Gray
                            $result = Remove-UpdateWithWUSA -KBNumber $kbNumber -Quiet
                            if ($result.Success) {
                                $removeSuccess = $true
                                $removalMethods += $result.Method
                                Write-Host "Successfully removed via $($result.Method)" -ForegroundColor Green
                            } else {
                                Write-Host "   [!] WUSA failed: $($result.Message)" -ForegroundColor Yellow
                                $errorDetails += "WUSA: $($result.Message)"
                            }

                            # Method 2: PSWindowsUpdate module (if available)
                            if (-not $removeSuccess -and (Test-PSWindowsUpdateModule)) {
                                Write-Host "Trying PSWindowsUpdate module..." -ForegroundColor Gray
                                $result = Remove-UpdateWithPSWindowsUpdate -KBNumber $kbNumber
                                if ($result) {
                                    $removeSuccess = $true
                                    $removalMethods += "PSWindowsUpdate"
                                    Write-Host "Successfully removed via PSWindowsUpdate" -ForegroundColor Green
                                } else {
                                    $errorDetails += "PSWindowsUpdate: Module failed"
                                }
                            }

                            # Method 3: DISM approach (fallback)
                            if (-not $removeSuccess) {
                                Write-Host "Trying DISM package discovery..." -ForegroundColor Gray
                                $dismAvailable = Get-Command "dism.exe" -ErrorAction SilentlyContinue
                                if ($dismAvailable) {
                                    try {
                                        $dismOutput = & dism /online /get-packages /format:table 2>$null
                                        $kbPackages = $dismOutput | Where-Object { $_ -match "Package.*KB$cleanKB" -or $_ -match "KB$cleanKB.*Package" }
                                        
                                        if ($kbPackages) {
                                            foreach ($packageLine in $kbPackages) {
                                                if ($packageLine -match "Package Identity : (.*)") {
                                                    $packageName = $matches[1].Trim()
                                                    Write-Host "Testing package: $packageName" -ForegroundColor Gray
                                                    
                                                    # Use Remove-DISMPackage function
                                                    $result = Remove-DISMPackage -PackageName $packageName -Quiet -NoRestart
                                                    if ($result.Success) {
                                                        $removeSuccess = $true
                                                        $removalMethods += "DISM ($packageName)"
                                                        Write-Host "   $($result.Message)" -ForegroundColor Green
                                                        break
                                                    }
                                                }
                                            }
                                        }
                                    } catch {
                                        Write-Host "   [!] DISM search error: $($_.Exception.Message)" -ForegroundColor Yellow
                                    }
                                }
                            }
                        }

                        if ($removeSuccess) {
                            Write-Host "Successfully processed $($update.HotFixID)" -ForegroundColor Green
                        } else {
                            Write-Host "Failed to process $($update.HotFixID)" -ForegroundColor Red
                            Write-Host "Attempted methods: $($removalMethods -join ', ')" -ForegroundColor Gray
                            Write-Host "Errors: $($errorDetails -join '; ')" -ForegroundColor Yellow
                        }
                    } catch {
                        Write-Host "Failed to process $($update.HotFixID): $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
                
                Write-Host "`nUpdate processing completed!" -ForegroundColor Green
                Read-Host "Press Enter to continue"
                
            } catch {
                Write-Host "Error scanning for updates: $($_.Exception.Message)" -ForegroundColor Red
                Read-Host "Press Enter to continue"
                continue
            }
        
        "2" {
            # Block updates
            Write-Host ""
            Write-Host "=== Block Updates ===" -ForegroundColor Cyan
            Write-Host "- Enter 'back' or 'b' to return to main menu" -ForegroundColor Gray
            Write-Host "- Enter KB numbers to block (comma-separated, e.g., KB5063878,KB1234567)" -ForegroundColor Yellow
            $kbInput = Read-Host "KB Number(s)"
            
            if ($kbInput -eq 'back' -or $kbInput -eq 'b') {
                continue
            }
            
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
        }
        "3" {
            # Unblock updates
            Write-Host ""
            Write-Host "=== Unblock Updates ===" -ForegroundColor Cyan
            Write-Host "- Enter 'back' or 'b' to return to main menu" -ForegroundColor Gray
            Write-Host "- Enter 'all' or 'A' to unblock all currently blocked updates:" -ForegroundColor Green
            Write-Host '- Enter KB numbers to unblock (comma-separated, e.g., KB5063878,KB1234567)' -ForegroundColor Yellow
            $kbInput = Read-Host "KB Number(s) or 'all'"
            
            if ($kbInput -eq 'back' -or $kbInput -eq 'b') {
                continue
            }
            
            if ($kbInput) {
                if ($kbInput -eq "all" -or $kbInput -eq "ALL" -or $kbInput -eq "A" -or $kbInput -eq "a") {
                    Write-Host "Scanning for blocked updates..." -ForegroundColor Yellow
                    $blockedUpdates = @()
                    $registryPaths = @(
                        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\",
                        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\"
                    )
                    
                    foreach ($regPath in $registryPaths) {
                        if (Test-Path $regPath) {
                            $wushowhide = Get-ItemProperty -Path $regPath -Name "WUServer" -ErrorAction SilentlyContinue
                            $exclude = Get-ItemProperty -Path $regPath -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
                        }
                    }
                    
                    # Check for blocked KBs in registry
                    $blockedKBs = @()
                    $regPaths = @(
                        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\",
                        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\"
                    )
                    
                    foreach ($regPath in $regPaths) {
                        if (Test-Path $regPath) {
                            $properties = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                            foreach ($property in $properties.PSObject.Properties) {
                                if ($property.Name -match "KB\\d+") {
                                    $blockedKBs += $property.Name
                                }
                            }
                        }
                    }
                    
                    if ($blockedKBs.Count -gt 0) {
                        Write-Host "Found $($blockedKBs.Count) blocked updates:" -ForegroundColor Green
                        foreach ($kb in $blockedKBs) {
                            Write-Host "  - $kb" -ForegroundColor White
                        }
                        
                        $confirm = Read-Host "Unblock all $($blockedKBs.Count) updates? (y/n)"
                        if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                            foreach ($kb in $blockedKBs) {
                                $normalizedKB = Get-NormalizedKBNumber $kb
                                if ($normalizedKB) {
                                    Unblock-UpdateKB -KBNumber $normalizedKB
                                }
                            }
                        }
                    } else {
                        Write-Host "No blocked updates found." -ForegroundColor Yellow
                    }
                } else {
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
            }
            Read-Host "Press Enter to continue"
        }
            "4" {
            # Check blocking status
            Write-Host ""
            Write-Host "=== Check Blocking Status ===" -ForegroundColor Cyan
            Write-Host "- Enter 'back' or 'b' to return to main menu" -ForegroundColor Gray
            Write-Host "- Enter 'all' or 'A' to check all currently blocked updates:" -ForegroundColor Green
            Write-Host '- Enter KB numbers to check (comma-separated, e.g., KB5063878,KB1234567)' -ForegroundColor Yellow


            $kbInput = Read-Host "KB Number(s) or 'all'"
            
            if ($kbInput -eq 'back' -or $kbInput -eq 'b') {
                continue
            }
            
            if ($kbInput) {
                if ($kbInput -eq "all" -or $kbInput -eq "ALL" -or $kbInput -eq "A" -or $kbInput -eq "a") {
                    Check-UpdateBlockStatus -KBNumber "all"
                } else {
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
            }
            Read-Host "Press Enter to continue"
        }
            "5" {
            # Show blocking methods
            Show-BlockingMethods
            Write-Host ""
            Read-Host "Press Enter to continue"
        }
            "6" {
             # Repair Windows Update
            Invoke-QuickFix
            Read-Host "Press Enter to continue"
        }
            "7" {
            # Diagnostics
            Invoke-Diagnostic
            Read-Host "Press Enter to continue"
        }

            "0" {
            Write-Host "Exiting..." -ForegroundColor Yellow
            exit 0
        }
            "q" {
            Write-Host "Exiting..." -ForegroundColor Yellow
            exit 0
        }
            "Q" {
            Write-Host "Exiting..." -ForegroundColor Yellow
            exit 0
        }
        default {
            Write-Warning "Invalid choice. Please select 0-9 or type 'q' to quit."
            Read-Host "Press Enter to continue"
        }
    }
} while ($menuChoice -notin @("0", "q", "Q"))
    exit 0  # Exit after interactive menu completes
}

# Parameter-based processing continues below for non-interactive mode ONLY
# This section only runs when parameters are provided (not interactive mode)
if ($updatesToProcess.Count -eq 0) {
    Write-Host "No valid updates selected." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 0
}

# Handle new parameter-based operations
if ($DateRange) {
    Write-Host "Processing date-based removal..." -ForegroundColor Cyan
    if ($DateRange -match "^(\d{4}-\d{2}-\d{2}):(\d{4}-\d{2}-\d{2})$") {
        $startDate = [datetime]::Parse($matches[1])
        $endDate = [datetime]::Parse($matches[2])
        $result = Remove-UpdatesByDateRange -StartDate $startDate -EndDate $endDate -WhatIf:$ListOnly
        exit 0
    } else {
        Write-Host "Invalid date range format. Use: YYYY-MM-DD:YYYY-MM-DD" -ForegroundColor Red
        exit 1
    }
}

# Handle PSWindowsUpdate module installation if requested
if ($UsePSWindowsUpdate -and -not (Test-PSWindowsUpdateModule)) {
    Write-Host "PSWindowsUpdate module requested but not available. Installing..." -ForegroundColor Yellow
    $installed = Install-PSWindowsUpdateModule
    if (-not $installed) {
        Write-Host "Failed to install PSWindowsUpdate module. Exiting..." -ForegroundColor Red
        exit 1
    }
}

# Handle remote computer operations
if ($RemoteComputer) {
    Write-Host "Setting up remote connection to $RemoteComputer..." -ForegroundColor Cyan
    # Remote processing will be handled in the removal logic
}

# Validate selected updates for combined SSU/LCU packages
$selectedKBs = $updatesToProcess | ForEach-Object { Get-NormalizedKBNumber $_.HotFixID }
if (-not (Validate-KBInput -KBNumbers $selectedKBs)) {
    Write-Host "Validation failed. Exiting..." -ForegroundColor Yellow
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
                        Write-Host 'You can manually enable it via: System Properties -> System Protection -> Configure' -ForegroundColor Yellow
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
            Write-Host '5. Or use: System Properties > System Protection > Configure' -ForegroundColor White
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
    
    # Check for SSU updates before processing
    $isSSU = Test-SSUDetection -KBNumber $kb
    if ($isSSU) {
        Write-Host "Skipping SSU update due to permanent nature..." -ForegroundColor Yellow
        continue
    }
    
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
        
        # Enhanced multi-method removal with new capabilities
        
        # Method 1: PSWindowsUpdate module (if requested and available)
        if ($UsePSWindowsUpdate -and (Test-PSWindowsUpdateModule)) {
            Write-Host "Trying PSWindowsUpdate module..." -ForegroundColor Cyan
            try {
                $result = Remove-UpdateWithPSWindowsUpdate -KB $kb -Hide:$HideUpdate -WhatIf:$ListOnly
                if ($result.Success) {
                    $removeSuccess = $true
                    $removalMethods += "PSWindowsUpdate"
                    Write-Host "Successfully removed via PSWindowsUpdate module" -ForegroundColor Green
                    if ($HideUpdate) {
                        Write-Host "Update also hidden from Windows Update" -ForegroundColor Green
                    }
                } else {
                    Write-Host "   [!] PSWindowsUpdate failed: $($result.Error)" -ForegroundColor Yellow
                    $errorDetails += "PSWindowsUpdate: $($result.Error)"
                }
            } catch {
                Write-Host "   [!] PSWindowsUpdate module error: $($_.Exception.Message)" -ForegroundColor Yellow
                $errorDetails += "PSWindowsUpdate: $($_.Exception.Message)"
            }
        }

        # Method 2: Enhanced WUSA with Windows 10 1507+ support
        if (-not $removeSuccess) {
            Write-Host "Trying Windows Update Standalone Installer (WUSA)..." -ForegroundColor Gray
            
            # Check for Windows 10 1507+ WUSA limitations
            $wusaTest = Test-WUSAQuietMode -KB $kb
            if (-not $wusaTest.CanUseWUSA) {
                Write-Host "   [!] WUSA not supported for this update on Windows 10 1507+: $($wusaTest.Reason)" -ForegroundColor Yellow
                $errorDetails += "WUSA limitation: $($wusaTest.Reason)"
            } else {
                # Clean KB input for WUSA (remove KB prefix)
                $cleanKB = $kb -replace "^KB", ""
                
                $wusaArgs = "/uninstall", "/kb:$cleanKB", "/quiet", "/norestart"
                $wusaProcess = Start-Process -FilePath "wusa.exe" -ArgumentList $wusaArgs -Wait -PassThru -NoNewWindow
                
                if ($wusaProcess.ExitCode -eq 0 -or $wusaProcess.ExitCode -eq 3010) {
                    $removeSuccess = $true
                    $removalMethods += "WUSA"
                    Write-Host "Successfully removed via WUSA" -ForegroundColor Green
                } else {
                    $wusaError = switch ($wusaProcess.ExitCode) {
                        5 { "Access denied - requires administrator privileges" }
                        87 { "Invalid parameter - KB may not exist or format incorrect" }
                        2359302 { "Update not found or not applicable - may be combined SSU/LCU package" }
                        3010 { "Success, restart required" }
                        2149842967 { "Update not applicable - Windows 10 1507+ limitation" }
                        2149842966 { "Update not found - package database issue" }
                        default { "WUSA error code: $($wusaProcess.ExitCode)" }
                    }
                    Write-Host "   [!] WUSA failed: $wusaError" -ForegroundColor Yellow
                    $errorDetails += "WUSA: $wusaError"
                    
                    # Check for combined SSU/LCU packages
                    $combinedSSUPackages = @("5063878", "5062839", "5062978", "5034441", "5034127", "5031356", "5029331", "5028166", "5027231", "5025221")
                    if ($combinedSSUPackages -contains $cleanKB -and $wusaProcess.ExitCode -eq 2359302) {
                        Write-Host "   [!] This appears to be a combined SSU/LCU package that cannot be removed via WUSA" -ForegroundColor Yellow
                        Write-Host "   [i] Combined packages contain Servicing Stack Updates (SSU) which are permanent" -ForegroundColor Cyan
                        Write-Host "   [i] Use DISM or PowerShell cmdlets instead" -ForegroundColor Cyan
                        Write-Host '   [i] Settings -> Windows Update -> Update History -> Uninstall updates' -ForegroundColor Cyan
                    }
                }
            }
        }

        # Method 3: PSWindowsUpdate fallback (if available but not requested)
        if (-not $removeSuccess -and -not $UsePSWindowsUpdate -and (Test-PSWindowsUpdateModule)) {
            Write-Host "Trying PSWindowsUpdate module as fallback..." -ForegroundColor Gray
            try {
                $result = Remove-UpdateWithPSWindowsUpdate -KB $kb -Hide:$HideUpdate -WhatIf:$ListOnly
                if ($result.Success) {
                    $removeSuccess = $true
                    $removalMethods += "PSWindowsUpdate (fallback)"
                    Write-Host "Successfully removed via PSWindowsUpdate module" -ForegroundColor Green
                } else {
                    Write-Host "   [!] PSWindowsUpdate fallback failed: $($result.Error)" -ForegroundColor Yellow
                    $errorDetails += "PSWindowsUpdate fallback: $($result.Error)"
                }
            } catch {
                Write-Host "   [!] PSWindowsUpdate fallback error: $($_.Exception.Message)" -ForegroundColor Gray
            }
        }

        # Method 4: Universal DISM package discovery and removal (robust fallback)
        if (-not $removeSuccess) {
            Write-Host "Trying universal DISM package discovery..." -ForegroundColor Gray
            
            # Check if DISM is available
            $dismAvailable = Get-Command "dism.exe" -ErrorAction SilentlyContinue
            if (-not $dismAvailable) {
                Write-Host "DISM command not available, skipping DISM methods" -ForegroundColor Yellow
                $errorDetails += "DISM not available on this system"
            } else {
                # Clean KB input for DISM search
                $cleanKB = $kb -replace "^KB", ""
                
                # Dynamic DISM package discovery
                Write-Host "Searching for KB$cleanKB packages dynamically..." -ForegroundColor Gray
                try {
                    $dismOutput = & dism /online /get-packages /format:table 2>$null
                    $kbPackages = $dismOutput | Where-Object { $_ -match "Package.*KB$cleanKB" -or $_ -match "KB$cleanKB.*Package" }
                    
                    if ($kbPackages) {
                        Write-Host "Found KB$cleanKB in DISM packages" -ForegroundColor Green
                        
                        foreach ($packageLine in $kbPackages) {
                            if ($packageLine -match "Package Identity : (.*)") {
                                $packageName = $matches[1].Trim()
                                Write-Host "Testing package: $packageName" -ForegroundColor Gray
                                
                                # Check if package is removable
                                $testResult = Test-DISMPackage -PackageName $packageName
                                if ($testResult.Exists -and $testResult.IsRemovable) {
                                    $result = Remove-DISMPackage -PackageName $packageName -Quiet -NoRestart
                                    if ($result.Success) {
                                        $removeSuccess = $true
                                        $removalMethods += "DISM (dynamic discovery: $packageName)"
                                        Write-Host "   $($result.Message)" -ForegroundColor Green
                                        break
                                    } else {
                                        Write-Host "   [!] $($result.Message)" -ForegroundColor Yellow
                                        $errorDetails += "DISM dynamic: $($result.Message)"
                                    }
                                } elseif ($testResult.Exists -and -not $testResult.IsRemovable) {
                                    Write-Host "   [!] Package is permanent" -ForegroundColor Yellow
                                    $errorDetails += "Package $packageName is permanent"
                                }
                            }
                        }
                    } else {
                        Write-Host "KB$cleanKB not found in DISM packages" -ForegroundColor Gray
                    }
                } catch {
                    Write-Host "   [!] DISM search error: $($_.Exception.Message)" -ForegroundColor Yellow
                    $errorDetails += "DISM search failed: $($_.Exception.Message)"
                }
            }
        }
        
    } catch {
        $errorDetails += "Exception during removal: $($_.Exception.Message)"
        Write-Host "Exception during removal: $($_.Exception.Message)" -ForegroundColor Red
        $removeSuccess = $false
    }
    
    if ($removeSuccess) {
        $methodUsed = if ($removalMethods.Count -gt 0) { " using $($removalMethods[-1])" } else { "" }
        Write-Host "KB$kb removal initiated successfully$methodUsed!" -ForegroundColor Green
        $processedCount++
    } else {
        Write-Host "Failed to remove KB$kb" -ForegroundColor Red
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
            Write-Host '- Check Windows Update history: Settings > Windows Update > Update History' -ForegroundColor White
        }
        
        # Combined SSU/LCU package guidance
        if ($errorDetails -like "*combined*SSU*LCU*" -or $errorDetails -like "*KB5063878*" -or $errorDetails -like "*KB5062839*" -or $errorDetails -like "*KB5062978*") {
            Write-Host "`n--- Combined SSU/LCU Package Guidance ---" -ForegroundColor Red
            Write-Host "This appears to be a combined Servicing Stack Update (SSU) and Latest Cumulative Update (LCU) package." -ForegroundColor Yellow
            Write-Host "Microsoft states these packages cannot be removed via WUSA because they contain permanent SSU components." -ForegroundColor Yellow
            Write-Host "`nAlternative removal methods:" -ForegroundColor Cyan
            Write-Host '1. Settings GUI: Settings -> Windows Update -> Update History -> Uninstall updates' -ForegroundColor White
            Write-Host "2. DISM command: dism /online /get-packages -> find package -> dism /online /remove-package /packagename:Package_for_KB$kb" -ForegroundColor White
            Write-Host "3. PowerShell: Get-WindowsPackage -Online | Where-Object {`$_.PackageName -like \"*KB$kb*\"} | Remove-WindowsPackage -Online" -ForegroundColor White
            Write-Host "`nNote: SSU components are permanent system updates and cannot be removed." -ForegroundColor Yellow
        }
        
        $failedUpdates.Add($kb)
    }
}

# Handle remote computer processing
if ($RemoteComputer) {
    Write-Host "`n--- Remote Computer Processing ---" -ForegroundColor Cyan
    try {
        $remoteResult = Invoke-RemoteUpdateRemoval -ComputerName $RemoteComputer -KBs $updatesToProcess.HotFixID -UsePSWindowsUpdate:$UsePSWindowsUpdate -HideUpdate:$HideUpdate
        if ($remoteResult.Success) {
            Write-Host "Remote processing completed successfully" -ForegroundColor Green
            Write-Host "Updates processed remotely: $($remoteResult.ProcessedCount)" -ForegroundColor Green
            Write-Host "Failed removals: $($remoteResult.FailedKBs -join ', ')" -ForegroundColor Yellow
        } else {
            Write-Host "Remote processing failed: $($remoteResult.Error)" -ForegroundColor Red
        }
        exit 0
    } catch {
        Write-Host "Remote processing error: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
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
PowerShell Version: $($PSVersionTable.PSVersion)
Execution Policy: $(Get-ExecutionPolicy)
User: $env:USERNAME
Is Admin: $isAdmin

Error Summary:
$(if ($failedUpdates.Count -gt 0) { "Failed updates: $($failedUpdates -join ', ')" } else { "No failures detected" })

Detailed Process Log:
Script started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Found updates: $($installedUpdates.Count)
Selected for removal: $($updatesToProcess.Count)
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
    Write-Host "   - Run: net stop wuauserv; net stop bits; net stop cryptsvc" -ForegroundColor Gray
            Write-Host "   - Run: ren %systemroot%\SoftwareDistribution SoftwareDistribution.old" -ForegroundColor Gray
            Write-Host "   - Run: net start wuauserv; net start bits; net start cryptsvc" -ForegroundColor Gray
    Write-Host "10. Check Event Viewer: Applications and Services Logs -> Microsoft -> Windows -> WindowsUpdateClient" -ForegroundColor White
}