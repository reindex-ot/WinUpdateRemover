# WinUpdateRemover

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-brightgreen.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-Unlicense-yellow.svg)](LICENSE)

**Safely remove problematic Windows Updates with automatic restore point protection**

A PowerShell tool to remove Windows updates causing system issues, with built-in safety features and comprehensive error handling.

## Quick Start

**Run as Administrator:**
```powershell
iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/danalec/WinUpdateRemover/main/WinUpdateRemover.ps1'))
```

Or download and run:
```powershell
# Download first, then run as Admin
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/danalec/WinUpdateRemover/main/WinUpdateRemover.ps1" -OutFile "WinUpdateRemover.ps1"
.\WinUpdateRemover.ps1
```

### Built-in Diagnostic Tools
- **Verification Mode**: Check if updates are actually installed before removal
- **Quick Fix Mode**: Automated Windows Update repair and cache reset
- **Diagnostic Mode**: Comprehensive Windows Update system analysis

## Requirements

- Windows 10/11 (Administrator rights required)
- PowerShell 5.1+
- System Restore enabled (recommended)

## Usage

### Interactive Mode (Recommended)
```powershell
.\WinUpdateRemover.ps1
```

### Diagnostic & Verification Tools
```powershell
# Verify if a specific update is installed
.\WinUpdateRemover.ps1 -Verify -KBNumbers "KB5063878"

# Run Windows Update repair
.\WinUpdateRemover.ps1 -QuickFix

# Comprehensive system diagnostics
.\WinUpdateRemover.ps1 -Diagnostic
```

### Batch Processing
```powershell
# Remove specific updates
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878","KB5055523"

# Silent removal
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878" -Force

# Preview only
.\WinUpdateRemover.ps1 -ListOnly
```

## Common Issues & Solutions

### Error 0x800f0805: "Invalid Windows package"
**Cause:** Update already removed or corrupted package
**Fix:**
```powershell
# Use built-in diagnostic tools
.\WinUpdateRemover.ps1 -QuickFix          # Automated repair
.\WinUpdateRemover.ps1 -Verify -KBNumbers "KB5063878"  # Check if update exists
.\WinUpdateRemover.ps1 -Diagnostic       # Comprehensive analysis

# Manual verification:
dism /online /get-packages | findstr "KB5063878"
```

### Error: "Service cannot be started"
**Cause:** System Restore disabled
**Fix:**
```powershell
Enable-ComputerRestore -Drive $env:SystemDrive
Start-Service -Name VSS
```

### Error: "Access denied"
**Cause:** Not running as Administrator
**Fix:** Right-click PowerShell → "Run as Administrator"

### Error: "Update not found"
**Cause:** Wrong KB format or update never installed
**Fix:** Use exact KB number format: `KB1234567` (not `1234567`)

### Error: "DISM failed"
**Cause:** Windows Update service issues
**Fix:**
```powershell
# Reset Windows Update components
Stop-Service wuauserv,bits,cryptsvc
Remove-Item "$env:SystemRoot\SoftwareDistribution\*" -Recurse -Force
Start-Service wuauserv,bits,cryptsvc
```

### Error: "Restart required"
**Cause:** Update partially removed
**Fix:** Restart computer, then re-run script

### Error: "Log file access denied"
**Cause:** Previous instance still running
**Fix:** Close all PowerShell windows, then retry

### Error: "PowerShell execution policy"
**Cause:** Script execution blocked
**Fix:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Advanced Parameters

| Parameter | Example | Purpose |
|-----------|---------|---------|
| `-ListOnly` | `-ListOnly` | Preview updates without removal |
| `-Force` | `-Force` | Skip confirmations |
| `-KBNumbers` | `-KBNumbers "KB5063878"` | Target specific updates |
| `-NoRestorePoint` | `-NoRestorePoint` | Skip restore point (not recommended) |
| `-Verify` | `-Verify -KBNumbers "KB5063878"` | Check if updates are installed |
| `-QuickFix` | `-QuickFix` | Automated Windows Update repair |
| `-Diagnostic` | `-Diagnostic` | Comprehensive system analysis |

## Troubleshooting Checklist

1. **Before running:**
   - [ ] Run PowerShell as Administrator
   - [ ] Check Windows Update service is running
   - [ ] Verify System Restore is enabled

2. **If removal fails:**
   - [ ] Check update actually exists: `Get-HotFix -Id KB5063878`
   - [ ] Run Windows Update troubleshooter
   - [ ] Clear Windows Update cache
   - [ ] Try Safe Mode if persistent

3. **Get help:**
   - Check logs: `%TEMP%\WinUpdateRemover_*.log`
   - Report issues: [GitHub Issues](https://github.com/danalec/WinUpdateRemover/issues)

## Safety Features

- **Automatic restore point** before any changes
- **Update verification** before removal attempts
- **Multiple removal methods** (DISM, WUSA, Windows Update API)
- **Detailed logging** for troubleshooting
- **Confirmation prompts** in interactive mode

## Examples

### Basic Usage
```powershell
# Remove problematic SSD update
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878"

# Remove multiple updates silently
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878","KB5055523","KB5062660" -Force

# Check what would be removed
.\WinUpdateRemover.ps1 -ListOnly | Out-GridView

# Emergency removal (skip safety checks - use with caution)
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878" -Force -NoRestorePoint
```

### Diagnostic & Verification Examples
```powershell
# Verify if KB5063878 is actually installed before removal
.\WinUpdateRemover.ps1 -Verify -KBNumbers "KB5063878"

# Run comprehensive Windows Update diagnostics
.\WinUpdateRemover.ps1 -Diagnostic

# Quick fix for Windows Update issues
.\WinUpdateRemover.ps1 -QuickFix

# Complete workflow for 0x800f0805 error
.\WinUpdateRemover.ps1 -Verify -KBNumbers "KB5063878"  # Check if update exists
.\WinUpdateRemover.ps1 -QuickFix                       # Repair Windows Update
.\WinUpdateRemover.ps1 -Diagnostic                     # Full system check
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878" -Force   # Remove if still needed
```