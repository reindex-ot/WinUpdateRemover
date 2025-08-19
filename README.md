# WinUpdateRemover

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-brightgreen.svg)](https://www.microsoft.com/windows)

**Safely remove Windows Updates with automatic restore point protection**

## [!] Administrator Privileges Required

**This script requires administrator privileges** for all operations except read-only functions. Run PowerShell as Administrator before using this script.

## Quick Start

**Run as Administrator:**
```powershell
iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/danalec/WinUpdateRemover/main/WinUpdateRemover.ps1'))
```

## Usage

### Interactive Mode
```powershell
.\WinUpdateRemover.ps1
```

### Command Line
```powershell
# Remove specific KBs
.\WinUpdateRemover.ps1 -KBNumbers "KB5053656","KB5055523"

# Check before removal
.\WinUpdateRemover.ps1 -Verify -KBNumbers "KB5053656"

# Preview only
.\WinUpdateRemover.ps1 -ListOnly

# Repair Windows Update
.\WinUpdateRemover.ps1 -QuickFix

# Full diagnostics
.\WinUpdateRemover.ps1 -Diagnostic
```

## Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-KBNumbers` | Target specific updates | `"KB5063878"` |
| `-Verify` | Check if updates are installed | `-Verify -KBNumbers "KB5063878"` |
| `-QuickFix` | Repair Windows Update service | `-QuickFix` |
| `-Diagnostic` | Run system analysis | `-Diagnostic` |
| `-Force` | Skip confirmations | `-Force` |
| `-ListOnly` | Preview without changes | `-ListOnly` |
| `-UsePSWindowsUpdate` | Use PSWindowsUpdate module | `-UsePSWindowsUpdate -KBNumbers "KB5063878"` |
| `-HideUpdate` | Hide update after removal | `-KBNumbers "KB5063878" -HideUpdate` |
| `-DateRange` | Remove by date range | `-DateRange "2024-01-01"` |
| `-RemoteComputer` | Target remote computer | `-RemoteComputer "SERVER01" -KBNumbers "KB5055523"` |

## Requirements
- Windows 10/11
- PowerShell 5.1+
- **Administrator rights** (required for most operations)
- System Restore enabled

## Administrator Privileges

**This script requires administrator privileges for:**
- Creating system restore points
- Removing Windows updates
- Modifying Windows registry
- Managing Windows services
- Using Windows Update API

**To run as administrator:**
1. Right-click PowerShell and select "Run as administrator"
2. Or use: `Start-Process powershell -Verb RunAs`

**Read-only operations** (no admin required):
- List installed updates (`-ListOnly`)
- Verify if updates are installed (`-Verify`)
- Check blocking status (`-CheckBlockStatus`)
- Show blocking methods (`-ShowBlockMethods`)

## Safety Features
- Automatic restore points
- Pre-removal verification
- Multiple removal methods
- Detailed logging
- SSU detection and warnings
- Remote computer validation
- Update hiding capabilities

## Common Issues

| Error | Solution |
|-------|----------|
| **Access denied** | Run as Administrator |
| **0x800f0805** | Run `-QuickFix` |
| **Service errors** | Run `-EnableSystemRestore` |
| **Update not found** | Verify exact KB format |

## Examples

### Basic Usage
```powershell
# Basic removal
.\WinUpdateRemover.ps1 -KBNumbers "KB5053656"

# Batch removal (silent)
.\WinUpdateRemover.ps1 -KBNumbers "KB5053656","KB5055523" -Force

# Check all blocked updates
.\WinUpdateRemover.ps1 -CheckBlockStatus -a

# Emergency workflow
.\WinUpdateRemover.ps1 -Verify -KBNumbers "KB5063878"
.\WinUpdateRemover.ps1 -QuickFix
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878"
```

### PSWindowsUpdate Integration
```powershell
# Use PSWindowsUpdate module for removal
.\WinUpdateRemover.ps1 -UsePSWindowsUpdate -KBNumbers "KB5063878"

# Hide updates after removal (requires PSWindowsUpdate)
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878" -HideUpdate
```

### Date-Based Removal
```powershell
# Remove all updates installed after specific date
.\WinUpdateRemover.ps1 -DateRange "2024-01-01"

# Remove updates from last 30 days
$30DaysAgo = (Get-Date).AddDays(-30).ToString("yyyy-MM-dd")
.\WinUpdateRemover.ps1 -DateRange $30DaysAgo
```

### Remote Computer Support
```powershell
# Remove updates from remote computer
.\WinUpdateRemover.ps1 -RemoteComputer "SERVER01" -KBNumbers "KB5055523"

# Remote removal with PSWindowsUpdate
.\WinUpdateRemover.ps1 -RemoteComputer "SERVER01" -KBNumbers "KB5063878" -UsePSWindowsUpdate

# Batch remote removal
$computers = @("SERVER01", "SERVER02", "WORKSTATION01")
foreach ($computer in $computers) {
    .\WinUpdateRemover.ps1 -RemoteComputer $computer -KBNumbers "KB5063878" -Force
}
```

## Servicing Stack Updates (SSU) Warnings

The script automatically detects **Servicing Stack Updates (SSUs)** and **Combined SSU/LCU packages** that cannot be removed:

- **SSUs are permanent system components** required for Windows Update functionality
- **Combined SSU/LCU packages** contain both servicing stack and cumulative updates
- These updates will be **skipped automatically** with appropriate warnings
- **Manual removal** may be possible via Windows Settings → Update & Security → Update History → Uninstall Updates

## Troubleshooting

### General Issues
1. **Run as Administrator**
2. **Check logs:** `%TEMP%\WinUpdateRemover_*.log`
3. **Use -Diagnostic for system analysis**

### Remote Computer Issues
| Issue | Solution |
|-------|----------|
| **Access denied** | Ensure PowerShell remoting is enabled: `Enable-PSRemoting -Force` |
| **Network connectivity** | Verify computer name and network access |
| **Authentication** | Use appropriate credentials for remote access |

### PSWindowsUpdate Module
| Issue | Solution |
|-------|----------|
| **Module not found** | Run with admin rights to auto-install: `-UsePSWindowsUpdate` |
| **Import failure** | Install manually: `Install-Module PSWindowsUpdate -Force` |

### Date Range Issues
| Issue | Solution |
|-------|----------|
| **Invalid date format** | Use ISO format: `yyyy-MM-dd` |
| **No updates found** | Verify date range includes actual update installations |

## License
[Unlicense](LICENSE)