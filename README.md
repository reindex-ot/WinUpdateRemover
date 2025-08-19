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

## Common Issues

| Error | Solution |
|-------|----------|
| **Access denied** | Run as Administrator |
| **0x800f0805** | Run `-QuickFix` |
| **Service errors** | Run `-EnableSystemRestore` |
| **Update not found** | Verify exact KB format |

## Examples

```powershell
# Basic removal
.\WinUpdateRemover.ps1 -KBNumbers "KB5053656"

# Batch removal (silent)
.\WinUpdateRemover.ps1 -KBNumbers "KB5053656","KB5055523" -Force

# Check all blocked updates
.\WinUpdateRemover.ps1 -CheckBlockStatus "all"
# Or use A as alias
.\WinUpdateRemover.ps1 -CheckBlockStatus "A"

# Emergency workflow
.\WinUpdateRemover.ps1 -Verify -KBNumbers "KB5063878"
.\WinUpdateRemover.ps1 -QuickFix
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878"
```

## Troubleshooting
1. **Run as Administrator**
2. **Check logs:** `%TEMP%\WinUpdateRemover_*.log`
3. **Use -Diagnostic for system analysis**

## License
[Unlicense](LICENSE)