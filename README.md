# WinUpdateRemover

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-brightgreen.svg)](https://www.microsoft.com/windows)

**Safely remove problematic Windows Updates with automatic restore point protection**

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

### Target Specific Updates
```powershell
# Remove specific KBs
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878","KB5055523"

# Verify before removal
.\WinUpdateRemover.ps1 -Verify -KBNumbers "KB5063878"

# Preview only
.\WinUpdateRemover.ps1 -ListOnly
```

### Diagnostic Tools
```powershell
# Quick Windows Update repair
.\WinUpdateRemover.ps1 -QuickFix

# Full system diagnostics
.\WinUpdateRemover.ps1 -Diagnostic

# Fix System Restore service
.\WinUpdateRemover.ps1 -EnableSystemRestore
```

## Common Issues

| Error | Cause | Solution |
|-------|-------|----------|
| **0x800f0805** | Update already removed/corrupted | Run `.\WinUpdateRemover.ps1 -QuickFix` |
| **Access denied** | Not admin | Run PowerShell as Administrator |
| **Service cannot be started** | System Restore disabled | Run `.\WinUpdateRemover.ps1 -EnableSystemRestore` |
| **Update not found** | Wrong format or not installed | Use exact KB format: `KB1234567` |

## Parameters

| Parameter | Purpose | Example |
|-----------|---------|---------|
| `-KBNumbers` | Target specific updates | `-KBNumbers "KB5063878"` |
| `-Verify` | Check if updates installed | `-Verify -KBNumbers "KB5063878"` |
| `-QuickFix` | Repair Windows Update | `-QuickFix` |
| `-Diagnostic` | System analysis | `-Diagnostic` |
| `-Force` | Skip confirmations | `-KBNumbers "KB5063878" -Force` |
| `-ListOnly` | Preview without removal | `-ListOnly` |

## Requirements
- Windows 10/11 (Administrator required)
- PowerShell 5.1+
- System Restore enabled (recommended)

## Safety Features
- Automatic restore point creation
- Update verification before removal
- Multiple removal methods (DISM, WUSA, Windows Update API)
- Detailed logging to `%TEMP%\WinUpdateRemover_*.log`

## Examples

**Basic removal:**
```powershell
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878"
```

**Silent batch removal:**
```powershell
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878","KB5055523" -Force
```

**Emergency workflow:**
```powershell
# Verify → Repair → Remove
.\WinUpdateRemover.ps1 -Verify -KBNumbers "KB5063878"
.\WinUpdateRemover.ps1 -QuickFix
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878"
```

**Block problematic updates:**
```powershell
# Prevent KB5063878 from installing
.\BlockKB5063878.ps1 -BlockUpdate

# Check if update is blocked
.\BlockKB5063878.ps1 -CheckStatus

# Show all blocking methods
.\BlockKB5063878.ps1 -ShowMethods
```

## Troubleshooting
1. **Before running:** Run PowerShell as Administrator
2. **If fails:** Check logs in `%TEMP%\WinUpdateRemover_*.log`

## License
Unlicense - See [LICENSE](LICENSE) for details