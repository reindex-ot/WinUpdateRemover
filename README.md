# WinUpdateRemover

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-brightgreen.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-Unlicense-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-v1.0.1-red.svg)](https://github.com/danalec/WinUpdateRemover/releases)
[![Author](https://img.shields.io/badge/Author-@danalec-orange.svg)](https://github.com/danalec)

> **Safely remove problematic Windows Updates with automatic restore point protection**

WinUpdateRemover is an interactive PowerShell tool designed to help Windows administrators and power users safely remove problematic Windows Updates that may cause system instability, performance issues, or hardware problems. It provides a safe and guided approach to update removal, with automatic System Restore point creation and enhanced error handling.

## Features

- **Safe Removal Process**: Automatic System Restore point creation before any changes
- **Targeted Removal**: Remove specific problematic updates (like KB5063878 causing SSD issues)
- **Enhanced Error Handling**: Improved handling for 0x800f0805 and other common errors
- **Multi-Method Removal**: Four different removal approaches (DISM auto-detect, DISM standard, WUSA, Windows Update API)
- **Smart Detection**: Automatically checks if updates are installed before attempting removal
- **Interactive Mode**: Step-by-step guidance with confirmation prompts
- **Detailed Logging**: Comprehensive logs with system info and error details
- **Troubleshooting Guide**: Built-in guidance for common removal failures
- **Custom KB Support**: Add your own KB numbers for removal
- **KB Number Normalization**: Handles various KB formats consistently (KB1234567, 1234567, etc.)
- **Batch Processing**: Remove multiple updates in a single session

## Requirements

- **Windows 10/11** (Windows Server 2016+ also supported)
- **PowerShell 5.1** or higher
- **Administrator privileges** (required for update removal)
- **System Restore** enabled (recommended, script can enable if needed)

## Quick Start

### Option 1: Direct Execution
```powershell
# Run PowerShell as Administrator
# Navigate to script directory
.\WinUpdateRemover.ps1
```

### Option 2: One-liner Download & Run
```powershell
# Download and execute (Run as Admin)
iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/danalec/WinUpdateRemover/main/WinUpdateRemover.ps1'))
```

## Usage Guide

### Basic Workflow

1. **Launch PowerShell as Administrator**
   ```powershell
   # Right-click PowerShell > Run as Administrator
   ```

2. **Run the Script**
   ```powershell
   .\WinUpdateRemover.ps1
   ```

3. **Select Updates**
   - View all installed updates with problematic ones highlighted
   - Choose specific updates by number or select all
   - Script automatically identifies known problematic updates

4. **Review & Confirm**
   - Script displays all selected updates with installation status
   - Creates System Restore point (highly recommended)
   - Confirms before proceeding with removal

5. **Process Updates**
   - Interactive removal for each update
   - Option to skip individual updates
   - Real-time status feedback

6. **Restart System**
   - Choose immediate or manual restart
   - Changes take effect after reboot

### Advanced Usage

#### Interactive Mode (Default)
```powershell
# Standard interactive execution
.\WinUpdateRemover.ps1
```

#### Non-Interactive Modes

**List Only Mode** - View updates without making changes:
```powershell
.\WinUpdateRemover.ps1 -ListOnly
```

**Force Mode** - Skip all confirmation prompts:
```powershell
.\WinUpdateRemover.ps1 -Force
```

**Specific KB Removal** - Remove specific updates by KB number:
```powershell
# Remove specific KB numbers
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878","KB5055523"

# Force removal without prompts
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878" -Force
```

**Skip Restore Point** - Useful for automation:
```powershell
.\WinUpdateRemover.ps1 -NoRestorePoint -Force
```

#### Batch Processing Examples
```powershell
# Remove all problematic updates silently
.\WinUpdateRemover.ps1 -Force -NoRestorePoint

# Remove specific updates with logging
.\WinUpdateRemover.ps1 -KBNumbers "KB5063878","KB5062660" -Force | Tee-Object -FilePath "C:\Logs\UpdateRemoval.log"

# Preview before removal
.\WinUpdateRemover.ps1 -ListOnly | Out-GridView
```

#### Parameter Reference

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `-ListOnly` | Switch | List updates without removal | `-ListOnly` |
| `-Force` | Switch | Skip all confirmation prompts | `-Force` |
| `-KBNumbers` | String[] | Specific KB numbers to remove | `-KBNumbers "KB5063878","KB5055523"` |
| `-NoRestorePoint` | Switch | Skip System Restore point creation | `-NoRestorePoint` |

### Troubleshooting

### Common Errors and Solutions

#### Error 0x800f0805: "指定したパッケージは無効な Windows パッケージです"
This error indicates the update package is invalid or not found. This commonly occurs when:
- The update has already been removed
- The package name format is incorrect
- Windows Update components are corrupted

**Solutions:**
1. **Verify update status**: Check if the update is actually installed
2. **Run Windows Update Troubleshooter**: Settings > System > Troubleshoot > Other troubleshooters
3. **Repair Windows Update**: Run `DISM /Online /Cleanup-Image /RestoreHealth` then `sfc /scannow`
4. **Check Windows Update history**: Review what updates were recently installed/removed

#### Error: "サービスは、無効であるか、または関連付けられた有効なデバイスがないため、開始できません"
This indicates System Restore service is disabled.

**Solutions:**
1. **Enable System Restore**:
   ```powershell
   Enable-ComputerRestore -Drive $env:SystemDrive
   ```
2. **Start Volume Shadow Copy service**:
   ```powershell
   Start-Service -Name VSS
   ```
3. **Skip restore point**: Use `-NoRestorePoint` parameter (not recommended for production)

#### Error: "Failed to remove KB..."
General removal failure with multiple potential causes.

**Solutions:**
1. **Restart Windows Update service**:
   ```powershell
   Restart-Service -Name wuauserv
   Restart-Service -Name bits
   ```
2. **Clear Windows Update cache**:
   ```powershell
   Stop-Service wuauserv
   Remove-Item -Path "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force
   Start-Service wuauserv
   ```
3. **Use Safe Mode**: Boot into Safe Mode and run the script
4. **Manual removal**: Use Windows Settings > Windows Update > Update History > Uninstall Updates

### Log Analysis
The script creates detailed logs in `%TEMP%\WinUpdateRemover_*.log`. Check these logs for:
- Specific error codes
- System information
- Attempted removal methods
- Detailed error messages

### Getting Help
If issues persist:
1. Check the GitHub issues page: [WinUpdateRemover Issues](https://github.com/danalec/WinUpdateRemover/issues)
2. Include the log file when reporting issues
3. Provide system information from the log
4. Check Windows Event Viewer for additional error details

## Advanced Usage Scenarios

#### Automation & Scheduling
```powershell
# Create scheduled task for weekly problematic update removal
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File 'C:\Tools\WinUpdateRemover.ps1' -Force -NoRestorePoint"
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "2:00AM"
Register-ScheduledTask -TaskName "Weekly Update Cleanup" -Action $Action -Trigger $Trigger
```

#### Remote Execution
```powershell
# Execute on remote computer
Invoke-Command -ComputerName "SERVER01" -ScriptBlock {
    & "C:\Tools\WinUpdateRemover.ps1" -KBNumbers "KB5063878" -Force -NoRestorePoint
}
```

#### Integration with Monitoring
```powershell
# Check for problematic updates and alert
$Updates = .\WinUpdateRemover.ps1 -ListOnly
if ($Updates -match "KB5063878") {
    Send-MailMessage -To "admin@company.com" -Subject "CRITICAL: Problematic Update Found" -Body "KB5063878 detected on $env:COMPUTERNAME"
}
```

#### Removing Specific Updates
The script automatically scans for and highlights problematic updates. You can select specific updates by entering their corresponding numbers when prompted.

#### Batch Removal Mode
Choose 'all' to process all updates at once, or specify multiple numbers separated by commas (e.g., 1,3,5).

## Known Problematic Updates

### Windows 11 24H2 - Critical Issues (2025)

| KB Number | Issue Description | Status |
|-----------|-------------------|---------|
| KB5063878 | **CRITICAL**: SSD/HDD corruption during intensive writes | ACTIVE ISSUE |
| KB5055523 | **CRITICAL**: BSOD SECURE_KERNEL_ERROR, CRITICAL_PROCESS_DIED | KIR Released |
| KB5053656 | **CRITICAL**: System crashes and BSODs | KIR Released |
| KB5053598 | **CRITICAL**: BSOD SECURE_KERNEL_ERROR | KIR Released |

### Windows 11 24H2/23H2/22H2 - High/Medium Issues

| KB Number | Issue Description | Status |
|-----------|-------------------|---------|
| KB5062660 | Installation failures, CertEnroll errors | July 2025 |
| KB5055528 | Various system issues | KIR Released |
| KB5043145 | System functionality issues | KIR Released |
| KB5039302 | Script execution issues | KIR Released |

### Windows 10 22H2/21H2 - Critical Issues

| KB Number | Issue Description | Status |
|-----------|-------------------|---------|
| KB5058379 | **CRITICAL**: BitLocker recovery loops (Intel TXT) | OOB Fix Released |
| KB5019959 | **CRITICAL**: BSOD DPC_WATCHDOG_VIOLATION on boot | November 2022 |

### Windows 10 22H2 - High/Medium Issues (2025)

| KB Number | Issue Description | Status |
|-----------|-------------------|---------|
| KB5062649 | Emoji Panel broken, performance issues | ACTIVE ISSUE |
| KB5062554 | Various system issues | ACTIVE ISSUE |
| KB5055518 | Random text when printing | Fixed |
| KB5046714 | Packaged apps update/uninstall failures | Fixed |
| KB5057589 | Windows RE update shows as failed | Fixed |

### Special Thanks
- **[@Necoru_cat](https://x.com/Necoru_cat)** - For extensive NVMe SSD testing that helped identify critical issues with KB5063878

## Troubleshooting

### Common Issues

**Script won't run:**
```powershell
# Check execution policy
Get-ExecutionPolicy
# If restricted, temporarily allow
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

**Update won't uninstall:**
- Some updates are permanent and cannot be removed
- Try Safe Mode for stubborn updates
- Use DISM for deeper system changes

**System Restore fails:**
```powershell
# Enable System Restore manually
Enable-ComputerRestore -Drive "C:\"
# Verify service is running
Get-Service "VSS", "SWPRV", "Schedule" | Start-Service
```

### Recovery Options

If issues occur after removal:

1. **Use System Restore**
   ```powershell
   rstrui.exe
   ```

2. **Reinstall Update**
   ```powershell
   # Check Windows Update
   Start-Process ms-settings:windowsupdate
   ```

3. **Use DISM/SFC**
   ```powershell
   # Repair system files
   DISM /Online /Cleanup-Image /RestoreHealth
   sfc /scannow
   ```

## Safety Features

- **Mandatory Admin Check**: Prevents accidental execution without proper privileges
- **Restore Point Creation**: Automatic System Restore point before any system changes
- **Update Verification**: Checks if updates exist before attempting removal
- **Multiple Confirmations**: Prevents accidental removals
- **Detailed Logging**: Track all operations for audit purposes
- **Graceful Fallbacks**: Multiple removal methods for compatibility

## Configuration

### Default Updates List

The script includes a pre-defined list of problematic updates. You can modify the `$problematicKBs` array in the script to customize which updates are flagged as problematic.

### Timeout Settings

Modify restart delay by changing the timeout value in the restart prompt section.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is released into the public domain under the Unlicense - see the [LICENSE](LICENSE) file for details.

## Disclaimer

**USE AT YOUR OWN RISK**

This tool modifies system components. While it includes safety features:
- Always create restore points before use
- Test in non-production environments first
- Understand what each update does before removal
- Some updates may be required for security

The authors are not responsible for any damage or data loss.

## Support

- **Issues**: [GitHub Issues](https://github.com/danalec/WinUpdateRemover/issues)
- **Discussions**: [GitHub Discussions](https://github.com/danalec/WinUpdateRemover/discussions)
- **Wiki**: [Documentation Wiki](https://github.com/danalec/WinUpdateRemover/wiki)

## Acknowledgments

- **[@Necoru_cat](https://x.com/Necoru_cat)** for NVMe SSD testing that identified KB5063878 issues ([Reference](https://x.com/Necoru_cat/status/1956949132066898080))
- Windows IT Pro community for identifying problematic updates
- PowerShell community for scripting best practices
- Contributors and testers

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0   | 2025-08-18 | Initial release with comprehensive safety features |
| 1.0.1 | 2025-08-19 | Added support for custom KB numbers and improved error handling |

---

**Made with care by [@danalec](https://github.com/danalec) for the Windows sysadmin community**

*If this tool helped you, consider giving it a star on GitHub!*