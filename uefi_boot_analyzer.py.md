```markdown
UEFI Boot Analyzer - Comprehensive UEFI/EFI Boot Configuration Analysis Tool

Description:
    A powerful cross-platform utility for analyzing UEFI/EFI boot configurations,
    system firmware information, and boot-related security settings. This tool
    provides detailed insights into boot entries, Secure Boot status, EFI System
    Partition configuration, and overall system boot health across Windows, Linux,
    and macOS platforms.

Features:
    • UEFI/Legacy BIOS detection and identification
    • Boot entry enumeration and analysis
    • Secure Boot and System Integrity Protection status
    • EFI System Partition (ESP) analysis
    • Cross-platform compatibility (Windows/Linux/macOS)
    • JSON report generation for automation
    • Comprehensive error handling and logging
    • Verbose analysis mode for troubleshooting

Supported Platforms:
    - Windows (10/11) - Uses bcdedit, PowerShell, and WMI
    - Linux (most distributions) - Uses efibootmgr, GRUB, and sysfs
    - macOS (Intel/Apple Silicon) - Uses bless, diskutil, and csrutil

Requirements:
    - Python 3.6 or higher
    - Administrator/root privileges (recommended for full functionality)
    - Platform-specific tools (bcdedit, efibootmgr, etc.)

Usage Examples:
    python uefi_boot_analyzer.py                    # Basic analysis
    python uefi_boot_analyzer.py -v                 # Verbose mode
    python uefi_boot_analyzer.py -o report.json     # Save to file
    python uefi_boot_analyzer.py --help             # Show help

Author: dawciobiel
GitHub: https://github.com/dawciobiel
Date: June 02, 2025
Version: 1.0

License:
GPL (GNU General Public License)
Copyright (C) 2025 dawciobiel

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

Security Notice:
    This tool analyzes system boot configuration and may require elevated
    privileges. Always review the source code before running with administrator
    or root permissions. The tool does not modify system configuration - it
    only reads and analyzes existing settings.

Technical Notes:
    - Windows analysis uses bcdedit and PowerShell cmdlets
    - Linux analysis requires access to /sys/firmware/efi and boot configuration
    - macOS analysis uses system_profiler and native BSD tools
    - Some features may be limited without appropriate system privileges
    - EFI variable access may vary depending on system configuration

Changelog:
    v1.0 (2025-06-02): Initial release with multi-platform support
```
