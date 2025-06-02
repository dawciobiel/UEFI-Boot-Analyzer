#!/usr/bin/env python3
"""
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
License: GPL (GNU General Public License)

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
"""

import os
import sys
import subprocess
import platform
import json
import re
from pathlib import Path
from datetime import datetime
import argparse

class UEFIBootAnalyzer:
    def __init__(self):
        self.system = platform.system()
        self.architecture = platform.machine()
        self.boot_info = {}
        self.errors = []

    def print_header(self):
        """Print the application header"""
        print("=" * 60)
        print("           UEFI BOOT ANALYZER v1.0")
        print("=" * 60)
        print(f"System: {self.system} ({self.architecture})")
        print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        print()

    def check_uefi_support(self):
        """Check if the system supports UEFI"""
        print("🔍 Checking UEFI Support...")

        if self.system == "Windows":
            return self._check_uefi_windows()
        elif self.system == "Linux":
            return self._check_uefi_linux()
        elif self.system == "Darwin":  # macOS
            return self._check_uefi_macos()
        else:
            self.errors.append(f"Unsupported operating system: {self.system}")
            return False

    def _check_uefi_windows(self):
        """Check UEFI support on Windows"""
        try:
            # Check if system firmware is UEFI
            result = subprocess.run(['bcdedit', '/enum', 'firmware'],
                                  capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                self.boot_info['firmware_type'] = 'UEFI'
                print("✅ UEFI firmware detected")
                return True
            else:
                # Try alternative method
                result = subprocess.run(['wmic', 'path', 'win32_computersystem', 'get', 'bootupstate'],
                                      capture_output=True, text=True, shell=True)
                if "Normal boot" in result.stdout:
                    self.boot_info['firmware_type'] = 'UEFI'
                    print("✅ UEFI firmware detected (alternative method)")
                    return True
        except Exception as e:
            self.errors.append(f"Error checking UEFI on Windows: {str(e)}")

        print("❌ UEFI firmware not detected or Legacy BIOS mode")
        self.boot_info['firmware_type'] = 'Legacy BIOS'
        return False

    def _check_uefi_linux(self):
        """Check UEFI support on Linux"""
        try:
            # Check if /sys/firmware/efi exists
            if os.path.exists('/sys/firmware/efi'):
                self.boot_info['firmware_type'] = 'UEFI'
                print("✅ UEFI firmware detected")
                return True
            else:
                print("❌ UEFI firmware not detected - Legacy BIOS mode")
                self.boot_info['firmware_type'] = 'Legacy BIOS'
                return False
        except Exception as e:
            self.errors.append(f"Error checking UEFI on Linux: {str(e)}")
            return False

    def _check_uefi_macos(self):
        """Check UEFI support on macOS (Mac uses EFI)"""
        try:
            # macOS uses EFI by default on Intel Macs, custom firmware on Apple Silicon
            result = subprocess.run(['system_profiler', 'SPHardwareDataType'],
                                  capture_output=True, text=True)
            if "Apple" in result.stdout:
                self.boot_info['firmware_type'] = 'Apple EFI'
                print("✅ Apple EFI firmware detected")
                return True
        except Exception as e:
            self.errors.append(f"Error checking EFI on macOS: {str(e)}")

        self.boot_info['firmware_type'] = 'Unknown'
        return False

    def analyze_boot_entries(self):
        """Analyze boot entries"""
        print("\n🔍 Analyzing Boot Entries...")

        if self.system == "Windows":
            self._analyze_boot_entries_windows()
        elif self.system == "Linux":
            self._analyze_boot_entries_linux()
        elif self.system == "Darwin":
            self._analyze_boot_entries_macos()

    def _analyze_boot_entries_windows(self):
        """Analyze Windows boot entries"""
        try:
            # Get boot configuration data
            result = subprocess.run(['bcdedit', '/enum'],
                                  capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                self.boot_info['boot_entries'] = self._parse_bcdedit_output(result.stdout)
                print(f"✅ Found {len(self.boot_info['boot_entries'])} boot entries")
            else:
                self.errors.append("Failed to retrieve boot configuration data")
        except Exception as e:
            self.errors.append(f"Error analyzing Windows boot entries: {str(e)}")

    def _parse_bcdedit_output(self, output):
        """Parse bcdedit output"""
        entries = []
        current_entry = {}

        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('identifier'):
                if current_entry:
                    entries.append(current_entry)
                current_entry = {'identifier': line.split(None, 1)[1]}
            elif line.startswith('description'):
                current_entry['description'] = line.split(None, 1)[1]
            elif line.startswith('device'):
                current_entry['device'] = line.split(None, 1)[1]
            elif line.startswith('path'):
                current_entry['path'] = line.split(None, 1)[1]

        if current_entry:
            entries.append(current_entry)

        return entries

    def _analyze_boot_entries_linux(self):
        """Analyze Linux boot entries"""
        try:
            boot_entries = []

            # Check efibootmgr if available
            if os.path.exists('/usr/bin/efibootmgr') or os.path.exists('/usr/sbin/efibootmgr'):
                result = subprocess.run(['efibootmgr', '-v'],
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    boot_entries = self._parse_efibootmgr_output(result.stdout)

            # Check GRUB configuration
            grub_configs = ['/boot/grub/grub.cfg', '/boot/grub2/grub.cfg']
            for config_path in grub_configs:
                if os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        grub_content = f.read()
                        boot_entries.extend(self._parse_grub_config(grub_content))
                    break

            self.boot_info['boot_entries'] = boot_entries
            print(f"✅ Found {len(boot_entries)} boot entries")

        except Exception as e:
            self.errors.append(f"Error analyzing Linux boot entries: {str(e)}")

    def _parse_efibootmgr_output(self, output):
        """Parse efibootmgr output"""
        entries = []
        for line in output.split('\n'):
            if line.startswith('Boot'):
                match = re.match(r'Boot(\d+)\*?\s+(.+)', line)
                if match:
                    entries.append({
                        'number': match.group(1),
                        'description': match.group(2),
                        'type': 'EFI'
                    })
        return entries

    def _parse_grub_config(self, content):
        """Parse GRUB configuration"""
        entries = []
        lines = content.split('\n')

        for i, line in enumerate(lines):
            if 'menuentry' in line:
                match = re.search(r'menuentry\s+["\']([^"\']+)', line)
                if match:
                    entries.append({
                        'description': match.group(1),
                        'type': 'GRUB',
                        'line': i + 1
                    })

        return entries

    def _analyze_boot_entries_macos(self):
        """Analyze macOS boot entries"""
        try:
            # Use bless command to get boot information
            result = subprocess.run(['bless', '--info'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                self.boot_info['boot_entries'] = [{'description': 'macOS System', 'info': result.stdout}]
                print("✅ macOS boot information retrieved")
            else:
                self.errors.append("Failed to retrieve macOS boot information")
        except Exception as e:
            self.errors.append(f"Error analyzing macOS boot entries: {str(e)}")

    def check_secure_boot(self):
        """Check Secure Boot status"""
        print("\n🔍 Checking Secure Boot Status...")

        if self.system == "Windows":
            self._check_secure_boot_windows()
        elif self.system == "Linux":
            self._check_secure_boot_linux()
        elif self.system == "Darwin":
            self._check_secure_boot_macos()

    def _check_secure_boot_windows(self):
        """Check Secure Boot on Windows"""
        try:
            result = subprocess.run(['powershell', '-Command',
                                   'Confirm-SecureBootUEFI'],
                                  capture_output=True, text=True, shell=True)
            if "True" in result.stdout:
                self.boot_info['secure_boot'] = 'Enabled'
                print("✅ Secure Boot is enabled")
            else:
                self.boot_info['secure_boot'] = 'Disabled'
                print("❌ Secure Boot is disabled")
        except Exception as e:
            self.errors.append(f"Error checking Secure Boot on Windows: {str(e)}")

    def _check_secure_boot_linux(self):
        """Check Secure Boot on Linux"""
        try:
            if os.path.exists('/sys/firmware/efi/efivars/SecureBoot-*'):
                # Read Secure Boot status from EFI variables
                with open('/proc/sys/kernel/securelevel', 'r') as f:
                    level = f.read().strip()
                    if int(level) > 0:
                        self.boot_info['secure_boot'] = 'Enabled'
                        print("✅ Secure Boot is enabled")
                    else:
                        self.boot_info['secure_boot'] = 'Disabled'
                        print("❌ Secure Boot is disabled")
            else:
                self.boot_info['secure_boot'] = 'Not available'
                print("ℹ️ Secure Boot information not available")
        except Exception as e:
            self.errors.append(f"Error checking Secure Boot on Linux: {str(e)}")

    def _check_secure_boot_macos(self):
        """Check Secure Boot on macOS"""
        try:
            result = subprocess.run(['csrutil', 'status'],
                                  capture_output=True, text=True)
            if "enabled" in result.stdout.lower():
                self.boot_info['secure_boot'] = 'SIP Enabled'
                print("✅ System Integrity Protection (SIP) is enabled")
            else:
                self.boot_info['secure_boot'] = 'SIP Disabled'
                print("❌ System Integrity Protection (SIP) is disabled")
        except Exception as e:
            self.errors.append(f"Error checking SIP on macOS: {str(e)}")

    def analyze_esp_partition(self):
        """Analyze EFI System Partition"""
        print("\n🔍 Analyzing EFI System Partition...")

        if self.system == "Windows":
            self._analyze_esp_windows()
        elif self.system == "Linux":
            self._analyze_esp_linux()
        elif self.system == "Darwin":
            self._analyze_esp_macos()

    def _analyze_esp_windows(self):
        """Analyze ESP on Windows"""
        try:
            result = subprocess.run(['mountvol'], capture_output=True, text=True, shell=True)
            esp_paths = []

            for line in result.stdout.split('\n'):
                if 'EFI' in line or 'System' in line:
                    esp_paths.append(line.strip())

            if esp_paths:
                self.boot_info['esp_partitions'] = esp_paths
                print(f"✅ Found {len(esp_paths)} EFI System Partition(s)")
            else:
                print("❌ No EFI System Partition found")

        except Exception as e:
            self.errors.append(f"Error analyzing ESP on Windows: {str(e)}")

    def _analyze_esp_linux(self):
        """Analyze ESP on Linux"""
        try:
            # Check mounted ESP partitions
            result = subprocess.run(['mount'], capture_output=True, text=True)
            esp_mounts = []

            for line in result.stdout.split('\n'):
                if '/boot/efi' in line or 'vfat' in line:
                    esp_mounts.append(line.strip())

            self.boot_info['esp_partitions'] = esp_mounts
            print(f"✅ Found {len(esp_mounts)} mounted ESP partition(s)")

        except Exception as e:
            self.errors.append(f"Error analyzing ESP on Linux: {str(e)}")

    def _analyze_esp_macos(self):
        """Analyze ESP on macOS"""
        try:
            result = subprocess.run(['diskutil', 'list'], capture_output=True, text=True)
            esp_partitions = []

            for line in result.stdout.split('\n'):
                if 'EFI' in line:
                    esp_partitions.append(line.strip())

            self.boot_info['esp_partitions'] = esp_partitions
            print(f"✅ Found {len(esp_partitions)} EFI partition(s)")

        except Exception as e:
            self.errors.append(f"Error analyzing ESP on macOS: {str(e)}")

    def generate_report(self, output_file=None):
        """Generate analysis report"""
        print("\n📋 Generating Analysis Report...")

        report = {
            'analysis_date': datetime.now().isoformat(),
            'system_info': {
                'os': self.system,
                'architecture': self.architecture,
                'platform': platform.platform()
            },
            'boot_analysis': self.boot_info,
            'errors': self.errors
        }

        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"✅ Report saved to: {output_file}")
            except Exception as e:
                print(f"❌ Error saving report: {str(e)}")

        return report

    def print_summary(self):
        """Print analysis summary"""
        print("\n" + "=" * 60)
        print("                ANALYSIS SUMMARY")
        print("=" * 60)

        print(f"Firmware Type: {self.boot_info.get('firmware_type', 'Unknown')}")
        print(f"Secure Boot: {self.boot_info.get('secure_boot', 'Unknown')}")

        boot_entries = self.boot_info.get('boot_entries', [])
        print(f"Boot Entries Found: {len(boot_entries)}")

        esp_partitions = self.boot_info.get('esp_partitions', [])
        print(f"ESP Partitions: {len(esp_partitions)}")

        if self.errors:
            print(f"\n⚠️  Errors encountered: {len(self.errors)}")
            for error in self.errors:
                print(f"   • {error}")

        print("\n" + "=" * 60)

    def run_analysis(self, verbose=False, output_file=None):
        """Run complete UEFI boot analysis"""
        self.print_header()

        # Check if running with appropriate privileges
        if self.system in ["Windows", "Linux"] and os.geteuid != 0:
            print("⚠️  Note: Some features may require administrator/root privileges")
            print()

        # Perform analysis steps
        uefi_supported = self.check_uefi_support()

        if uefi_supported or verbose:
            self.analyze_boot_entries()
            self.check_secure_boot()
            self.analyze_esp_partition()

        # Generate and display results
        report = self.generate_report(output_file)
        self.print_summary()

        return report

def main():
    parser = argparse.ArgumentParser(description='UEFI Boot Analyzer - Analyze UEFI boot configuration')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output (analyze even if UEFI not detected)')
    parser.add_argument('-o', '--output', type=str,
                       help='Save analysis report to JSON file')
    parser.add_argument('--version', action='version', version='UEFI Boot Analyzer v1.0')

    args = parser.parse_args()

    try:
        analyzer = UEFIBootAnalyzer()
        analyzer.run_analysis(verbose=args.verbose, output_file=args.output)
    except KeyboardInterrupt:
        print("\n\n❌ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
