#!/usr/bin/env python3
# uefi_hex_explorer.py
"""
# UEFI Hex Explorer

**A lightweight utility for analyzing UEFI firmware dumps and inspecting low-level boot configuration data.**

---

### Metadata

- **Author:** dawciobiel
- **GitHub:** [https://github.com/dawciobiel](https://github.com/dawciobiel)
- **Date:** June 02, 2025
- **Version:** 1.0
- **License:** GPL (GNU General Public License)
- **Script Name:** `uefi_hex_explorer.py`

---

## 📌 Description

`uefi_hex_explorer.py` is a Python tool designed to analyze binary UEFI firmware dumps (e.g., `uefi_backup.bin`) and detect specific boot configuration areas, such as `Setup` sections and well-known UEFI boot variables (e.g., `SecureBoot`, `FastBoot`).

It provides:
- Hex and ASCII visualizations of firmware data near `Setup` markers.
- Basic detection of likely boot-related flag values.
- A lightweight method to inspect low-level firmware settings for reverse engineering, audit, or analysis.

---

## 🧠 Features

- Scans binary UEFI dump for `Setup` signatures.
- Displays hex and ASCII data near `Setup` sections.
- Heuristically interprets binary values for known flags (e.g., enabled/disabled).
- Searches for well-known UEFI variable names.
- Highlights values and byte offsets for easier reverse engineering.

---

## 🔧 Usage

### Requirements
- Python 3.x
- No additional libraries required

### Run the script:

```bash
python3 uefi_hex_explorer.py
````

Make sure a UEFI dump file (e.g., `uefi_backup.bin`) is present in the same directory.
"""

def find_boot_settings(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    print("=== Boot Settings Analysis ===\n")

    # 1. Find all occurrences of "Setup"
    setup_positions = []
    pos = 0
    while True:
        pos = data.find(b"Setup\x00", pos)
        if pos == -1:
            break
        setup_positions.append(pos)
        pos += 1

    print(f"Found {len(setup_positions)} Setup sections")

    # 2. Analyze data after each Setup section
    for i, setup_pos in enumerate(setup_positions):
        print(f"\n--- Setup Section #{i+1} at position 0x{setup_pos:08X} ---")

        # Search for data 100–200 bytes after "Setup"
        start = setup_pos + 10
        end = start + 200
        if end > len(data):
            end = len(data)

        setup_data = data[start:end]

        # Display as hex with ASCII interpretation
        print("Hex data (likely settings):")
        for j in range(0, min(100, len(setup_data)), 16):
            hex_part = " ".join(f"{b:02X}" for b in setup_data[j:j+16])
            ascii_part = "".join(chr(b) if 32 <= b < 127 else '.' for b in setup_data[j:j+16])
            print(f"{j:04X}: {hex_part:<48} |{ascii_part}|")

        # Check common positions for Fast Boot / Secure Boot
        analyze_boot_bytes(setup_data)

    # 3. Search for UEFI variables
    find_uefi_variables(data)

def analyze_boot_bytes(data):
    """Analyzes common positions where boot settings might be located"""
    print("\n--- Analysis of Probable Settings ---")

    # Check the first 50 bytes (usually main options are here)
    if len(data) >= 50:
        print("First 50 bytes (main settings):")
        for i in range(50):
            value = data[i]
            status = "ENABLED" if value == 1 else "DISABLED" if value == 0 else f"VALUE:{value}"
            print(f"  Byte {i:2d} (0x{i:02X}): {value:02X} = {status}")

def find_uefi_variables(data):
    """Searches for UEFI variables related to boot"""
    print("\n=== UEFI Variables ===")

    # Common UEFI variable names
    variables = [
        b"SecureBoot",
        b"FastBoot",
        b"QuietBoot",
        b"BootMode",
        b"CSMSupport",
        b"Setup"
    ]

    for var in variables:
        pos = data.find(var)
        if pos != -1:
            print(f"Found {var.decode()} at position 0x{pos:08X}")

            # Check a few bytes after the variable name
            if pos + len(var) + 10 < len(data):
                following_bytes = data[pos + len(var):pos + len(var) + 10]
                hex_str = " ".join(f"{b:02X}" for b in following_bytes)
                print(f"  Following bytes: {hex_str}")

if __name__ == "__main__":
    find_boot_settings("uefi_backup.bin")
