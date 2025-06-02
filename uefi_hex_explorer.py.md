````markdown
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

---

## 📂 File Structure

```text
uefi_hex_explorer.py
uefi_backup.bin      # <- Your binary firmware/UEFI dump
```

---

## 🧬 Function Overview

### `find_boot_settings(filename)`

* Reads the binary UEFI dump.
* Locates all `Setup` sections.
* Prints the hex + ASCII view of 100–200 bytes after each `Setup`.
* Calls subroutines to analyze boot flags and variables.

### `analyze_boot_bytes(data)`

* Interprets the first 50 bytes of a given section.
* Flags values `0x00` as **DISABLED**, `0x01` as **ENABLED**.
* Prints byte-level details to help understand boot flags.

### `find_uefi_variables(data)`

* Searches for UEFI variable names like:

  * `SecureBoot`
  * `FastBoot`
  * `QuietBoot`
  * `BootMode`
  * `CSMSupport`
* Displays their positions and next 10 bytes of data for inspection.

---

## 📘 Example Output

```
=== Boot Settings Analysis ===

Found 3 Setup sections

--- Setup Section #1 at position 0x00012F40 ---
Hex data (likely settings):
0000: 01 00 01 00 00 00 01 00 01 00 01 00 00 00 00 00 |................|
0010: 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
...
First 50 bytes (main settings):
  Byte  0 (0x00): 01 = ENABLED
  Byte  1 (0x01): 00 = DISABLED
...

=== UEFI Variables ===
Found SecureBoot at position 0x0009B2C8
  Following bytes: 01 00 00 00 00 00 00 00 00 00
```

---

## 📄 License

This project is licensed under the **GNU General Public License (GPL)**.
You are free to use, modify, and distribute this code under the terms of the GPL.

---

## 🤝 Contributions

Pull requests and suggestions are welcome!
Feel free to fork the project or open issues via [GitHub](https://github.com/dawciobiel).

```
