# NPA: Network Pentest Automation Framework

## Overview

NPA is a modular Python-based framework designed to automate common phases of network security assessments. It includes structured scope input, host discovery, port scanning, and a placeholder for vulnerability assessment. All components share a centralized state for consistency and traceability.

## Features

- **Scope Management:** Accepts IPs, CIDRs, domains, or URLs. Normalizes and expands targets.
- **Host Discovery:** Detects live hosts using multiple methods (ICMP, TCP SYN/ACK, UDP, NetBIOS, netcat).
- **Port Scanning:** Scans common and full port ranges using RustScan and Nmap. Service detection included.
- **Environment Setup:** Verifies tools, system requirements, and paths before execution.
- **State File:** Stores all metadata, alive status, ports, and scan results in a single file (`data/state.json`).
- **Atomic Writes:** Ensures file integrity via temp file replacement.

## Directory Structure

```
/NPA/
│
├── main.py                  # Entry point
├── config.py                # Global settings and directory paths
├── env_setup.py             # Environment validation and setup
├── scope_input.py           # Scope parsing and normalization
├── alive_checker.py         # Live host detection logic
├── port_scanner.py          # Port and service scan engine
├── data/
│   └── state.json           # Central live state file
├── alive/
│   ├── alive.txt            # Legacy output of alive IPs
│   └── scan_output/         # Outputs from fping/nmap/etc.
└── logs/
└── env_info.txt             # Environment diagnostics
```

## Setup Instructions

1. **Install Python ≥ 3.8**

2. **Run the main script:**
   ```bash
   python3 main.py
   ```

3. **The first phase verifies and prepares the environment:**

   * Validates Python version
   * Checks for:
     * `nmap`, `fping`, `nbtscan`, `netcat`, `jq`
     * `rustscan` (`~/.cargo/bin/rustscan`)
     * `naabu`, `nuclei` (`~/go/bin/`)
   * Prompts user to install missing tools
   * Validates disk space (≥ 2 GB)
   * Confirms write access to key directories
   * Saves system info to `logs/env_info.txt`
   * Records initialization details in `state.json`

4. **Subsequent phases:**
   * **Scope Input:** Manual or file-based entry
   * **Alive Detection:** Uses ICMP, TCP, UDP, NetBIOS, and netcat
   * **Port Scanning:** Performs common/full scans and service detection via Nmap

## Dependencies

Installed via apt:

```bash
sudo apt install -y nmap fping nbtscan netcat jq libpcap-dev cargo
```

Optional tools (installed manually if approved during setup):

```bash
cargo install rustscan
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

## Notes

* All scan results and metadata are written atomically.
* The system maintains backward compatibility with legacy file structures.
* Port scanning only begins after alive detection is successfully completed.
* Vulnerability scanning is not yet implemented but reserved in structure.

## License
MIT
