# Python Netmiko Starter Kit

This repository provides a simple yet powerful starter kit for using [Netmiko](https://github.com/ktbyers/netmiko) to automate the collection of "show" command outputs from network devices. It is ideal for network engineers and automation beginners who want to quickly gather device information for discovery or documentation purposes.

## Features

- **Single Device Basics:**
  - `basic_show.py` demonstrates how to connect to an individual device and run a single show command.
- **Multi-Device, Multi-Command Automation:**
  - `get_showcmds.py` is a more advanced script that can:
    - Read a list of device IPs/hostnames from a file
    - Read a list of show commands from a file
    - Connect to each device and execute all specified commands
    - Save the output for each device/command combination
- **Flexible Input:**
  - Supports input files for both device inventory and command lists, making it easy to scale up discovery tasks.

## Use Cases
- Initial network discovery
- Device inventory and documentation
- Bulk configuration validation
- Troubleshooting and diagnostics

## Getting Started

### Prerequisites
- Python 3.7+
- Install dependencies:
  ```bash
  pip install netmiko
  ```

### Usage

#### 1. Run a Show Command on a Single Device
Edit `basic_show.py` to specify your device credentials and desired show command, then run:
```bash
python basic_show.py
```

#### 2. Run Multiple Show Commands on Multiple Devices
Prepare:
- A text file with device IPs/hostnames (e.g., `lab_ip.txt`)
- A text file with show commands (e.g., `showcmds.txt`)
- A credentials file (e.g., `creds.txt`)

Then run:
```bash
python get_showcmds.py
```
Outputs will be saved to the `OUTPUT/` directory.

## File Overview
- `basic_show.py` — Simple example for one device
- `get_showcmds.py` — Advanced script for multiple devices and commands
- `lab_ip.txt`, `lg_ip.txt`, `sbx_ip.txt` — Example device lists
- `creds.txt` — Example credentials file (format: see script comments)
- `OUTPUT/` — Directory for collected outputs

## Why Use This Kit?
This type of script is extremely handy for initial network discovery, quickly gathering information from a large number of devices, and automating repetitive network management tasks.

---

Feel free to fork, modify, and extend this starter kit for your own automation projects!
