# Python Netmiko Starter Kit

<img src="images/image001.png" alt="image001" style="zoom:50%;" />

## Using uv for Python Environment Management

This repository was created using the [uv](https://github.com/astral-sh/uv) package manager, which provides fast dependency management and seamless virtual environment creation for Python projects.

### Benefits of Using uv
- **Automatic Virtual Environment Creation:**
  - `uv run` will automatically create and manage a `.venv` directory for your project if one does not exist.
- **Easy Script Execution:**
  - Run any script with all dependencies in place using:
    ```bash
    uv run python <scriptname.py>
    ```
    For example:
    ```bash
    uv run python get_showcmds.py
    ```
- **Dependency Management:**
  - All dependencies are tracked in `pyproject.toml`. To add or update dependencies, edit `pyproject.toml` and run:
    ```bash
    # add a new package directly
    uv pip install netmiko
    ```
  - After editing `pyproject.toml`, use `uv pip install -r requirements.txt` or `uv pip install <package>` to update your environment.
- **No Manual Virtualenv Activation Needed:**
  
  - Just use `uv run` and everything is handled for you.

---

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
