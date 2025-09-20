#!/usr/bin/python -tt
# Project: python_interop19
# Filename: basic_show.py
# claudiadeluna
# PyCharm

from __future__ import absolute_import, division, print_function

__author__ = "Claudia de Luna (claudia@indigowire.net)"
__version__ = ": 1.0 $"
__date__ = "9/20/25"
__copyright__ = "Copyright (c) 2023 Claudia"
__license__ = "Python"

import argparse
import logging
import netmiko
import time
import os


def main():

    # Setup logging
    timestr = time.strftime("%Y%m%d-%H%M%S")
    outdir = arguments.outdir
    if not os.path.exists(outdir):
        os.makedirs(outdir)
    outfile = arguments.outfile or os.path.join(outdir, f"show_{arguments.ip.replace('.', '-')}_{timestr}.log")
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s',
        handlers=[
            logging.FileHandler(outfile, mode='w'),
            logging.StreamHandler()
        ]
    )

    logging.info(f"Connecting to {arguments.ip} as {arguments.username}...")
    device = {
        'device_type': arguments.device_type,
        'ip': arguments.ip,
        'username': arguments.username,
        'password': arguments.password,
        'secret': arguments.enable,
    }
    try:
        conn = netmiko.ConnectHandler(**device)
        conn.enable()
        logging.info(f"Successfully connected to {arguments.ip}. Running command: {arguments.command}")
        output = conn.send_command(arguments.command, strip_prompt=False, strip_command=False)
        print("\n--- Device Output ---\n")
        print(output)
        logging.info("Show command output written above.")
        # Save output to a text file
        showfile = os.path.join(outdir, f"show_output_{arguments.ip.replace('.', '-')}_{time.strftime('%Y%m%d-%H%M%S')}.txt")
        with open(showfile, 'w') as f:
            f.write(output)
        logging.info(f"Show command output saved to {showfile}")
        conn.disconnect()
    except Exception as e:
        logging.error(f"Failed to connect or run command: {e}")
        exit(1)
    logging.info(f"Log output also saved to {outfile}\n\n")

# Standard call to the main() function.
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Script Description",
                                     epilog="Usage: ' python basic_show.py' ")

    parser = argparse.ArgumentParser(description="Run a show command on a device and log output to screen and file.")
    parser.add_argument("ip", help="IP address or FQDN of the device")
    parser.add_argument("command", help="Show command to run (wrap in quotes if it contains spaces)")
    parser.add_argument("-u", "--username", default="cisco", help="Username (default: cisco)")
    parser.add_argument("-p", "--password", default="cisco", help="Password (default: cisco)")
    parser.add_argument("-e", "--enable", default="cisco", help="Enable/secret password (default: cisco)")
    parser.add_argument("-d", "--device_type", default="cisco_ios", help="Netmiko device_type (default: cisco_ios)")
    parser.add_argument("-o", "--outfile", default=None, help="Output file (default: auto-named with device and timestamp)")
    parser.add_argument("--outdir", default="OUTPUT", help="Output directory for logs and show output (default: OUTPUT)")
    arguments = parser.parse_args()
    main()
