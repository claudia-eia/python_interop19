
## Sample Python Script for Cisco IOS Discovery ##

The scripts contained within this repository are examples only.  They are intended to illustrate some basic usage. 


```

root@977934fdd07c:/ansible/python_interop19# python3 ios_show_lab.py -h
usage: ios_show_lab.py [-h] [-p PROJECT_DIR] [-s SHOW] [-c CREDS] [-i]
                       [-d DEVICE_CLASS]
                       ip_file

Discovery Script: Get show commands, test reachability, and validate IOS from
list of one or more IPs

positional arguments:
  ip_file               Name of the file in the curent working directory
                        containing one or more IPs on which to run show
                        commands.

optional arguments:
  -h, --help            show this help message and exit
  -p PROJECT_DIR, --project_dir PROJECT_DIR
                        Name (no spaces) of the project and directory in which
                        to store the output of the show commands.
  -s SHOW, --show SHOW  Name of the file in the current directory containing
                        show commands to override the default show commands.
  -c CREDS, --creds CREDS
                        Name of the file in the current directory containing
                        credentials to override the default credentials.
  -i, --icmppingonly    Test device reachability only
  -d DEVICE_CLASS, --device_class DEVICE_CLASS
                        Class of device software. Default value is cisco_ios.
                        Valid values include cisco_ios | cisco_ios_telnet |
                        cisco_nxos

Usage: 'python ios_show_lab.py <ip_filname> 
root@977934fdd07c:/ansible/python_interop19#

```


