#!/usr/bin/python -tt
# Project: Dropbox (Indigo Wire Networks)
# Filename: ios_show_lab.py
# claudia
# PyCharm

__author__ = "Claudia de Luna (claudia@indigowire.net)"
__version__ = ": 1.0 $"
__date__ = "2019-04-13"
__copyright__ = "Copyright (c) 2018 Claudia"
__license__ = "Python"


import re
import os
import argparse
import time
from netmiko import ConnectHandler
from netmiko import NetMikoAuthenticationException
from netmiko.ssh_exception import NetMikoTimeoutException
from paramiko.ssh_exception import SSHException
import sys
import subprocess



def get_show_info(shlines):

    show_info_dict = {}
    outfileline = ''
    lhostname = ''
    inv_name = ''
    inv_desc = ''
    inv_pid = ''
    inv_vid = ''
    inv_sn = ''
    id_sn = ''
    swver = ''
    swimg = ''

    numshlines = len(shlines)

    for i in range(0, numshlines):

        # Look for the hostname
        if re.match("^hostname(.*)", shlines[i]) or re.match("^switchname(.*)", shlines[i]):
            host = shlines[i]
            host = host.rstrip()
            # split the hostname line into two variables
            host1 = host.split(" ")
            lhostname = host1[1]
            # print "Matched Hostname", lhostname
            # else:
            # lhostname = "Unable to parse out hostname!!"

        if re.search("Processor Board ID(.*)", shlines[i]):
            tmp = shlines[i].strip()
            tmp = shlines[i].split()
            id_sn = tmp[3]

        elif re.search("Motherboard serial number(.*)", shlines[i]):
            tmp = shlines[i].strip()
            tmp = shlines[i].split()
            id_sn = tmp[-1]


        elif re.search("Motherboard Serial Number(.*)", shlines[i]):
            tmp = shlines[i].strip()
            tmp = shlines[i].split()
            id_sn = tmp[-1]

        # Look for the version
        if re.match("Cisco IOS Software,(.*)", shlines[i]):
            swver = shlines[i]
            # print swver
            swver = swver.rstrip()
            swver = re.sub(',', ' ', swver)
            # swver1 = swver.split(',')
            # swios = swver1[1]
        else:
            if re.match("boot system flash", shlines[i]):
                swver = shlines[i]
                # print swver
                swver = swver.rstrip()
                swver1 = swver.split(' ')
                # print "SWVER1: ",swver1
                if len(swver1) > 3:
                    swios = swver1[3]
                elif len(swver1) < 2:
                    swios = swver1[2]
                else:
                    print("Can't parse Software Version")

        # Look for the version System image file is
        if re.match("^System image file is(.*)", shlines[i]):
            swimg = shlines[i]
            # print swimg
            swimg = swimg.rstrip()
            swimg1 = swimg.split('"')
            swimg = swimg1[1]
        else:
            if re.match("boot system flash", shlines[i]):
                swimg = shlines[i]
                # print swimg
                swimg = swimg.rstrip()
                swimg1 = swimg.split(' ')
                # swimg = swimg1[3]
                if len(swimg1) > 3:
                    swimg = swimg1[3]
                elif len(swimg1) < 2:
                    swimg = swimg[2]
                else:
                    print("Can't parse Software Image")

        if "NAME:" in shlines[i]:
            invlist = []
            # print shlines[i]
            # print shlines[i+1]
            invname = re.sub('\s+', ' ', shlines[i])
            invpid = re.sub('\s+', ' ', shlines[i + 1])
            invname = re.sub('"', ' ', shlines[i])
            invpid = re.sub('"', ' ', shlines[i + 1])
            # print invname
            # print invpid
            invlist.append(invname)
            invlist.append(invpid)

            # NAME: "VG224 chassis", DESCR: "VG224 chassis"
            # PID: VG224             , VID: V06, SN: FTX1535ALU6

            # Split the first line, NAME, into a two list element, each with two items which can be split on :
            invnametmp = invname.split(",")
            # if the inventory name line split into two entries
            if len(invnametmp) == 2:
                # Split the first entry, 0, at the : so as to get NAME : inv_name
                tmp = invnametmp[0].split(":")
                # The name information is the second element of the tmp list, strip it, and put it int inv_name
                inv_name = tmp[1].rstrip()
                tmp1 = invnametmp[1].split(":")
                # The desc information is the second element of the tmp list, strip it, and put it int inv_desc
                inv_desc = tmp1[1].rstrip()

            elif len(invnametmp) == 3:
                tmp = invnametmp[0].split(":")
                # The name information is the second element of the tmp list, strip it, and put it int inv_name
                inv_name = tmp[1].rstrip()
                tmp1 = invnametmp[1].split(":")
                # The desc information is the second element of the tmp list, strip it, and put it int inv_desc
                inv_desc = tmp1[1].rstrip()
            else:
                print("Inventory NAME: ", invnametmp)
                inv_name = "Unexpected number of entries in the NAME: row: %d" % (len(invnametmp))

            invpidtmp = invpid.split(",")
            # if the inventory name line split into two entries
            if len(invpidtmp) == 3:
                # Split the first entry, 0, at the : so as to get NAME : inv_name
                tmp = invpidtmp[0].split(":")

                # The pid information is the first element of the tmp list, strip it, and put it int inv_pid
                inv_pid = tmp[1].rstrip()
                tmp1 = invpidtmp[1].split(":")
                # The vid information is the second element of the tmp list, strip it, and put it int inv_vid
                inv_vid = tmp1[1].rstrip()
                tmp2 = invpidtmp[2].split(":")
                # The serial number information is the third element of the tmp list, strip it, and put it int inv_sn
                inv_sn = tmp2[1].rstrip()
                # print inv_desc
            elif len(invpidtmp) == 9:
                inv_sn = invpidtmp[7]



            else:
                #print "Inventory PID: ", invpidtmp
                inv_pid = "Unexpected number of entries in the PID: row: %d" % (len(invpidtmp))


    outfileline = lhostname + "," + inv_name + "," + inv_desc + "," + inv_pid + "," + inv_vid + "," + inv_sn + "," + swver + "," + swimg + "," + "\n"

    show_info_dict['hostname'] = lhostname.strip()
    #show_info_dict['NAME'] = inv_name.strip()
    #show_info_dict['DESCR'] = inv_desc.strip()
    #show_info_dict['PID'] = inv_pid.strip()
    #show_info_dict['VID'] = inv_vid.strip()
    show_info_dict['SN'] = id_sn.strip()
    show_info_dict['Version'] = swver.strip()
    show_info_dict['Image'] = swimg.strip()

    return show_info_dict


def load_txt_file(txtfilename):

    comment_symbols = ["#", "!"]
    valid_lines = []
    # Saving comments in file for future use
    comments = []

    try:
        f = open(txtfilename)

    except Exception as e:
        # print("Ooops Error:", sys.exc_info()[0], sys.exc_info()[1])
        print(str(e))
        sys.exit("Aborting Program Execution!  Please verify file.")

    else:
        file_contents = f.readlines()
        #print file_contents
        for line in file_contents:
            if len(line.strip()) != 0:
                if line.strip()[0] not in comment_symbols:
                    # Add regexp for IP address format check
                    valid_lines.append(line.strip())
                else:
                    comments.append(line.strip())

    return valid_lines


def missing_device_log(missing_list, ip, note):

    entry = ip + "  -  " + str(note)

    if entry not in missing_list:
        missing_list.append(entry)

    return missing_list


def ping_device(ip):

    pings = False

    local_os = os_is()

    ## Ping with -c 3 on Linux or -n 3 on windows
    if local_os == 'linux':
        ping_count = "-c"
    else:
        ping_count = "-n"

    device_pings = False
    output = subprocess.Popen(['ping', ping_count, '3', '-W', '500', ip], stdout=subprocess.PIPE
                              ).communicate()[0]

    #print output
    if "Destination host unreachable" in output.decode('utf-8'):
        print(f"{ip} is Offline. Destination unreachable.")
    elif "TTL expired in transit" in output.decode('utf-8'):
        print(f"{ip} is not reachable. TTL expired in transit.")
    elif "Request timed out" in output.decode('utf-8'):
        print(f"{ip} is Offline. Request timed out.")
    else:
        #print(f"{ip} is Online")
        pings = True

    return pings


def os_is():
    # Determine OS to set ping arguments
    local_os = ''
    if sys.platform == "linux" or sys.platform == "linux2":
        local_os = 'linux'
    elif sys.platform == "darwin":
        local_os = 'linux'
    elif sys.platform == "win32":
        local_os = 'win'

    return local_os





# Provided main() calls the above functions
def main():
    """

    The ios_show_lab.py script is a discovery script which takes in a list of ip addresses and a project name as mandatory
    command line arguments and attempts to log in to one or more devices in the list of ips and extract and save the
    output of a set of show commands.
    Both the default login credentials and list of show commands can be overriden via optional command line
    arguments.
    The script also provides a "ping only" option to test reachability only.

    """

    ip_filename = arguments.ip_file.strip()

    # Set project directory to 'logs' unless an optional directory was given
    if arguments.project_dir:
        project = arguments.project_dir
    else:
        project = 'logs'

    if arguments.device_class:
        device_cls = arguments.device_class.strip()
    else:
        # Default device class for Netmiko
        device_cls = 'cisco_ios'

    ips = []
    ips = load_txt_file(ip_filename)

    total_devices = len(ips)
    # Track devices which fail login or pings
    missing_devices = []
    # Track devices which were successfully accessed
    devices_verified = 0

    # Create Directory for show output based on the Project Name
    path = os.path.join("./", project.strip())
    # print path
    if not os.path.exists(path):
        os.makedirs(path)
        print(f"Created directory: {path}")

    # Create logfile for the discovery run in same directory as the resulting show commands
    # logfilename = project + "-logfile.log"
    # logfilename = os.path.join(path, logfilename)

    if total_devices > 1:
        heading = f"##### Executing show commands for discovery project {project} for {str(total_devices)} devices! #####"
    else:
        heading = f"##### Executing show commands for discovery project {project} for {str(total_devices)} device! #####"

    print("#" * len(heading))
    print(heading)
    print("#" * len(heading))

    print(f"Device IP(s) in project {project}:")
    for i in ips:
        print(f"\t{i}")
    print("--------------------------")
    print(f"Total devices: {str(len(ips))}")
    print("#" * len(heading))
    print("\n")

    ## Default Credentials
    # Default list of credentials in format username, user password, enable password
    credentials = ['cisco, cisco, cisco']

    ## Load Credentials if -c or --creds option was used
    if arguments.creds:
        # Override default credentials as a new credential file with one or more sets of credentials was provided
        cred_filename = arguments.creds
        credentials = load_txt_file(cred_filename)

    ##### SHOW COMMANDS
    commands = []

    ## Load custom show commands if -c or --show option was used
    if arguments.show:
        # Override default list of show commands as a new file with one or more show commands was provided
        show_filename = arguments.show
        custom_showcmds = load_txt_file(show_filename)

        # first command to send is an end to get back to the main prompt
        commands = custom_showcmds

    else:
        # DEFAULT SHOW COMMANDS
        commands = ["show version",
                    ]

    # if not arguments.pingonly:
    #     print("Sending " + str(len(commands)) + " show commands:")
    #     for x in range(0, len(commands)):
    #         print("\t" + commands[x])

    # For each IP in the ip address file, attempt to ping, attempt to log in, attempt to enter enable mode and
    # execute and save show command output
    for mgmt_ip in ips:

        login_success = False
        enable_success = False
        output = ''
        hostname = "dev_" + mgmt_ip

        # If Ping is successful attempt to log in and if that is successful attempt to enter enable mode and
        # execute list of show commands
        device_pings = ping_device(mgmt_ip)

        if device_pings:
            print(f"Device {mgmt_ip} Responds to Pings!\n")

             # If the -i or --icmppingonly option was provided when the script was called, then only execute the ping code.
            if arguments.icmppingonly:
                # Keep a count of the devices that are pingable
                devices_verified += 1
                # Skip everything else as the icmp ping only option was given
                continue

            if len(credentials) > 1:
                print("**** Attempting multiple credentials to access device....")

            try_telnet = False
            # Credential Loop
            for line in credentials:

                lineitem = line.split(',')
                uname = lineitem[0].strip()
                upwd = lineitem[1].strip()
                epwd = lineitem[2].strip()

                if not try_telnet:

                    print(f"\t**** Attempting user credentials for {uname} with SSH.")

                    try:
                        dev_conn = ConnectHandler(device_type=device_cls, ip=mgmt_ip, username=uname, password=upwd,
                                                  secret=epwd)
                        login_success = True


                    except NetMikoAuthenticationException:
                        print(f"\tNetMikoAuthenticationException: Device failed SSH Authentication with username {uname}")
                        missing_devices = missing_device_log(missing_devices, mgmt_ip, 'Failed Authentication')
                        login_success = False
                        # continue

                    except (EOFError, SSHException, NetMikoTimeoutException):
                        print('\tSSH is not enabled for this device.')
                        missing_devices = missing_device_log(missing_devices, mgmt_ip, 'Failed SSH')
                        login_success = False
                        try_telnet = True
                        # continue

                    except Exception as e:
                        print("\tGeneral Exception: ERROR!:" + str(sys.exc_info()[0]) + "==>" + str(sys.exc_info()[1]))
                        print(str(e))
                        missing_devices = missing_device_log(missing_devices, mgmt_ip, 'General Exception')
                        login_success = False
                        # continue

                    if login_success:
                        print("\t**** SSH Login Succeeded! Will not attempt login with any other credentials.")
                        # Break out of credential loop
                        break
                    else:
                        print("\t**** SSH Login Failed!")
                        # continue

                # Try Telnet
                if try_telnet:
                    print("\t**** Attempting user credentials for " + uname + " with Telnet.")

                    try:
                        dev_conn = ConnectHandler(device_type='cisco_ios_telnet', ip=mgmt_ip, username=uname,
                                                  password=upwd,
                                                  secret=epwd)
                        login_success = True

                    except NetMikoAuthenticationException:
                        print(f"\tNetMikoAuthenticationException: Device failed SSH Authentication with username {uname}")
                        missing_devices = missing_device_log(missing_devices, mgmt_ip, 'Failed Authentication')
                        login_success = False
                        continue

                    except Exception as e:
                        print("\tGeneral Exception: ERROR!:" + str(sys.exc_info()[0]) + "==>" + str(sys.exc_info()[1]))
                        print(str(e))
                        missing_devices = missing_device_log(missing_devices, mgmt_ip, 'General Exception')
                        login_success = False
                        continue

                    if login_success:
                        print("\t**** Telnet Login Succeeded! Will not attempt login with any other credentials.")
                        # Break out of credential loop
                        break
                    else:
                        print("\t**** Telnet Login Failed!")
                        continue

            if login_success:
                # Check to see if login has resulted in enable mode (i.e. priv level 15)
                is_enabled = dev_conn.check_enable_mode()

                if not is_enabled:
                    try:
                        dev_conn.enable()
                        enable_success = True
                    except Exception as e:
                        print(str(e))
                        print("\tCannot enter enter enable mode on device!")
                        missing_devices = missing_device_log(missing_devices, mgmt_ip, 'failed enable')
                        enable_success = False
                        continue
                else:
                    print("\tDevice already in enabled mode!")
                    enable_success = True

            if enable_success:

                for cmd in commands:
                    output += dev_conn.send_command(cmd, strip_prompt=False, strip_command=False)
                dev_conn.exit_config_mode()
                dev_conn.disconnect()

                # output contains a stream of text vs individual lines
                # split into individual lies for further parsing
                # output_lines = re.split(r'[\n\r]+', output)

                # show_info = get_show_info(output_lines)
                #
                # if show_info['hostname']:
                #     hostname = show_info.pop('hostname')

                # print("Information for device: " + hostname)
                # for k, v in show_info.items():
                #     print("\t" + k +"\t\t-\t" + v)

                # Save output to file
                timestr = time.strftime("%Y%m%d-%H%M%S")

                log_filename = hostname + "-" + timestr + ".txt"
                log_filename = os.path.join(path, log_filename)

                log_file = open(log_filename, 'w')
                log_file.write("!#Output file for device " + hostname + "\n")
                log_file.write("!#Commands executed on " + timestr + "\n\r")
                log_file.write("!\n")
                log_file.write(output)
                log_file.close()
                devices_verified += 1
                print("\nOutput results saved in: " + log_filename + "\n\n")


        else:
            # Device does not PING
            print("Device is unreachable")
            missing_devices.append(mgmt_ip)

    # Totals Verification
    if arguments.icmppingonly:
        info = ("Total number of devices in IP list:\t\t" + str(total_devices) + "\n",
                "Total number of devices which responded to pings:\t" + str(devices_verified) + "\n")
    else:
        info = ("Total number of devices in IP list:\t\t" + str(total_devices) + "\n",
                "Total number of show command output files:\t" + str(devices_verified) + "\n")


    # Print Note on totals
    for note in info:
        print(note)



# Standard call to the main() function.
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Discovery Script: Get show commands, test reachability, and validate IOS from list of one or more IPs",
                                     epilog="Usage: 'python ios_show_lab.py  <ip_filname> <project_name>")

    parser.add_argument('ip_file', help='Name of the file in the curent working directory containing one or more IPs on which to run show commands.')
    parser.add_argument('-p', '--project_dir', help='Name (no spaces) of the project and directory in which to store the output of the show commands. ')
    parser.add_argument('-s', '--show', help='Name of the file in the current directory containing show commands to override the default show commands.')
    parser.add_argument('-c', '--creds', help='Name of the file in the current directory containing credentials to override the default credentials.')
    parser.add_argument('-i', '--icmppingonly', help='Test device reachability only', action='store_true', default=False)
    parser.add_argument('-d', '--device_class', help='Class of device software. Default value is cisco_ios. Valid values include cisco_ios | cisco_ios_telnet | cisco_nxos ')

    arguments = parser.parse_args()
    main()
