# Nihilist

Cisco IOS configuration analyzer for finding misconfigurations and vulnerabilities

![](/visuals/nihilist_card.png)

```
Nihilist: Cisco IOS Security Inspector
Author: Magama Bazarov, <magamabazarov@mailbox.org>
Alias: Caster
Version: 1.0
Codename: Gestalt
```

# Disclaimer

**Nihilist** is a security auditing tool designed for security engineers to assess the configuration of their own Cisco devices. Unauthorized use of this tool may be illegal.

Before use, make sure that you have permission to analyze device configurations. Use of this tool must comply with local laws and not violate the policies of the organizations that own the devices being tested.

## Important

- **Nihilist** is not designed to hack into Cisco devices and does not contain vulnerability exploitation features;
- This tool does not change the device configuration or perform destructive actions;
- The author of the tool is not liable for incorrect or illegal use of the tool;
- The tool works solely by reading the device configuration and does not make any changes. It does not require an account with maximum privileges (`privilege level 15`) to operate. It is sufficient to grant access only to execute show commands (read-only), which makes auditing as secure as possible;
- **Nihilist** uses SSH-only remote connectivity.

# Underlying Mechanism

**Nihilist** uses [netmiko](https://github.com/ktbyers/netmiko) to remotely connect to Cisco IOS devices via SSH. It executes Cisco IOS system commands to extract configuration data and analyze it for potential vulnerabilities and security issues.

The user connects to the device themselves using **Nihilist** by entering their credentials. The tool only executes commands to view the configuration and does not make any changes to the device settings. Thus, an account with read-only privileges is sufficient for Nihilist to work.

Nihilist does not use any exploits, malicious payloads or brute-force attacks. All security analysis is based solely on examining the device configuration.

# Nihilist Demo

![](/visuals/nihilist_demo.gif)

> Here is a demo of a Nihilist doing a security analysis of a Cisco router

# Security Checks

Nihilist performs a comprehensive security analysis, covering IOS security, link layer security, routing protocols, and redundancy protocols. It also supports router and L2/L3 switch analysis.

For more details and usage, check out the [dedicated page on the Wiki of this repository](https://github.com/casterbyte/Nihilist/wiki/Mechanism-of-the-tool)

# How to Use

To install the Nihilist:

```bash
:~$ sudo apt install git python3-colorama python3-netmiko
:~$ git clone https://github.com/casterbyte/Nihilist
:~$ cd Nihilist
:~/Nihilist$ sudo python3 setup.py install
:~$ nihilist --help

usage: nihilist.py [-h] --ip IP --username USERNAME --password PASSWORD [--port PORT] [--router] [--l2-switch] [--l3-switch]

options:
  -h, --help           show this help message and exit
  --ip IP              Specify the IP address of the device
  --username USERNAME  SSH Username
  --password PASSWORD  SSH Password
  --port PORT          SSH Port (default:22)
  --router             Specify if the device is a router
  --l2-switch          Specify if the device is a L2 switch
  --l3-switch          Specify if the device is a L3 switch
```

## Trigger Arguments (CLI Options)

**Nihilist** supports as input parameters:

- `--ip`: the user will need to specify the IP address of their device;
- `--username`: the username for SSH connection to the Cisco device;
- `--password`: the password for SSH connection to the Cisco device;
- `--port`: SSH port number, by default the tool uses port 22;
- `--router`: if the Cisco device is a router;
- `--l2-switch`: if it's a Cisco L2 switch;
- `--l3-switch`: if it's a Cisco L3 switch.

For example, here's how to run a security analysis on a Cisco router:

```bash
:~$ nihilist --ip 10.1.10.2 --username caster --password caster --port 2222 --router
```

> The data passed here as arguments are fictitious for illustrative purposes

# Tested Devices

When I developed Nihilist I tested it successfully on the following devices:

- Cisco ISR4321/K9, IOS-XE Software Version: `16.09.02`
- Cisco WS-C2960+24TC-L, Software Version: `15.2(2)E8`

# Copyright

Copyright (c) 2025 Magama Bazarov. This project is licensed under the Apache 2.0 License

This project is not affiliated with or endorsed by Cisco Systems, Inc.

# Outro

Cisco equipment is very common all over the world and security is a major issue.
With the release of this tool I just want to make the world a little better. Use it wisely and take care of the security of your infrastructure.

When I wrote this tool, I was inspired by the works of Friedrich Nietzsche and the release of this tool is my tribute to his writings.

E-mail for contact: magamabazarov@mailbox.org
