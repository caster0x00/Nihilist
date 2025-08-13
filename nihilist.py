# Copyright (c) 2025 Magama Bazarov
# Licensed under the Apache 2.0 License
# This project is not affiliated with or endorsed by Cisco Systems, Inc.

import argparse
import re
import datetime
import sys
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException
from colorama import Fore, Style

# This is banner
def banner():
    banner_text = r"""
 _______  .__.__    .__.__  .__          __   
 \      \ |__|  |__ |__|  | |__| _______/  |_ 
 /   |   \|  |  |  \|  |  | |  |/  ___/\   __\
/    |    \  |   Y  \  |  |_|  |\___ \  |  |  
\____|__  /__|___|  /__|____/__/____  > |__|  
        \/        \/                \/        
"""
    banner_text = "    " + banner_text.replace("\n", "\n    ")
    print(banner_text)
    print("    " + Fore.YELLOW + "Nihilist: Cisco IOS Security Inspector" + Style.RESET_ALL)
    print("    " + Fore.YELLOW + "Author: " + Style.RESET_ALL + "Magama Bazarov, <magamabazarov@mailbox.org>")
    print("    " + Fore.YELLOW + "Alias: " + Style.RESET_ALL + "Caster")
    print("    " + Fore.YELLOW + "Version: " + Style.RESET_ALL + "1.0")
    print("    " + Fore.YELLOW + "How to Use: " + Style.RESET_ALL + "https://github.com/caster0x00/Nihilist")
    print("    " + Fore.YELLOW + "Detailed Documentation: " + Style.RESET_ALL + "https://github.com/caster0x00/Nihilist/wiki/Mechanism-of-the-tool\n")
    print("    " + Fore.MAGENTA + "❝He who fights with monsters should look to it that he himself does not become a monster❞")
    print("    " + Fore.MAGENTA + "— Friedrich Nietzsche, 1886\n" + Style.RESET_ALL)

# Connect to the Cisco IOS
def connect_to_device(ip, username, password, port, device_type):
    print(Fore.WHITE + f"[*] Running on Python {sys.version.split()[0]}" + Style.RESET_ALL)
    device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": username,
        "password": password,
        "port": port,
        "timeout": 10,
    }
    try:
        print(Fore.GREEN + f"[*] Connecting to {device_type} at {ip}:{port}..." + Style.RESET_ALL)
        connection = ConnectHandler(**device)
        print(Fore.WHITE + "[*] Connection successful!\n" + Style.RESET_ALL)
        return connection
    except NetmikoAuthenticationException:
        print(Fore.RED + "[-] Authentication failed! Check your credentials." + Style.RESET_ALL)
        exit(1)
    except NetmikoTimeoutException:
        print(Fore.RED + "[-] Connection timed out! Check device availability." + Style.RESET_ALL)
        exit(1)
    except Exception as e:
        print(Fore.RED + f"[-] Connection failed: {e}" + Style.RESET_ALL)
        exit(1)

# Simple separator
def print_separator():
    print(Fore.WHITE + Style.BRIGHT + "=" * 50 + Style.RESET_ALL)

# Display Uptime
def check_device_uptime(connection):
    try:
        # Execute command to get device uptime
        output = connection.send_command("show version | include uptime")

        # Match the hostname and uptime from the output
        match = re.match(r'(\S+) uptime is (.+)', output)

        if match:
            hostname, uptime = match.groups()
            print(Fore.GREEN + "[*] Device " + Fore.WHITE + f"'{hostname}'" + Fore.GREEN + f" Uptime: {uptime}" + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "[!] Unable to parse device uptime." + Style.RESET_ALL)

    except Exception as e:
        # Handle any errors during command execution
        print(Fore.RED + f"[-] Failed to retrieve uptime: {e}" + Style.RESET_ALL)

# Checking Configuration Size
def checking_config_size(connection): 
    try:
        # Retrieve the configuration size from running config
        config_size_output = connection.send_command("show running-config | include Current configuration").strip()
        
        # Extract the configuration size using regex
        match = re.search(r"Current configuration : (\d+) bytes", config_size_output)
        if match:
            config_size = int(match.group(1))
            print(Fore.GREEN + "[*] Configuration size: " + Fore.WHITE + f"{config_size} bytes" + Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] WARNING: Unable to determine configuration size." + Style.RESET_ALL)

    except Exception as e:
        # Handle errors during command execution
        print(Fore.RED + f"[-] Failed to retrieve configuration size: {e}" + Style.RESET_ALL)

# PAD Status
def checking_pad_service(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking PAD Service (X.25)..." + Style.RESET_ALL)

    try:
        # Retrieve the current PAD service configuration from running config
        pad_config = connection.send_command("show running-config | include service pad").strip()
    except Exception as e:
        # Handle errors if the command fails
        print(Fore.RED + f"[-] Failed to retrieve PAD configuration: {e}" + Style.RESET_ALL)
        return

    # Check if PAD service is explicitly disabled
    if 'no service pad' in pad_config:
        print(Fore.GREEN + "[OK] PAD service explicitly disabled ('no service pad')." + Style.RESET_ALL)
    
    # Check if PAD service is enabled, which is a potential security risk
    elif 'service pad' in pad_config:
        print(Fore.RED + "[!] WARNING: 'service pad' is enabled. Attackers could exploit PAD (X.25) for unauthorized access." + Style.RESET_ALL)
    
    # If no explicit setting is found, assume PAD is disabled by default
    else:
        print(Fore.GREEN + "[OK] PAD service is disabled by default." + Style.RESET_ALL)

# Checking service password-encryption
def checking_service_password_encryption(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking Password Protection Policy" + Style.RESET_ALL)
    
    try:
        # Retrieve the full running configuration
        config = connection.send_command("show running-config")
    except Exception as e:
        # Handle errors if the command fails
        print(Fore.RED + f"[-] Failed to retrieve configuration: {e}" + Style.RESET_ALL)
        return

    # Check if 'service password-encryption' is present and not explicitly disabled
    service_encryption_match = re.search(r"(?<!no )service password-encryption", config)

    if service_encryption_match:
        # Warn if weak encryption is enabled
        print(Fore.YELLOW + "[!] WARNING: 'service password-encryption' is enabled!" + Style.RESET_ALL)
        print(Fore.YELLOW + "    - This feature encrypts plaintext passwords using a weak Vigenère cipher (Type 7)" + Style.RESET_ALL)
        print(Fore.YELLOW + "    - Consider using 'secret' instead of 'password' for stronger encryption (Type 8 or 9)" + Style.RESET_ALL)
    else:
        # Confirm that weak encryption is disabled, advising proper password hashing
        print(Fore.GREEN + Style.BRIGHT + "[OK] The 'service password-encryption' function is disabled. When you create accounts, define the password hashing algorithm yourself with 'algorithm-type'" + Style.RESET_ALL)

# Checking Password Hashing (type4/5/7/8/9)
def checking_password_hashing(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking hashing of account passwords" + Style.RESET_ALL)
    
    try:
        # Retrieve the full running configuration
        config = connection.send_command("show running-config")
    except Exception as e:
        # Handle errors if the command fails
        print(Fore.RED + f"[-] Failed to retrieve configuration: {e}" + Style.RESET_ALL)
        return

    # Extract usernames and their password hashing types from the config
    password_hashes = re.findall(r'username\s+(\S+)\s+(?:privilege\s+\d+\s+)?(password|secret)\s+(\d+)', config)

    if password_hashes:
        for user, method, hash_type in password_hashes:
            # Type 7 passwords use a weak Vigenère cipher (easily reversible)
            if hash_type == "7":
                print(Fore.RED + f"[!] WARNING: User '{user}' uses weak Type 7 password encryption (easily reversible)" + Style.RESET_ALL)
            # Type 4 passwords are deprecated and considered insecure
            elif hash_type == "4":
                print(Fore.RED + f"[!] WARNING: User '{user}' uses Type 4 password (deprecated, insecure)" + Style.RESET_ALL)
            # Type 5 passwords use MD5 hashing, which is outdated and vulnerable to attacks
            elif hash_type == "5":
                print(Fore.YELLOW + f"[*] CAUTION: User '{user}' uses Type 5 password (better than type 7 but still outdated)" + Style.RESET_ALL)
            # Type 8 passwords use PBKDF2, which provides strong encryption
            elif hash_type == "8":
                print(Fore.GREEN + f"[OK] User '{user}' uses Type 8 PBKDF2 password (strong encryption)" + Style.RESET_ALL)
            # Type 9 passwords use SCRYPT, which is currently the most secure option
            elif hash_type == "9":
                print(Fore.GREEN + f"[OK] User '{user}' uses Type 9 SCRYPT password (the strongest, hardest to crack)" + Style.RESET_ALL)

# Checking RBAC
def checking_rbac(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking RBAC" + Style.RESET_ALL)

    try:
        # Retrieve the full running configuration
        config = connection.send_command("show running-config")
    except Exception as e:
        # Handle errors if the command fails
        print(Fore.RED + f"[-] Failed to retrieve configuration: {e}" + Style.RESET_ALL)
        return

    # Extract usernames and their privilege levels from the config
    users = re.findall(r'username\s+(\S+)(?:\s+privilege\s+(\d+))?', config)

    if users:
        # Display a warning about configured users and their privilege levels
        print(Fore.YELLOW + "[!] List of configured users and their privilege levels:" + Style.RESET_ALL)
        for user, privilege in users:
            # If no privilege level is explicitly set, assume default (1)
            privilege_level = privilege if privilege else "default (1)"
            print(Fore.YELLOW + "    - User '" + Fore.WHITE + f"{user}" + Fore.YELLOW + "' has privilege level: " + Fore.WHITE + f"{privilege_level}" + Style.RESET_ALL)

        # Security warning regarding high-privilege accounts
        print(Fore.YELLOW + Style.BRIGHT + "[!] Watch who you give high privileges to in the system!" + Style.RESET_ALL)
    else:
        # If no user accounts are found in the configuration, assume secure state
        print(Fore.GREEN + Style.BRIGHT + "[OK] No user accounts found in the configuration." + Style.RESET_ALL)

# Checking VTP
def checking_vtp_status(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking VTP Operation" + Style.RESET_ALL)

    try:
        # Retrieve the current VTP status
        vtp_status = connection.send_command("show vtp status")
    except Exception as e:
        # Handle errors if the command fails
        print(Fore.RED + f"[-] Failed to retrieve VTP status: {e}" + Style.RESET_ALL)
        return

    # Extract the VTP operating mode from the output
    match = re.search(r'VTP Operating Mode\s+:\s+(\S+)', vtp_status)

    if match:
        vtp_mode = match.group(1).strip()
        
        # Secure modes: "Off" or "Transparent" prevent VTP attacks
        if vtp_mode.lower() in ["off", "transparent"]:
            print(Fore.GREEN + f"[OK] VTP is running in a secure mode ({vtp_mode})" + Style.RESET_ALL)
        else:
            # Warn if VTP is in Server or Client mode, as it can introduce security risks
            print(Fore.YELLOW + f"[!] WARNING: VTP is active and operating in '{vtp_mode}' mode." + Style.RESET_ALL)
            print(Fore.YELLOW + "    - VTP may be vulnerable to unauthorized VLAN modifications." + Style.RESET_ALL)
            print(Fore.YELLOW + "    - Consider setting it to 'Transparent' or 'Off' if not needed." + Style.RESET_ALL)
    else:
        # Handle cases where VTP mode is not found in the output
        print(Fore.RED + "[-] Failed to determine VTP mode." + Style.RESET_ALL)

# Checking DTP
def checking_dtp_status(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking DTP Operation" + Style.RESET_ALL)

    try:
        # Retrieve the DTP status for all interfaces
        dtp_output = connection.send_command("show dtp interface")
    except Exception as e:
        # Handle errors if the command fails
        print(Fore.RED + f"[-] Failed to retrieve DTP status: {e}" + Style.RESET_ALL)
        return

    # Extract interface names where DTP is active
    dtp_interfaces = re.findall(r"DTP information for (\S+):", dtp_output)
    
    # Extract DTP negotiation status (TOS/TAS/TNS: Mode)
    dtp_statuses = re.findall(r"TOS/TAS/TNS:\s+\S+/(\S+)/\S+", dtp_output)

    if not dtp_interfaces or not dtp_statuses:
        # If the regex didn't match expected patterns, output is unexpected or empty
        print(Fore.RED + "[-] Unable to parse DTP status output!" + Style.RESET_ALL)
        return

    active_dtp_interfaces = []
    
    # Identify interfaces where DTP is still in auto-negotiation mode
    for iface, status in zip(dtp_interfaces, dtp_statuses):
        if status.lower() == "auto":
            active_dtp_interfaces.append(iface)

    if active_dtp_interfaces:
        # Warn if any interfaces have DTP enabled
        print(Fore.YELLOW + "[!] WARNING: DTP is enabled on the following interfaces:" + Style.RESET_ALL)
        for iface in active_dtp_interfaces:
            print(Fore.YELLOW + f"    - {iface}" + Style.RESET_ALL)
        
        # Highlight the security risk of VLAN hopping via DTP
        print(Fore.RED + "[!] DTP can be exploited for VLAN hopping attacks. Consider disabling it!" + Style.RESET_ALL)
    else:
        # Confirm that DTP is disabled on all interfaces
        print(Fore.GREEN + "[OK] DTP is disabled on all interfaces." + Style.RESET_ALL)

# Checking Native VLAN Settings
def checking_native_vlan(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking Native VLAN Configuration" + Style.RESET_ALL)

    try:
        # Retrieve the trunk interface configuration
        trunk_output = connection.send_command("show interfaces trunk").strip()
    except Exception as e:
        # Handle errors if the command fails
        print(Fore.RED + f"[-] Failed to retrieve Native VLAN configuration: {e}" + Style.RESET_ALL)
        return

    native_vlan_ports = []
    
    # Parse trunk interface details and extract the native VLAN assignments
    for line in trunk_output.splitlines():
        match = re.search(r'(\S+)\s+\S+\s+\S+\s+\S+\s+(\d+)', line)
        if match:
            port, native_vlan = match.groups()
            # Identify ports where VLAN 1 is used as the Native VLAN
            if native_vlan == "1":
                native_vlan_ports.append(port)

    if native_vlan_ports:
        # Warn if VLAN 1 is set as the Native VLAN on any trunk ports
        print(Fore.YELLOW + "[!] WARNING: The following trunk ports allow VLAN 1 as Native VLAN:" + Style.RESET_ALL)
        for port in native_vlan_ports:
            print(Fore.YELLOW + f"    - {port}" + Style.RESET_ALL)
        
        # Highlight the security risk of VLAN hopping due to Native VLAN 1
        print(Fore.RED + "[!] VLAN 1 as Native VLAN can lead to VLAN hopping attacks. Change it using 'switchport trunk native vlan <VLAN>'." + Style.RESET_ALL)
    else:
        # Confirm that VLAN 1 is not used as the Native VLAN on any trunk ports
        print(Fore.GREEN + "[OK] No trunk ports are using VLAN 1 as the Native VLAN." + Style.RESET_ALL)

# Checking CDP
def checking_cdp(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking CDP Operation" + Style.RESET_ALL)

    try:
        # Enable privileged EXEC mode
        connection.enable()
        
        # Disable terminal paging for uninterrupted output
        connection.send_command("terminal length 0")  
        
        # Retrieve CDP status for all interfaces
        cdp_output = connection.send_command("show cdp interface")
    except Exception as e:
        # Handle errors if the command fails
        print(Fore.RED + f"[-] Failed to retrieve CDP status: {e}" + Style.RESET_ALL)
        return

    # Regex pattern to extract all interface blocks
    pattern = re.compile(
        r'(?P<intf>\S+)\s+is\s+(?:up|down),\s+line\s+protocol\s+is\s+(?:up|down)\n'
        r'(?:\s+.*\n)*?',
        re.MULTILINE
    )

    all_blocks = pattern.findall(cdp_output)
    cdp_enabled_interfaces = []

    # Regex pattern to match CDP-enabled interfaces
    block_pattern = re.compile(
        r'(?P<block>(?P<intf>\S+)\s+is\s+(?:up|down),\s+line\s+protocol\s+is\s+(?:up|down)\n'
        r'(?:\s+.*\n)*?)'
        r'(?=\S+\s+is\s+(?:up|down),|$)',
        re.MULTILINE
    )
    
    # Iterate through all detected blocks and check if CDP is active
    blocks = block_pattern.finditer(cdp_output)
    for match_block in blocks:
        block_text = match_block.group('block')
        intf_name = match_block.group('intf')

        # If the block mentions CDP packet transmission, CDP is enabled
        if re.search(r'Sending CDP packets every \d+ seconds', block_text):
            cdp_enabled_interfaces.append(intf_name)

    if cdp_enabled_interfaces:
        # Warn if CDP is enabled on any interfaces
        print(Fore.YELLOW + "[!] WARNING: CDP is enabled on the following interfaces:" + Style.RESET_ALL)
        for interface in cdp_enabled_interfaces:
            print(Fore.YELLOW + f"    - {interface}" + Style.RESET_ALL)
        
        # Highlight security risks associated with CDP
        print(Fore.YELLOW + "[!] CDP frames carry sensitive information about the equipment." + Style.RESET_ALL)
        print(Fore.WHITE + "[*] Keep track of where CDP is active." + Style.RESET_ALL)
        print(Fore.WHITE + "[*] When disabling CDP, be careful not to break VoIP." + Style.RESET_ALL)
    else:
        # Confirm that CDP is disabled on all interfaces
        print(Fore.GREEN + "[OK] CDP is disabled on all interfaces." + Style.RESET_ALL)

# Checking VTY Lines
def checking_vty_security(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking VTY Lines" + Style.RESET_ALL)
    
    try:
        # Retrieve VTY line configuration
        config = connection.send_command("show running-config | section line vty")
        
        # Retrieve full configuration to check global settings like HTTP server status
        global_config = connection.send_command("show running-config")
    except Exception as e:
        # Handle errors if the command fails
        print(Fore.RED + f"[-] Failed to retrieve VTY configuration: {e}" + Style.RESET_ALL)
        return

    insecure_methods = []
    ssh_enabled = False
    access_class_found = False
    login_local_found = False

    # Split configuration into VTY blocks for analysis
    vty_blocks = re.split(r"line vty \d+ \d+", config)

    for vty_block in vty_blocks:
        if not vty_block.strip():
            continue
        
        # Check for transport input settings (protocols allowed for remote access)
        if "transport input" in vty_block:
            if "telnet" in vty_block:
                insecure_methods.append("Telnet")
            if "rlogin" in vty_block:
                insecure_methods.append("RLogin")
            if "ssh" in vty_block:
                ssh_enabled = True

        # Check if access-class is applied (restricts remote access)
        if "access-class" in vty_block:
            access_class_found = True
        
        # Check if login local authentication is used (local username-based auth)
        if "login local" in vty_block:
            login_local_found = True

    # Warn if insecure transport methods are enabled (Telnet or RLogin)
    if insecure_methods:
        print(Fore.RED + "[!] WARNING: Insecure transport methods detected!" + Style.RESET_ALL)
        for method in set(insecure_methods):
            print(Fore.RED + f"    - {method} is enabled on VTY lines. Consider disabling it (`transport input ssh`)." + Style.RESET_ALL)

    # Confirm if SSH is enabled (preferred secure access method)
    if ssh_enabled:
        print(Fore.GREEN + "[OK] SSH is enabled for secure remote access." + Style.RESET_ALL)

    # Inform if local authentication is used
    if login_local_found:
        print(Fore.WHITE + "[*] Local authentication (login local) is used for VTY access." + Style.RESET_ALL)

    # Warn if no access-class is applied (leaving remote access open)
    if not access_class_found:
        print(Fore.RED + "[!] WARNING: No 'access-class' applied to VTY lines!" + Style.RESET_ALL)
        print(Fore.RED + "    - Your device is vulnerable to unauthorized remote access." + Style.RESET_ALL)
        print(Fore.RED + "    - Consider applying an ACL using `access-class ACL_NAME in`." + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[OK] Access-class is applied, restricting remote access." + Style.RESET_ALL)

    # Web Service Activity: Checking if HTTP/HTTPS management is enabled
    http_server_disabled = "no ip http server" in global_config
    https_server_disabled = "no ip http secure-server" in global_config

    # Warn if web-based management interfaces are enabled (potential security risks)
    if not http_server_disabled or not https_server_disabled:
        print(Fore.YELLOW + "[!] WARNING: Web management interface (HTTP/HTTPS) is enabled!" + Style.RESET_ALL)
        print(Fore.YELLOW + "    - Check your hardware for CVE-2023-20273 & CVE-2023-20198" + Style.RESET_ALL)
        print(Fore.YELLOW + "    - If you're not using this as a control, you're better off turning it off" + Style.RESET_ALL)
    else:
        # Confirm if HTTP/HTTPS management is properly disabled
        print(Fore.GREEN + "[OK] HTTP/HTTPS management interface is disabled." + Style.RESET_ALL)

# Checking AAA
def checking_aaa(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking AAA Configuration" + Style.RESET_ALL)

    try:
        # Check if AAA is enabled by looking for 'aaa new-model'
        aaa_new_model = connection.send_command("show running-config | include aaa new-model").strip()
        
        # If AAA is not enabled, warn the user and stop further checks
        if not aaa_new_model or "no aaa new-model" in aaa_new_model:
            print(Fore.YELLOW + "[!] WARNING: AAA is not enabled (no 'aaa new-model' found). The device relies on local authentication only." + Style.RESET_ALL)
            return
        
        print(Fore.GREEN + "[OK] AAA is enabled on this device." + Style.RESET_ALL)

        # Dictionary to track authentication methods in use
        auth_methods = {
            "enable": [],
            "local": [],
            "none": [],
            "radius": [],
            "tacacs": []
        }

        # Retrieve AAA authentication methods from running config
        method_lines = connection.send_command("show running-config | include aaa authentication login").strip().splitlines()

        # Parse authentication methods from configuration
        for line in method_lines:
            match = re.search(r'aaa authentication login (\S+) (.+)', line)
            if match:
                list_name, methods = match.groups()
                methods_list = methods.split()
                
                if "enable" in methods_list:
                    auth_methods["enable"].append(list_name)
                if "local" in methods_list:
                    auth_methods["local"].append(list_name)
                if "none" in methods_list:
                    auth_methods["none"].append(list_name)
                if "group radius" in methods:
                    auth_methods["radius"].append(list_name)
                if "group tacacs+" in methods:
                    auth_methods["tacacs"].append(list_name)

        # Warn if 'none' is used in authentication (bypassing authentication)
        if auth_methods["none"]:
            for method in auth_methods["none"]:
                if method == "default":
                    print(Fore.RED + "[!] CRITICAL: 'none' is used as the primary authentication method! Unauthorized access is possible!" + Style.RESET_ALL)
                else:
                    print(Fore.YELLOW + f"[!] WARNING: 'none' is present in authentication list '{method}'. Consider removing it." + Style.RESET_ALL)

        # Warn if 'enable' password authentication is used (considered weak)
        if auth_methods["enable"]:
            print(Fore.YELLOW + "[!] WARNING: Authentication uses 'enable' password. Consider switching to more secure methods like RADIUS/TACACS+." + Style.RESET_ALL)

        # Confirm local authentication is in use
        if auth_methods["local"]:
            print(Fore.GREEN + "[OK] Local authentication is configured." + Style.RESET_ALL)

        # Confirm RADIUS authentication is enabled
        if auth_methods["radius"]:
            print(Fore.GREEN + "[OK] RADIUS authentication is enabled for login." + Style.RESET_ALL)

        # Confirm TACACS+ authentication is enabled
        if auth_methods["tacacs"]:
            print(Fore.GREEN + "[OK] TACACS+ authentication is enabled for login." + Style.RESET_ALL)

        # Warn if only local authentication is used without RADIUS/TACACS+
        if not (auth_methods["radius"] or auth_methods["tacacs"]) and auth_methods["local"]:
            print(Fore.YELLOW + "[!] WARNING: Only local authentication is used. Ensure strong passwords for local users." + Style.RESET_ALL)

        # Check if AAA accounting is configured
        accounting_config = connection.send_command("show running-config | include aaa accounting").strip()
        
        # Warn if AAA accounting is missing (no logging of actions)
        if not accounting_config:
            print(Fore.YELLOW + "[!] WARNING: AAA accounting is not configured. Actions on the device are not logged." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "[OK] AAA accounting is enabled. Actions on the device are logged." + Style.RESET_ALL)

    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve AAA configuration: {e}" + Style.RESET_ALL)

# Checking Sessions Limit
def checking_session_limit(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking Sessions Limit" + Style.RESET_ALL)

    try:
        # Retrieve session limit configuration from running config
        session_limit_output = connection.send_command("show running-config | include session-limit").strip()
        
        # Warn if no session limit is explicitly configured
        if not session_limit_output:
            print(Fore.RED + "[!] WARNING: No session limit is set! Default (16) sessions are allowed." + Style.RESET_ALL)
            return

        # Extract the configured session limit value
        match = re.search(r'session-limit (\d+)', session_limit_output)
        if match:
            session_limit = int(match.group(1))
            print(Fore.GREEN + f"[OK] Session limit is set to {session_limit} concurrent sessions." + Style.RESET_ALL)
            
            # Warn if the session limit is higher than the recommended value (default: 3)
            if session_limit > 3:
                print(Fore.YELLOW + f"[!] WARNING: The session limit is higher than recommended (3). Consider lowering it." + Style.RESET_ALL)
                print(Fore.YELLOW + f"[*] However, base it on your needs." + Style.RESET_ALL)
        else:
            # If session limit couldn't be parsed, display a warning
            print(Fore.RED + "[!] WARNING: Could not parse session limit value." + Style.RESET_ALL)

    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve session limit configuration: {e}" + Style.RESET_ALL)

# Checking Login Block
def checking_login_block_protection(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking Login Block" + Style.RESET_ALL)

    try:
        # Retrieve login block protection configuration
        login_block_output = connection.send_command("show running-config | include login block-for").strip()
        
        # Warn if brute-force protection is not configured
        if not login_block_output:
            print(Fore.RED + "[!] WARNING: No brute-force protection (login block) is configured." + Style.RESET_ALL)
            return

        # Extract login block settings from the configuration
        match = re.search(r'login block-for (\d+) attempts (\d+) within (\d+)', login_block_output)
        if match:
            block_time, attempts, within_time = match.groups()
            print(Fore.GREEN + f"[OK] Brute-force protection is enabled: {attempts} failed attempts within {within_time} sec → block for {block_time} sec." + Style.RESET_ALL)

            # Warn if the number of allowed failed attempts is too high
            if int(attempts) > 5:
                print(Fore.YELLOW + f"[!] WARNING: The failed attempts threshold ({attempts}) is too high. Recommended: 3." + Style.RESET_ALL)

            # Warn if the block time is too short for effective protection
            if int(block_time) < 30:
                print(Fore.YELLOW + f"[!] WARNING: The block time ({block_time} sec) is too short. Recommended: 60 sec or more." + Style.RESET_ALL)
        else:
            # If parsing fails, notify the user
            print(Fore.RED + "[!] WARNING: Could not parse brute-force protection configuration." + Style.RESET_ALL)

    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve login block configuration: {e}" + Style.RESET_ALL)

# Checking SSH Security Settings
def checking_ssh_security(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking SSH Security Settings" + Style.RESET_ALL)

    try:
        # Retrieve SSH-related configuration lines
        ssh_config = connection.send_command("show running-config | include ^ip ssh").strip().splitlines()

        # Default settings (Cisco default values)
        ssh_version = "Compatibility (1 & 2)"
        auth_retries = 3  # Default number of authentication retries
        timeout = 120  # Default session timeout in seconds
        maxstartups = 10  # Default max simultaneous SSH sessions

        # Parse SSH configuration for specific settings
        for line in ssh_config:
            if "ip ssh version" in line:
                ssh_version = line.split()[-1]  # Extracts SSH version
            elif "ip ssh authentication-retries" in line:
                auth_retries = int(line.split()[-1])  # Extracts authentication retry count
            elif "ip ssh time-out" in line:
                timeout = int(line.split()[-1])  # Extracts session timeout value
            elif "ip ssh maxstartups" in line:
                maxstartups = int(line.split()[-1])  # Extracts max startup sessions value

        # Check SSH version (should be explicitly set to version 2)
        if ssh_version != "2":
            print(Fore.RED + "[!] WARNING: SSH version is not explicitly set to 2. Set with 'ip ssh version 2'." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "[OK] SSH version 2 is explicitly configured." + Style.RESET_ALL)

        # Check SSH authentication retry limit (should not be too high)
        if auth_retries > 3:
            print(Fore.YELLOW + f"[!] NOTICE: SSH authentication-retries ({auth_retries}) is slightly high. Recommended: ≤ 3." + Style.RESET_ALL)
        elif auth_retries == 3:
            print(Fore.GREEN + f"[OK] SSH authentication-retries ({auth_retries}) is secure." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + f"[OK] SSH authentication-retries ({auth_retries}) is optimally low." + Style.RESET_ALL)

        # Check SSH session timeout (should be limited for security)
        if timeout > 120:
            print(Fore.RED + f"[!] WARNING: SSH timeout ({timeout}s) is too high. Recommended: ≤ 90s, ideally ≤ 60s." + Style.RESET_ALL)
        elif 90 < timeout <= 120:
            print(Fore.YELLOW + f"[!] NOTICE: SSH timeout ({timeout}s) is moderate. Consider ≤ 90s for better security." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + f"[OK] SSH timeout ({timeout}s) is optimal." + Style.RESET_ALL)

        # Check max simultaneous SSH sessions allowed (should be restricted)
        if maxstartups > 4:
            print(Fore.RED + f"[!] WARNING: SSH maxstartups ({maxstartups}) is too high. Recommended: ≤ 4." + Style.RESET_ALL)
        elif maxstartups == 4:
            print(Fore.YELLOW + f"[!] NOTICE: SSH maxstartups ({maxstartups}) is reasonable, but ≤ 3 is preferred." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + f"[OK] SSH maxstartups ({maxstartups}) is secure." + Style.RESET_ALL)

    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve SSH configuration: {e}" + Style.RESET_ALL)

# Checking LLDP
def checking_lldp(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking LLDP Operation" + Style.RESET_ALL)

    try:
        # Retrieve LLDP status for all interfaces
        lldp_output = connection.send_command("show lldp interface")
    except Exception as e:
        # Handle errors if the command fails
        print(Fore.RED + f"[-] Failed to retrieve LLDP status: {e}" + Style.RESET_ALL)
        return

    # Extract interfaces where LLDP is enabled for both transmission (Tx) and reception (Rx)
    lldp_enabled_interfaces = re.findall(r'(\S+):\n\s+Tx: enabled\n\s+Rx: enabled', lldp_output)

    if lldp_enabled_interfaces:
        # Warn if LLDP is enabled on any interfaces
        print(Fore.YELLOW + "[!] WARNING: LLDP is enabled on the following interfaces:" + Style.RESET_ALL)
        for interface in lldp_enabled_interfaces:
            print(Fore.YELLOW + f"    - {Fore.YELLOW}{interface}{Style.RESET_ALL}")
        
        # Highlight security risks associated with LLDP
        print(Fore.YELLOW + "[!] LLDP frames carry sensitive information about the equipment." + Style.RESET_ALL)
        print(Fore.WHITE + "[*] Keep track of where LLDP is active." + Style.RESET_ALL)
        print(Fore.WHITE + "[*] When disabling LLDP, be careful not to break VoIP." + Style.RESET_ALL)
    else:
        # Confirm that LLDP is disabled on all interfaces
        print(Fore.GREEN + "[OK] LLDP is disabled on all interfaces." + Style.RESET_ALL)

# Checking Default Usernames
def checking_default_usernames(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking Default Usernames" + Style.RESET_ALL)

    try:
        # Retrieve all configured usernames from the running configuration
        config = connection.send_command("show running-config | sec username")
    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve usernames: {e}" + Style.RESET_ALL)
        return

    # List of commonly used default usernames that should be avoided
    default_usernames = {"user", "test", "cisco", "ciscoadmin", "root", "ciscoios", "c1sc0", "administrator", "admin"}

    # Extract all usernames from the configuration
    found_users = re.findall(r'username\s+(\S+)', config)

    # Identify usernames that match known default usernames
    flagged_users = [user for user in found_users if user.lower() in default_usernames]

    if flagged_users:
        # Warn if any default usernames are found
        print(Fore.YELLOW + "[!] WARNING: Default usernames detected!" + Style.RESET_ALL)
        for user in flagged_users:
            print(Fore.YELLOW + f"    - {Fore.WHITE}{user}{Style.RESET_ALL}")

        # Highlight the security risk of using common usernames
        print(Fore.YELLOW + "[!] Using default usernames increases the risk of brute-force attacks. Change them to something more unique." + Style.RESET_ALL)
    else:
        # Confirm that no default usernames are present
        print(Fore.GREEN + "[OK] No default usernames found." + Style.RESET_ALL)

# Checking HSRP
def checking_hsrp(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking HSRP Operation" + Style.RESET_ALL)

    try:
        # Retrieve HSRP configuration from the running configuration
        hsrp_config = connection.send_command("show running-config | section standby").strip()
        
        # If no HSRP configuration is found, assume the feature is not in use
        if not hsrp_config:
            print(Fore.GREEN + "[OK] No HSRP configuration found on this device." + Style.RESET_ALL)
            return

        # Retrieve HSRP active status information
        hsrp_status = connection.send_command("show standby brief")
    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve HSRP configuration: {e}" + Style.RESET_ALL)
        return

    # Extract all unique HSRP group numbers from the configuration
    hsrp_groups = list(set(re.findall(r'standby\s+(\d+)', hsrp_config)))

    priority_issues = []  # Stores HSRP groups with low priority
    no_auth = []  # Stores HSRP groups without authentication
    md5_auth = []  # Stores HSRP groups using MD5 authentication
    plain_auth = []  # Stores HSRP groups using plaintext authentication

    for group in hsrp_groups:
        # Extract HSRP priority for each group
        pm = re.search(rf'standby {group} priority (\d+)', hsrp_config)
        priority = int(pm.group(1)) if pm else 100  # Default priority is 100 if not set

        # Check if the group is active and its priority is below 255 (not ideal)
        ac = re.search(rf'^\S+\s+{group}\s+(\d+)\s+\S*\s+Active', hsrp_status, re.MULTILINE)
        if ac and priority < 255:
            priority_issues.append(
                f"    - Group {group}: priority is {priority}. {Fore.RED}Should be 255 for Active role{Style.RESET_ALL}"
            )

        # Extract HSRP authentication settings
        auth_line = re.search(rf'^.*standby {group} authentication (.*)$', hsrp_config, re.MULTILINE)
        if auth_line:
            if 'md5' in auth_line.group(1).lower():
                md5_auth.append(f"    - Group {group}")
            else:
                plain_auth.append(f"    - Group {group}")
        else:
            no_auth.append(f"    - Group {group}")

    issues_found = (priority_issues or no_auth or plain_auth)

    if issues_found:
        # Warn about HSRP security risks and possible MITM attacks
        print(Fore.YELLOW + "[!] WARNING: HSRP security issues detected. Possible MITM risk." + Style.RESET_ALL)

        if priority_issues:
            print(Fore.YELLOW + "[!] HSRP groups with priority issues:" + Style.RESET_ALL)
            for issue in priority_issues:
                print(issue)

        if no_auth:
            print(Fore.YELLOW + "[!] HSRP groups without any authentication:" + Style.RESET_ALL)
            for group in no_auth:
                print(Fore.YELLOW + group + Style.RESET_ALL)

        if plain_auth:
            print(Fore.RED + "[!] HSRP groups using plaintext authentication:" + Style.RESET_ALL)
            for group in plain_auth:
                print(Fore.RED + group + Style.RESET_ALL)

    # Confirm if MD5 authentication is in use for HSRP groups
    if md5_auth:
        print(Fore.GREEN + "[OK] HSRP MD5 authentication is enabled on the following groups:" + Style.RESET_ALL)
        for group in md5_auth:
            print(Fore.GREEN + group + Style.RESET_ALL)

    # Inform that HSRP priority values may vary depending on infrastructure design
    print(Fore.WHITE + "[*] HSRP priorities can be configured differently in different infrastructures, you may even get MHSRP." + Style.RESET_ALL)

    if not issues_found:
        # Confirm that no security vulnerabilities were detected in HSRP configuration
        print(Fore.GREEN + "[OK] No security issues found with HSRP configuration." + Style.RESET_ALL)

# Checking VRRP
def checking_vrrp(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking VRRP Operation" + Style.RESET_ALL)

    try:
        # Retrieve VRRP configuration from the running configuration
        vrrp_config = connection.send_command("show running-config | section vrrp").strip()

        # If no VRRP configuration is found, assume the feature is not in use
        if not vrrp_config:
            print(Fore.GREEN + "[OK] No VRRP configuration found on this device." + Style.RESET_ALL)
            return

    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve VRRP configuration: {e}" + Style.RESET_ALL)
        return

    # Extract all unique VRRP group numbers from the configuration
    vrrp_instances = re.findall(r'vrrp\s+(\d+)', vrrp_config)
    vrrp_instances = list(set(vrrp_instances))

    priority_warnings = []  # Stores VRRP groups with low priority
    auth_issues = []  # Stores VRRP groups without authentication
    auth_md5 = []  # Stores VRRP groups using MD5 authentication
    weak_auth = []  # Stores VRRP groups using plaintext authentication

    for group in vrrp_instances:
        # Extract VRRP priority for each group
        priority_match = re.search(rf'vrrp {group} priority (\d+)', vrrp_config)
        priority = int(priority_match.group(1)) if priority_match else 100  # Default priority is 100 if not set

        priority_warnings.append(f"    - Group {group}: priority is {priority} (Max possible is 254. You can protect yourself from a MITM attack with authentication)")

        # Extract VRRP authentication settings
        auth_text_match = re.search(rf'vrrp {group} authentication text ', vrrp_config)
        auth_md5_keychain_match = re.search(rf'vrrp {group} authentication md5 key-chain ', vrrp_config)
        auth_md5_keystring_match = re.search(rf'vrrp {group} authentication md5 key-string ', vrrp_config)

        if auth_md5_keychain_match or auth_md5_keystring_match:
            auth_md5.append(f"    - Group {group}")
        elif auth_text_match:
            weak_auth.append(f"    - Group {group}")
        else:
            auth_issues.append(f"    - Group {group}")

    if priority_warnings or auth_issues or weak_auth:
        # Warn about VRRP security risks and possible MITM attacks
        print(Fore.YELLOW + "[!] WARNING: VRRP security issues detected. Possible MITM risk." + Style.RESET_ALL)

        if priority_warnings:
            print(Fore.YELLOW + "[!] VRRP groups and their priorities:" + Style.RESET_ALL)
            for issue in priority_warnings:
                print(Fore.YELLOW + issue + Style.RESET_ALL)

        if weak_auth:
            print(Fore.RED + "[!] VRRP groups using plaintext authentication:" + Style.RESET_ALL)
            for issue in weak_auth:
                print(Fore.RED + issue + Style.RESET_ALL)

        if auth_issues:
            print(Fore.RED + "[!] VRRP groups without authentication:" + Style.RESET_ALL)
            for issue in auth_issues:
                print(Fore.RED + issue + Style.RESET_ALL)

    # Confirm if MD5 authentication is in use for VRRP groups
    if auth_md5:
        print(Fore.GREEN + "[OK] VRRP MD5 authentication is enabled on the following groups:" + Style.RESET_ALL)
        for success in auth_md5:
            print(Fore.GREEN + success + Style.RESET_ALL)

    # Inform that VRRP priority values may vary depending on infrastructure design
    print(Fore.WHITE + "[*] VRRP priorities can be configured differently in different infrastructures, you may even get MVRRP." + Style.RESET_ALL)

    if not priority_warnings and not auth_issues and not weak_auth:
        # Confirm that no security vulnerabilities were detected in VRRP configuration
        print(Fore.GREEN + "[OK] No security issues found with VRRP configuration." + Style.RESET_ALL)

# Checking GLBP
def checking_glbp(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking GLBP Operation" + Style.RESET_ALL)

    try:
        # Retrieve GLBP configuration from the running configuration
        glbp_config = connection.send_command("show running-config | section glbp").strip()

        # If no GLBP configuration is found, assume the feature is not in use
        if not glbp_config:
            print(Fore.GREEN + "[OK] No GLBP configuration found on this device." + Style.RESET_ALL)
            return

        # Retrieve GLBP brief status information
        glbp_brief = connection.send_command("show glbp brief")
    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve GLBP configuration: {e}" + Style.RESET_ALL)
        return

    # Extract all unique GLBP group numbers from the configuration
    glbp_groups = list(set(re.findall(r'glbp\s+(\d+)\s', glbp_config)))

    priority_issues = []  # Stores GLBP groups with low AVG priority
    no_auth = []  # Stores GLBP groups without authentication
    md5_auth = []  # Stores GLBP groups using MD5 authentication
    plain_auth = []  # Stores GLBP groups using plaintext authentication

    # Regular expression pattern for parsing GLBP brief output
    pattern = re.compile(r'^(?P<intf>\S+)\s+(?P<grp>\d+)\s+(?P<fwd>-|\d+)\s+(?P<pri>\d+|-)\s+(?P<state>\S+)', re.MULTILINE)
    brief_matches = pattern.findall(glbp_brief)

    # Dictionary to store actual roles and priorities of GLBP groups
    actual_roles = {}

    for intf, grp, fwd, pri, state in brief_matches:
        if grp not in actual_roles:
            actual_roles[grp] = []
        is_avg = (fwd == '-')  # Check if the group acts as the AVG (Active Virtual Gateway)

        real_pri = int(pri) if pri.isdigit() else 100  # Default priority is 100 if not explicitly set
        actual_roles[grp].append({
            "interface": intf,
            "fwd": fwd,
            "priority": real_pri,
            "state": state.lower(),
            "is_avg": is_avg
        })

    for group in glbp_groups:
        # Extract GLBP priority for each group
        match_priority = re.search(rf'glbp {group} priority (\d+)', glbp_config)
        config_prio = int(match_priority.group(1)) if match_priority else 100

        # Extract authentication settings
        auth_line = re.search(rf'^.*glbp {group} authentication (\S+)\s+(.*)$', glbp_config, re.MULTILINE)
        if auth_line:
            auth_type = auth_line.group(1).lower()
            if auth_type == "md5":
                md5_auth.append(f"    - Group {group}")
            elif auth_type == "text":
                plain_auth.append(f"    - Group {group}")
            else:
                no_auth.append(f"    - Group {group}")
        else:
            no_auth.append(f"    - Group {group}")

        # Analyze GLBP roles and priority settings
        group_role_info = actual_roles.get(group, [])
        for role in group_role_info:
            if role["is_avg"] and role["state"] == "active":
                if config_prio < 255:
                    priority_issues.append(
                        f"    - Group {group}: priority is {config_prio}. {Fore.RED}Should be 255 for the AVG{Style.RESET_ALL}"
                    )

    issues_found = (priority_issues or no_auth or plain_auth)

    if issues_found:
        # Warn about GLBP security risks and possible MITM attacks
        print(Fore.YELLOW + "[!] WARNING: GLBP security issues detected. Possible MITM risk." + Style.RESET_ALL)

        if priority_issues:
            print(Fore.YELLOW + "[!] GLBP AVG with priority <255:" + Style.RESET_ALL)
            for issue in priority_issues:
                print(issue)

        if plain_auth:
            print(Fore.RED + "[!] GLBP groups using plaintext authentication:" + Style.RESET_ALL)
            for grp in plain_auth:
                print(Fore.RED + grp + Style.RESET_ALL)

        if no_auth:
            print(Fore.RED + "[!] GLBP groups without authentication:" + Style.RESET_ALL)
            for grp in no_auth:
                print(Fore.RED + grp + Style.RESET_ALL)

    # Confirm if MD5 authentication is in use for GLBP groups
    if md5_auth:
        print(Fore.GREEN + "[OK] GLBP MD5 authentication is enabled on the following groups:" + Style.RESET_ALL)
        for g in md5_auth:
            print(Fore.GREEN + g + Style.RESET_ALL)

    # Inform that GLBP priority values may vary depending on infrastructure design
    print(Fore.WHITE + Style.BRIGHT + "[*] GLBP settings in the context of prioritization can vary across infrastructures. Keep in mind." + Style.RESET_ALL)

    if not issues_found:
        # Confirm that no security vulnerabilities were detected in GLBP configuration
        print(Fore.GREEN + "[OK] No security issues found with GLBP configuration." + Style.RESET_ALL)

# Checking SNMP
def checking_snmp(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking SNMP Operation" + Style.RESET_ALL)

    try:
        # Retrieve SNMP configuration from the running configuration
        snmp_config = connection.send_command("show running-config | section snmp").strip()

        # If no SNMP configuration is found, assume SNMP is not in use
        if not snmp_config:
            print(Fore.GREEN + "[OK] No SNMP configuration found on this device." + Style.RESET_ALL)
            return

    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve SNMP configuration: {e}" + Style.RESET_ALL)
        return

    # List of commonly used weak SNMP community strings
    weak_snmp_strings = ["public", "private", "cisco", "admin", "root", "ciscoadmin", "c1sc0", "ciscorouter", "ciscoios"]

    # Extract SNMP community strings and their access levels (RO = Read-Only, RW = Read-Write)
    snmp_entries = re.findall(r'snmp-server community (\S+) (RO|RW)', snmp_config)

    rw_issues = []  # Stores SNMP communities with RW (Read-Write) access
    weak_issues = []  # Stores SNMP communities with weak names
    ro_entries = []  # Stores SNMP communities with RO (Read-Only) access

    for community, access in snmp_entries:
        # Flag communities with RW access as a high security risk
        if access == "RW":
            rw_issues.append(f"    - {community}: RW access (Dangerous! If an attacker obtains this, they may download the router's configuration via TFTP)")

        # Flag communities with weak, easily guessable names
        if community.lower() in weak_snmp_strings:
            weak_issues.append(f"    - {community}: Weak SNMP community detected")

        # Log communities with RO access (not as risky, but still a potential security concern)
        if access == "RO":
            ro_entries.append(f"    - {community}: RO access (Less risky, but still should be restricted)")

    if rw_issues or weak_issues:
        # Warn about SNMP security risks, including weak or RW-enabled community strings
        print(Fore.YELLOW + "[!] WARNING: SNMP security issues detected!" + Style.RESET_ALL)

        if rw_issues:
            print(Fore.YELLOW + "[!] SNMP RW communities found:" + Style.RESET_ALL)
            for issue in rw_issues:
                print(Fore.RED + issue + Style.RESET_ALL)

        if weak_issues:
            print(Fore.YELLOW + "[!] Weak SNMP community strings detected!" + Style.RESET_ALL)
            for issue in weak_issues:
                print(Fore.YELLOW + issue + Style.RESET_ALL)

    # Display SNMP RO communities, which pose a lower but still notable security risk
    if ro_entries:
        print(Fore.BLUE + "[*] SNMP RO communities found:" + Style.RESET_ALL)
        for entry in ro_entries:
            print(Fore.BLUE + entry + Style.RESET_ALL)

    if not rw_issues and not weak_issues:
        # Confirm that no critical SNMP security issues were detected
        print(Fore.GREEN + "[OK] No SNMP security issues found." + Style.RESET_ALL)

# Checking DHCP Snooping
def checking_dhcp_snooping(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking DHCP Snooping Operation" + Style.RESET_ALL)

    try:
        # Retrieve DHCP Snooping configuration from the running configuration
        dhcp_snooping_config = connection.send_command("show running-config | section dhcp snooping").strip()

        # If no DHCP Snooping configuration is found, assume the feature is not enabled
        if not dhcp_snooping_config:
            print(Fore.RED + "[!] WARNING: DHCP Snooping is NOT enabled on this device!" + Style.RESET_ALL)
            return

    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve DHCP Snooping configuration: {e}" + Style.RESET_ALL)
        return

    # Extract VLANs where DHCP Snooping is enabled
    snooping_vlans = re.findall(r'ip dhcp snooping vlan (\S+)', dhcp_snooping_config)

    # Extract trusted DHCP Snooping ports
    snooping_trust_ports = re.findall(r'ip dhcp snooping trust', dhcp_snooping_config)

    # Check if Option 82 (DHCP Snooping Information Option) is disabled
    option_82_disabled = "no ip dhcp snooping information option" in dhcp_snooping_config

    # Check if a DHCP Snooping binding database is configured
    snooping_database = re.search(r'ip dhcp snooping database\s+(flash:|ftp:|https:|rcp:|scp:|tftp:)/\S+', dhcp_snooping_config)

    # Check if a write-delay is configured for DHCP Snooping database updates
    write_delay_match = re.search(r'ip dhcp snooping database write-delay (\d+)', dhcp_snooping_config)

    # Check if DHCP Snooping rate limiting is enabled on any ports
    rate_limit = re.findall(r'ip dhcp snooping limit rate (\d+)', dhcp_snooping_config)

    issues = []  # Stores critical DHCP Snooping misconfigurations
    notices = []  # Stores best practice recommendations

    if not snooping_vlans:
        # Warn if DHCP Snooping is enabled but no VLANs are configured
        issues.append("[!] DHCP Snooping is enabled, but no VLANs are configured!")
    else:
        print(Fore.GREEN + f"[OK] DHCP Snooping is enabled for VLANs: {', '.join(snooping_vlans)}" + Style.RESET_ALL)

    if not snooping_trust_ports:
        # Warn if no trusted DHCP Snooping ports are defined
        issues.append("[!] No trusted ports configured! DHCP replies might be blocked.")
    else:
        print(Fore.YELLOW + f"[*] DHCP Snooping trust is configured on {len(snooping_trust_ports)} ports." + Style.RESET_ALL)

    if not option_82_disabled:
        # Notify the user that Option 82 is enabled (not necessarily a security issue)
        issues.append("[*] DHCP Snooping Information Option (Option 82) is enabled. I'm just keeping you posted.")
    else:
        print(Fore.GREEN + "[OK] Option 82 is disabled, reducing potential issues." + Style.RESET_ALL)

    if snooping_database:
        # Confirm that a DHCP Snooping binding database is set
        print(Fore.GREEN + f"[OK] DHCP Snooping binding database is set to: {snooping_database.group(1)}" + Style.RESET_ALL)
    else:
        # Warn if no DHCP Snooping binding database is set (bindings will be lost on reboot)
        issues.append("[!] No DHCP Snooping database configured! Snooping bindings will be lost on reboot.")

    if write_delay_match:
        # Display the configured DHCP Snooping write-delay
        write_delay_value = write_delay_match.group(1)
        print(Fore.GREEN + f"[OK] DHCP Snooping write-delay is set to {write_delay_value} seconds." + Style.RESET_ALL)
    else:
        # Warn if no write-delay is configured
        print(Fore.YELLOW + "[!] WARNING: No DHCP Snooping write-delay configured. Changes may not be written efficiently!" + Style.RESET_ALL)

    if rate_limit:
        # Confirm that DHCP Snooping rate limiting is enabled
        print(Fore.GREEN + f"[OK] DHCP Snooping rate limit is set on {len(rate_limit)} ports." + Style.RESET_ALL)
    else:
        # Recommend enabling DHCP Snooping rate limiting to prevent DHCP starvation attacks
        notices.append("[*] No rate limiting on DHCP Snooping. Consider enabling to prevent DHCP starvation attacks.")

    if issues:
        # Display warnings for detected security risks
        print(Fore.YELLOW + "[!] WARNING: DHCP Snooping security issues detected:" + Style.RESET_ALL)
        for issue in issues:
            print(Fore.YELLOW + "    - " + issue + Style.RESET_ALL)

    if notices:
        # Display additional recommendations for best practices
        print(Fore.YELLOW + "[*] Additional DHCP Snooping recommendations:" + Style.RESET_ALL)
        for notice in notices:
            print(Fore.WHITE + "    - " + notice + Style.RESET_ALL)

    if not issues:
        # Confirm that no critical DHCP Snooping security issues were detected
        print(Fore.GREEN + "[OK] No critical security issues found with DHCP Snooping." + Style.RESET_ALL)

# Checking DAI
def checking_dai(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking Dynamic ARP Inspection" + Style.RESET_ALL)

    try:
        # Retrieve Dynamic ARP Inspection (DAI) configuration from the running configuration
        dai_config = connection.send_command("show running-config | section arp inspection").strip()

        # If no DAI configuration is found, assume the feature is not enabled
        if not dai_config:
            print(Fore.RED + "[!] WARNING: Dynamic ARP Inspection (DAI) is NOT enabled on this device!" + Style.RESET_ALL)
            return

    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve DAI configuration: {e}" + Style.RESET_ALL)
        return

    # Extract VLANs where DAI is enabled
    dai_vlans = re.findall(r'ip arp inspection vlan (\S+)', dai_config)

    # Extract trusted interfaces for ARP inspection
    trusted_ports = re.findall(r'ip arp inspection trust', dai_config)

    # Extract ARP filters applied for additional security
    arp_filters = re.findall(r'ip arp inspection filter (\S+)', dai_config)

    # Extract ARP inspection rate limits
    arp_rate_limits = re.findall(r'ip arp inspection limit rate (\d+)', dai_config)

    issues = []  # Stores critical DAI misconfigurations
    notices = []  # Stores best practice recommendations

    if not dai_vlans:
        # Warn if DAI is enabled but no VLANs are configured
        issues.append("[!] DAI is enabled, but no VLANs are configured!")
    else:
        print(Fore.GREEN + f"[OK] DAI is enabled for VLANs: {', '.join(dai_vlans)}" + Style.RESET_ALL)

    if not trusted_ports:
        # Warn if no trusted interfaces are configured
        issues.append("[!] No trusted ports configured! DHCP server responses may be blocked.")
    else:
        print(Fore.YELLOW + f"[*] Trusted ports are configured on {len(trusted_ports)} interfaces." + Style.RESET_ALL)

    if arp_filters:
        # Confirm that ARP inspection filters are applied
        print(Fore.GREEN + f"[OK] ARP inspection filter(s) configured: {', '.join(arp_filters)}" + Style.RESET_ALL)
    else:
        # Recommend configuring ARP inspection filters for enhanced security
        notices.append("[*] No ARP inspection filters configured. Consider adding ACLs for better security.")

    if arp_rate_limits:
        # Confirm that ARP inspection rate limiting is enabled
        print(Fore.GREEN + f"[OK] ARP inspection rate limit is set on {len(arp_rate_limits)} ports." + Style.RESET_ALL)
    else:
        # Recommend enabling ARP rate limiting to prevent ARP flooding attacks
        notices.append("[*] No rate limiting on ARP inspection. Consider setting limits to prevent flooding.")

    if issues:
        # Display warnings for detected security risks
        print(Fore.YELLOW + "[!] WARNING: DAI security issues detected!" + Style.RESET_ALL)
        for issue in issues:
            print(Fore.YELLOW + "    - " + issue + Style.RESET_ALL)

    if notices:
        # Display additional recommendations for best practices
        print(Fore.YELLOW + "[*] NOTICE: Additional DAI recommendations:" + Style.RESET_ALL)
        for notice in notices:
            print(Fore.YELLOW + "    - " + notice + Style.RESET_ALL)

    if not issues:
        # Confirm that no critical DAI security issues were detected
        print(Fore.GREEN + "[OK] No critical security issues found with DAI configuration." + Style.RESET_ALL)

# Checking BPDU Guard
def checking_bpdu_guard(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking BPDU Guard Operation" + Style.RESET_ALL)

    try:
        # Retrieve BPDU Guard global setting
        bpdu_global = connection.send_command("show running-config | include spanning-tree portfast bpduguard default").strip()

        # Retrieve interface-level BPDU Guard settings
        bpdu_interfaces = connection.send_command("show running-config | section interface").strip()

        # Identify interfaces where BPDU Guard is explicitly enabled
        bpdu_enabled_ports = re.findall(r'interface (\S+)\n.*?spanning-tree bpduguard enable', bpdu_interfaces, re.DOTALL)

    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve BPDU Guard configuration: {e}" + Style.RESET_ALL)
        return

    if bpdu_global:
        # Confirm that BPDU Guard is enabled globally
        print(Fore.GREEN + "[OK] BPDU Guard is enabled globally (portfast default)" + Style.RESET_ALL)

    if bpdu_enabled_ports:
        # Confirm that BPDU Guard is enabled on specific interfaces
        print(Fore.GREEN + "[OK] BPDU Guard is enabled on the following interfaces:" + Style.RESET_ALL)
        for interface in bpdu_enabled_ports:
            print(Fore.GREEN + f"    - {interface}" + Style.RESET_ALL)

    if not bpdu_global and not bpdu_enabled_ports:
        # Warn if BPDU Guard is not enabled globally or on any interfaces
        print(Fore.RED + "[!] WARNING: BPDU Guard is NOT enabled on any interface!" + Style.RESET_ALL)
        print(Fore.RED + "    - Without BPDU Guard, an attacker can exploit STP, hijack the root switch role, and perform a partial MITM attack." + Style.RESET_ALL)
        print(Fore.RED + "    - Consider enabling BPDU Guard on all edge ports to prevent unauthorized STP participation." + Style.RESET_ALL)

# Checking SMI
def checking_smart_install(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking Smart Install Operation" + Style.RESET_ALL)

    try:
        # Retrieve Smart Install configuration using 'show vstack config'
        vstack_config = connection.send_command("show vstack config").strip()
    except Exception as e:
        # If the command is not recognized, Smart Install is not supported on this device
        if "Invalid input detected" in str(e):
            print(Fore.WHITE + "[*] This device does not support Smart Install (no `show vstack config` command)." + Style.RESET_ALL)
            return
        else:
            # Handle errors if the command execution fails
            print(Fore.RED + f"[-] Failed to retrieve Smart Install configuration: {e}" + Style.RESET_ALL)
            return

    # Check if Smart Install is enabled or disabled
    enabled_match = re.search(r'Oper Mode:\s+Enabled', vstack_config)
    disabled_match = re.search(r'Oper Mode:\s+Disabled', vstack_config)

    # Retrieve running-config to check if Smart Install is explicitly disabled
    running_config = connection.send_command("show running-config | include vstack").strip()
    explicit_disable = "no vstack" in running_config

    if enabled_match:
        # Warn if Smart Install is enabled, as it is a known security risk
        print(Fore.RED + "[!] WARNING: Smart Install is ENABLED! Device is vulnerable to remote exploitation." + Style.RESET_ALL)
        print(Fore.RED + "    - Oper Mode: Enabled" + Style.RESET_ALL)
        print(Fore.RED + "    - RECOMMENDATION: Disable Smart Install immediately using `no vstack`." + Style.RESET_ALL)
    elif disabled_match or explicit_disable:
        # Confirm that Smart Install is disabled
        print(Fore.GREEN + "[OK] Smart Install is disabled. No security risks detected." + Style.RESET_ALL)
    else:
        # Notify if the status of Smart Install cannot be determined
        print(Fore.YELLOW + "[*] NOTICE: Unable to determine Smart Install status. Manual check recommended." + Style.RESET_ALL)

# Checking Storm-Control
def checking_storm_control(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking Storm-Control Operation" + Style.RESET_ALL)

    try:
        # Ensure the device is in privileged exec mode
        connection.enable()
        connection.send_command("terminal length 0")

        # Retrieve Storm-Control settings from the device
        storm_control_output = connection.send_command("show storm-control").strip()

        # If the command is invalid or there is no output, assume Storm-Control is not enabled or supported
        if "Invalid input" in storm_control_output or not storm_control_output:
            print(Fore.RED + "[!] WARNING: Storm-Control is NOT supported or not enabled on this device!" + Style.RESET_ALL)
            return
    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve Storm-Control configuration: {e}" + Style.RESET_ALL)
        return

    # Regex pattern to extract interface settings from the storm-control output
    pattern = re.compile(
        r'^(\S+)\s+Link\s+\S+\s+(\d+\.\d+%)\s+(\d+\.\d+%)\s+(\d+\.\d+%)\s+(\S+)\s+([BUM])'
    )

    storm_interfaces = {}

    for line in storm_control_output.splitlines():
        match = pattern.search(line)
        if match:
            interface, upper, lower, current, action, traffic_type = match.groups()
            
            # Initialize the interface entry if not present
            if interface not in storm_interfaces:
                storm_interfaces[interface] = {
                    "Broadcast": None,
                    "Multicast": None,
                    "Unicast": None,
                    "Action": action
                }

            # Assign limits based on traffic type (B - Broadcast, M - Multicast, U - Unicast)
            if traffic_type == "B":
                storm_interfaces[interface]["Broadcast"] = f"{upper} (Lower: {lower}, Current: {current})"
            elif traffic_type == "M":
                storm_interfaces[interface]["Multicast"] = f"{upper} (Lower: {lower}, Current: {current})"
            elif traffic_type == "U":
                storm_interfaces[interface]["Unicast"] = f"{upper} (Lower: {lower}, Current: {current})"

    no_action_interfaces = []

    # Identify interfaces where no action is set for Storm-Control violations
    for interface, settings in storm_interfaces.items():
        if settings["Action"].lower() == "none":
            no_action_interfaces.append(interface)

    if storm_interfaces:
        # Confirm that Storm-Control is enabled on interfaces and display their settings
        print(Fore.GREEN + "[OK] Storm-Control is enabled on the following interfaces:" + Style.RESET_ALL)
        for interface, settings in storm_interfaces.items():
            print(Fore.GREEN + f"    - {interface}:" + Style.RESET_ALL)
            for t_type, limit_str in settings.items():
                if t_type != "Action" and limit_str:
                    print(Fore.GREEN + f"        {t_type}: {limit_str}" + Style.RESET_ALL)
            print(Fore.GREEN + f"        Action: {settings['Action']}" + Style.RESET_ALL)
    else:
        # Warn if Storm-Control is not enabled on any interfaces
        print(Fore.RED + "[!] WARNING: Storm-Control is NOT enabled on this device!" + Style.RESET_ALL)

    if no_action_interfaces:
        # Warn if Storm-Control is enabled but no action is configured for violations
        print(Fore.YELLOW + "[!] WARNING: Some interfaces have no storm-control action set!" + Style.RESET_ALL)
        for intf in no_action_interfaces:
            print(Fore.YELLOW + f"    - {intf}: No storm-control action set!" + Style.RESET_ALL)

# Checking Port-Security
def checking_port_security(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking Port-Security Operation" + Style.RESET_ALL)

    try:
        # Retrieve Port Security status from the device
        port_security_output = connection.send_command("show port-security").strip()

        # If the command is invalid or there is no output, assume Port Security is not supported or enabled
        if "Invalid input" in port_security_output or not port_security_output:
            print(Fore.RED + "[!] WARNING: Port Security is NOT supported on this device!" + Style.RESET_ALL)
            return

    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve Port Security configuration: {e}" + Style.RESET_ALL)
        return

    port_security_status = {}

    # Parse each line of the output to extract relevant details
    for line in port_security_output.splitlines():
        match = re.search(r'(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)', line)
        if match:
            interface, max_addr, current_addr, violations, action = match.groups()
            port_security_status[interface] = {
                "Max MAC": max_addr,
                "Current MAC": current_addr,
                "Violations": violations,
                "Action": action
            }

    if port_security_status:
        # Confirm that Port Security is enabled and display its configuration per interface
        print(Fore.GREEN + "[OK] Port Security is enabled on the following interfaces:" + Style.RESET_ALL)
        for interface, details in port_security_status.items():
            print(Fore.GREEN + f"    - {interface}: " + Style.RESET_ALL)
            print(Fore.GREEN + f"        Max Secure MACs: {details['Max MAC']}" + Style.RESET_ALL)
            print(Fore.GREEN + f"        Current MACs: {details['Current MAC']}" + Style.RESET_ALL)
            
            # Highlight any security violations on interfaces
            if int(details["Violations"]) > 0:
                print(Fore.YELLOW + f"        Violations: {details['Violations']}" + Style.RESET_ALL)
            
            print(Fore.GREEN + f"        Security Action: {details['Action']}" + Style.RESET_ALL)
    else:
        # Warn if no interfaces have Port Security enabled
        print(Fore.RED + "[!] WARNING: No interfaces with Port Security enabled!" + Style.RESET_ALL)

# Checking OSPF Passive Interfaces
def checking_ospf_passive(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking OSPF Passive Interfaces" + Style.RESET_ALL)

    try:
        # Retrieve OSPF process information
        ospf_processes_output = connection.send_command("show running-config | include router ospf").strip()
        ospf_processes = re.findall(r"router ospf (\d+)", ospf_processes_output)

        # If no OSPF processes are detected, assume OSPF is not in use
        if not ospf_processes:
            print(Fore.GREEN + "[!] No OSPF processes detected on this device." + Style.RESET_ALL)
            return

        # Retrieve OSPF interface and configuration details
        ospf_interfaces_output = connection.send_command("show ip ospf interface brief").strip()
        ospf_config_output = connection.send_command("show running-config | section router ospf").strip()

    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve OSPF configuration: {e}" + Style.RESET_ALL)
        return

    warnings = []

    # Identify passive interfaces in OSPF configuration
    passive_interfaces = re.findall(r"passive-interface (\S+)", ospf_config_output)
    passive_interfaces = [iface.replace("Vlan", "Vl") for iface in passive_interfaces]  # Adjust VLAN notation

    # Extract OSPF-enabled interfaces and their associated IPs
    ospf_interfaces = re.findall(r"(\S+)\s+\d+\s+\d+\s+([\d\.\/]+)", ospf_interfaces_output)

    # Identify interfaces that should be passive but are not
    for interface, ip in ospf_interfaces:
        if interface not in passive_interfaces:
            warnings.append(f"[WARNING] OSPF: Interface {interface} ({ip}) is not passive!")

    if warnings:
        # Warn if any OSPF interfaces are not set to passive
        print(Fore.YELLOW + "[!] WARNING: Some OSPF interfaces are not passive!" + Style.RESET_ALL)
        for warning in warnings:
            print(Fore.YELLOW + warning + Style.RESET_ALL)

    print(Fore.YELLOW + "[!] Enable passive interfaces for those networks where you don't want to see a malicious router." + Style.RESET_ALL)
    print(Fore.GREEN + "[*] Passive interfaces help defend against attacks on dynamic routing domains." + Style.RESET_ALL)

# Checking OSPF Authentication
def checking_ospf_auth(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking OSPF Authentication" + Style.RESET_ALL)

    try:
        # Retrieve OSPF interfaces brief output
        ospf_if_brief_output = connection.send_command("show ip ospf interface brief")
    except Exception as e:
        # Handle errors if command execution fails
        print(Fore.RED + f"[-] Failed to retrieve OSPF interface list: {e}" + Style.RESET_ALL)
        return

    # Regular expression to extract interface details from OSPF interface brief output
    pattern = r'^(\S+)\s+(\d+)\s+(\S+)\s+(\S+/\S+)\s+\S+\s+\S+\s+\S+/\S+'
    matches = re.findall(pattern, ospf_if_brief_output, re.MULTILINE)

    if not matches:
        # If no OSPF interfaces are found, exit function
        print(Fore.GREEN + "[*] No OSPF interfaces found." + Style.RESET_ALL)
        return

    # Lists to categorize authentication types per interface
    md5_list = []
    simple_list = []
    none_list = []

    # Iterate through each OSPF interface and check authentication status
    for intf_name, pid, area, ip_mask in matches:
        try:
            # Retrieve detailed OSPF interface information
            ospf_if_output = connection.send_command(f"show ip ospf interface {intf_name}")
        except Exception as e:
            # Handle errors if interface-specific command execution fails
            print(Fore.RED + f"[-] Failed to check interface {intf_name}: {e}" + Style.RESET_ALL)
            continue

        # Categorize authentication methods based on command output
        if "Cryptographic authentication enabled" in ospf_if_output:
            md5_list.append((intf_name, ip_mask))
        elif "Simple password authentication enabled" in ospf_if_output:
            simple_list.append((intf_name, ip_mask))
        else:
            none_list.append((intf_name, ip_mask))

    # Display warnings if insecure or missing authentication is detected
    if none_list or simple_list:
        print(Fore.RED + "[!] WARNING: Some OSPF interfaces have no or insecure authentication!" + Style.RESET_ALL)

    for intf_name, ip_mask in none_list:
        print(Fore.RED + f"[WARNING] OSPF: Interface {intf_name} ({ip_mask}) has no authentication!" + Style.RESET_ALL)

    for intf_name, ip_mask in simple_list:
        print(Fore.RED + f"[WARNING] OSPF: Interface {intf_name} ({ip_mask}) has Simple authentication!" + Style.RESET_ALL)

    # Display secure authentication configuration
    for intf_name, ip_mask in md5_list:
        print(Fore.GREEN + f"[OK] OSPF: Interface {intf_name} ({ip_mask}) has MD5 authentication!" + Style.RESET_ALL)

# Checking EIGRP Passive Interfaces
def checking_eigrp_passive(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking EIGRP Passive Interfaces" + Style.RESET_ALL)

    try:
        # Retrieve EIGRP process information
        eigrp_processes_output = connection.send_command("show running-config | include router eigrp").strip()
        eigrp_processes = re.findall(r"router eigrp (\d+)", eigrp_processes_output)

        # If no EIGRP processes are detected, assume EIGRP is not in use
        if not eigrp_processes:
            print(Fore.GREEN + "No EIGRP processes detected on this device." + Style.RESET_ALL)
            return

        # Retrieve EIGRP interfaces and configuration details
        eigrp_interfaces_output = connection.send_command("show ip eigrp interfaces").strip()
        eigrp_config_output = connection.send_command("show running-config | section router eigrp").strip()

    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve EIGRP configuration: {e}" + Style.RESET_ALL)
        return

    # Identify passive interfaces in EIGRP configuration
    passive_interfaces = re.findall(r"passive-interface (\S+)", eigrp_config_output)

    # Extract EIGRP-enabled interfaces
    eigrp_interfaces = re.findall(r"^(\S+)\s+\d+", eigrp_interfaces_output, re.MULTILINE)

    warnings = []

    # Identify interfaces that should be passive but are not
    for interface in eigrp_interfaces:
        if interface not in passive_interfaces:
            warnings.append(f"[WARNING] EIGRP: Interface {interface} is not passive!")

    if warnings:
        # Warn if any EIGRP interfaces are not set to passive
        print(Fore.YELLOW + "[!] WARNING: Some EIGRP interfaces are not passive!" + Style.RESET_ALL)
        for warning in warnings:
            print(Fore.YELLOW + warning + Style.RESET_ALL)

    print(Fore.YELLOW + "[!] Enable passive interfaces for those networks where you don't want to see a malicious router." + Style.RESET_ALL)
    print(Fore.GREEN + "[*] Passive interfaces help defend against attacks on dynamic routing domains." + Style.RESET_ALL)

# Checking EIGRP Authentication
def checking_eigrp_auth(connection):
    # Prints a visual separator for clarity
    print_separator()
    print(Fore.WHITE + Style.BRIGHT + "[*] Checking EIGRP Authentication" + Style.RESET_ALL)

    try:
        # Retrieve a list of interfaces running EIGRP
        eigrp_interfaces_output = connection.send_command("show ip eigrp interfaces").strip()
    except Exception as e:
        # Handle errors if the command execution fails
        print(Fore.RED + f"[-] Failed to retrieve EIGRP interfaces: {e}" + Style.RESET_ALL)
        return

    # Extract EIGRP-enabled interfaces
    eigrp_interfaces = re.findall(r"^(\S+)\s+\d+", eigrp_interfaces_output, re.MULTILINE)

    if not eigrp_interfaces:
        # If no EIGRP interfaces are found, exit
        print(Fore.GREEN + "[*] No EIGRP interfaces found." + Style.RESET_ALL)
        return

    md5_kc_list = []  # Interfaces with MD5 authentication and key-chain
    md5_only_list = []  # Interfaces with MD5 authentication but no key-chain
    none_list = []  # Interfaces with no authentication

    for interface in eigrp_interfaces:
        try:
            # Retrieve the running configuration for each interface
            run_int_output = connection.send_command(f"show run interface {interface}")
        except Exception as e:
            # Handle errors if unable to check the interface
            print(Fore.RED + f"[-] Failed to check interface {interface}: {e}" + Style.RESET_ALL)
            continue

        # Search for MD5 authentication mode
        md5_mode = re.search(r"ip authentication mode eigrp (\d+) md5", run_int_output)
        # Search for a key-chain used with MD5 authentication
        key_chain = re.search(r"ip authentication key-chain eigrp (\d+) (\S+)", run_int_output)

        if md5_mode and key_chain:
            # If both MD5 mode and key-chain are found
            md5_kc_list.append((interface, key_chain.group(2)))
        elif md5_mode:
            # If MD5 authentication is found but no key-chain
            md5_only_list.append(interface)
        else:
            # If no authentication is configured
            none_list.append(interface)

    # Display warnings if any interfaces lack authentication
    if none_list:
        print(Fore.RED + "[!] WARNING: Some EIGRP interfaces have no authentication!" + Style.RESET_ALL)
    for interface in none_list:
        print(Fore.RED + f"[WARNING] EIGRP: Interface {interface} has no authentication!" + Style.RESET_ALL)

    # Display interfaces with MD5 authentication but no key-chain
    for interface in md5_only_list:
        print(Fore.GREEN + f"[OK] EIGRP: Interface {interface} has MD5 mode configured (no key-chain detected)!" + Style.RESET_ALL)

    # Display interfaces with MD5 authentication and an assigned key-chain
    for interface, chain_name in md5_kc_list:
        print(Fore.GREEN + f"[OK] EIGRP: Interface {interface} has MD5 mode with key-chain '{chain_name}'!" + Style.RESET_ALL)

# Outro
def analysis_summary(start_time, device_type):
    """
    Prints a summary of the Cisco IOS security inspection, including elapsed time and device type.
    """
    # Calculate the total execution time
    end_time = datetime.datetime.now()
    elapsed_time = round((end_time - start_time).total_seconds(), 2)

    # Print completion banner
    print("=" * 60)
    print(Fore.CYAN + Style.BRIGHT + "[*] Cisco IOS Security Inspection COMPLETED" + Style.RESET_ALL)

    # Display the time taken for the inspection
    print(Fore.GREEN + f"[*] Time taken: {elapsed_time} seconds" + Style.RESET_ALL)

    # Determine the device type (Router or Switch)
    device_type_str = "Router" if device_type == "router" else "Switch"
    print(Fore.WHITE + f"[*] Device Type: {device_type_str}" + Style.RESET_ALL)

    # Display a cautionary note for reviewing findings
    print(Fore.YELLOW + "[!] Review the results carefully and apply necessary fixes" + Style.RESET_ALL)
    
    # Print closing separator
    print("=" * 60)

# Visual separator
def print_stage_separator(title="CHECKS", color=Fore.CYAN, width=30):
    """
    Prints a formatted section separator with a title for better readability of output.
    
    Args:
        title (str): The title displayed in the separator.
        color (Fore): The color of the separator text.
        width (int): The width of the separator lines.
    """
    print()  # Add an empty line for spacing

    # Create the top and bottom separator line
    top_bottom_line = "[" + "=" * width + "]"

    # Format the title line with a centered text and vertical bars
    middle_line = "|" + title.center(width) + "|"

    # Print the formatted separator with the specified color
    print(color + top_bottom_line + Style.RESET_ALL)
    print(color + middle_line + Style.RESET_ALL)
    print(color + top_bottom_line + Style.RESET_ALL)
    
    print()  # Add an empty line for spacing

# Main func
def main():
    """
    Main function to execute Cisco IOS Security Inspection.
    It connects to the target device, performs multiple security checks, and prints a summary.
    """
    # Display banner
    banner()

    # Argument parser to handle command-line options
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", required=True, help="Specify the IP address of the device")
    parser.add_argument("--username", required=True, help="SSH Username")
    parser.add_argument("--password", required=True, help="SSH Password")
    parser.add_argument("--port", type=int, default=22, help="SSH Port (default:22)")
    parser.add_argument("--router", action="store_true", help="Specify if the device is a router")
    parser.add_argument("--l2-switch", action="store_true", help="Specify if the device is a L2 switch")
    parser.add_argument("--l3-switch", action="store_true", help="Specify if the device is a L3 switch")
    args = parser.parse_args()

    # Ensure that exactly one device type is selected
    flags = [args.router, args.l2_switch, args.l3_switch]
    if sum(flags) != 1:
        print(Fore.YELLOW + "[!] You must specify exactly one device type: --router, --l2-switch, or --l3-switch." + Style.RESET_ALL)
        exit(1)

    # Determine the device type based on the argument
    if args.router:
        device_type = "router"
    elif args.l2_switch:
        device_type = "l2-switch"
    else:
        device_type = "l3-switch"

    # Track execution time
    start_time = datetime.datetime.now()

    # Establish SSH connection to the target device
    conn = connect_to_device(args.ip, args.username, args.password, args.port, device_type)

    # Perform system and operational checks
    print_stage_separator("SYSTEM & OPERATIONAL CHECKS", color=Fore.MAGENTA, width=50)
    check_device_uptime(conn)
    checking_config_size(conn)

    # Perform Cisco IOS security analysis
    print_stage_separator("IOS SECURITY ANALYZING", color=Fore.MAGENTA, width=50)
    checking_pad_service(conn)
    checking_service_password_encryption(conn)
    checking_password_hashing(conn)
    checking_rbac(conn)
    checking_vty_security(conn)
    checking_aaa(conn)
    checking_session_limit(conn)
    checking_login_block_protection(conn)
    checking_ssh_security(conn)
    checking_default_usernames(conn)
    checking_snmp(conn)
    checking_smart_install(conn)

    # Perform Layer 2 security checks if the device is a switch
    if args.l2_switch or args.l3_switch:
        print_stage_separator("L2 SECURITY ANALYZING", color=Fore.MAGENTA, width=50)
        checking_vtp_status(conn)
        checking_dtp_status(conn)
        checking_native_vlan(conn)
        checking_dhcp_snooping(conn)
        checking_dai(conn)
        checking_bpdu_guard(conn)
        checking_storm_control(conn)
        checking_port_security(conn)

    # Perform Layer 3 security checks if the device is a router or L3 switch
    if args.router or args.l3_switch:
        print_stage_separator("L3 SECURITY ANALYZING", color=Fore.MAGENTA, width=50)
        checking_hsrp(conn)
        checking_vrrp(conn)
        checking_glbp(conn)
        checking_ospf_passive(conn)
        checking_ospf_auth(conn)
        checking_eigrp_passive(conn)
        checking_eigrp_auth(conn)

    # Disconnect from the device
    if conn:
        conn.disconnect()

    # Display the final analysis summary
    analysis_summary(start_time, device_type)

if __name__ == "__main__":
    main()
