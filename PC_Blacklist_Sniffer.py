#PC_Blacklist_Sniffer.py

#TODO:
# ADD notification sounds
# ADD packet interval sounds
# ADD dynamic IPs detection
# ADD temporary iplookup files
# REMOVE sound from Windows notifications

#!/usr/bin/env python3
# Standard library imports
import os
import re
import sys
import uuid
import time
import json
import enum
import socket
import ctypes
import textwrap
import threading
import ipaddress
import subprocess
import webbrowser
from pathlib import Path
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network

# Third-party library imports
import psutil
import pyshark
import urllib3
import requests
import colorama
from colorama import Fore

if sys.version_info.major <= 3 and sys.version_info.minor < 9:
    print("To use this script, your Python version must be 3.9 or higher.")
    print("Please note that Python 3.9 is not compatible with Windows versions 7 or lower.")
    exit()

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__)) # os.getcwd()
os.chdir(SCRIPT_DIR)

colorama.init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.util.ssl_.DEFAULT_CIPHERS += "HIGH:!DH:!aNULL"
s = requests.Session()

class Version:
    def __init__(self, version:str):
        self.major = int(version[1])
        self.minor = int(version[3])
        self.patch = int(version[5])
        self.date = f"{version[9:19]}"
        self.version = f"v{version[1:6]}"
        self.version_date = f"{self.version} - {self.date}"

    def __str__(self):
        return self.version_date

class Updater:
    def __init__(self, current_version):
        self.current_version = current_version

    def check_for_update(self, latest_version):
        if latest_version.major > self.current_version.major:
            return True
        elif latest_version.major == self.current_version.major:
            if latest_version.minor > self.current_version.minor:
                return True
            elif latest_version.minor == self.current_version.minor:
                if latest_version.patch > self.current_version.patch:
                    return True
        return False

class Msgbox(enum.IntFlag):
    # https://stackoverflow.com/questions/50086178/python-how-to-keep-messageboxw-on-top-of-all-other-windows
    # https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw
    # https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/msgbox-function
    OKOnly = 0  # Display OK button only.
    OKCancel = 1  # Display OK and Cancel buttons.
    AbortRetryIgnore = 2  # Display Abort, Retry, and Ignore buttons.
    YesNoCancel = 3  # Display Yes, No, and Cancel buttons.
    YesNo = 4  # Display Yes and No buttons.
    RetryCancel = 5  # Display Retry and Cancel buttons.
    Critical = 16  # Display Critical Message icon.
    Question = 32  # Display Warning Query icon.
    Exclamation = 48  # Display Warning Message icon.
    Information = 64  # Display Information Message icon.
    DefaultButton1 = 0  # First button is default.
    DefaultButton2 = 256  # Second button is default.
    DefaultButton3 = 512  # Third button is default.
    DefaultButton4 = 768  # Fourth button is default.
    ApplicationModal = 0  # Application modal; the user must respond to the message box before continuing work in the current application.
    SystemModal = 4096  # System modal; all applications are suspended until the user responds to the message box.
    MsgBoxHelpButton = 16384  # Adds Help button to the message box.
    MsgBoxSetForeground = 65536  # Specifies the message box window as the foreground window.
    MsgBoxRight = 524288  # Text is right-aligned.
    MsgBoxRtlReading = 1048576  # Specifies text should appear as right-to-left reading on Hebrew and Arabic systems.

class ThirdPartyServers(enum.Enum):
    Discord = ["66.22.196.0/22"]
    GTA5 = ["26.0.0.0/8", "185.56.64.0/22", "192.81.241.0/24"]
    Minecraft = ["168.61.142.128/25", "168.61.143.0/24", "168.61.144.0/20", "168.61.160.0/19"]

def title(title):
    print(f"\033]0;{title}\007", end="")

def cls():
    print("\033c", end="")

def plural(variable):
    return "s" if variable > 1 else ""

def is_ip_address(string):
  try:
    ipaddress.ip_address(string)
    return True
  except ValueError:
    return False

def is_mac_address(string):
    pattern = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
    return pattern.match(string) is not None

def is_file_need_newline_ending(file):
    file = Path(file)
    if file.stat().st_size == 0:
        return False

    return not file.read_bytes().endswith(b"\n")

def get_mac_address():
    mac_address = hex(uuid.getnode()).replace("0x", "").upper()
    if len(mac_address) % 2:
        mac_address = "0{}".format(mac_address)
    return ":".join(mac_address[i:i+2] for i in range(0, len(mac_address), 2))

def get_local_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def show_message_box(title, message, style):
    return ctypes.windll.user32.MessageBoxW(0, message, title, style)

def npcap_or_winpcap_installed():
    try:
        subprocess.check_output(["sc", "query", "npcap"], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        try:
            subprocess.check_output(["sc", "query", "npf"], stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False

def reconstruct_settings():
    print("\nCorrect reconstruction of 'Settings.ini' ...")
    try:
        os.remove("file.txt")
    except FileNotFoundError:
        pass
    with open(SETTINGS_PATH, "w", encoding="utf-8") as file:
        # TODO:
        #;;<DETECTION_TYPE_DYNAMIC_IP_PRECISION>
        #;;The chosen number of octet(s) that will be used for the Dynamic IP lookup,
        #;;in order to lookup and detect the blacklisted users.
        #;;Valid values are '1-3'.
        #;;
        #DETECTION_TYPE_DYNAMIC_IP_PRECISION={DETECTION_TYPE_DYNAMIC_IP_PRECISION}
        text = f"""
            ;;-----------------------------------------------------------------------------
            ;;Lines starting with ";;" symbols are commented lines.
            ;;
            ;;This is the settings file for 'PC Blacklist Sniffer' configuration.
            ;;
            ;;If you don't know what value to choose for a specifc setting, set it's value to None.
            ;;The program will automatically analyzes this file and if needed will regenerate it if it contains errors.
            ;;
            ;;<BLACKLIST_PATH>
            ;;The file where you store the blacklisted users.
            ;;The Windows path where your Blacklist file is located.
            ;;
            ;;<INTERFACE_NAME>
            ;;Automatically select this network adapter where the packekts are going to be captured from.
            ;;
            ;;<STDOUT_DEBUG>
            ;;Determine if you want or not to show any detected IPs in real-time.
            ;;
            ;;<STDOUT_LOGGING>
            ;;Determine if you want or not to use <STDOUT_LOGGING_PATH>.
            ;;
            ;;<STDOUT_LOGGING_PATH>
            ;;Logs the results of the console on your computer disk.
            ;;The Windows path where your logging file is located.
            ;;
            ;;<NOTIFICATIONS>
            ;;Determine if you want or not to get notified when a blacklisted user is found.
            ;;
            ;;<NOTIFICATIONS_TIMER>
            ;;Time interval between which this will display a notification.
            ;;
            ;;<NOTIFICATIONS_PACKETS_INTERVAL>
            ;;Determine if you want or not to use <NOTIFICATIONS_PACKETS_INTERVAL_TIMER>.
            ;;
            ;;<NOTIFICATIONS_PACKETS_INTERVAL_TIMER>
            ;;Time interval between which this will not display <NOTIFICATIONS>
            ;;if the packets are still received from the blacklisted user.
            ;;Your PC will get hardly spammed if you send it too many notifications.
            ;;If you are having this problem, I recommend that you increase the number.
            ;;
            ;;<IP_AND_MAC_ADDRESS_AUTOMATIC>
            ;;Determine if you want or not to automaticly detect your <IP_ADDRESS> and <MAC_ADDRESS> addresses.
            ;;
            ;;<IP_ADDRESS>
            ;;Your PC local IP address. You can obtain it like that:
            ;;https://support.microsoft.com/en-us/windows/find-your-ip-address-in-windows-f21a9bbc-c582-55cd-35e0-73431160a1b9
            ;;Valid example value: 'x.x.x.x'
            ;;
            ;;<MAC_ADDRESS>
            ;;Your PC MAC address. You can obtain it from your PC:
            ;;https://support.microsoft.com/en-us/windows/find-your-ip-address-in-windows-f21a9bbc-c582-55cd-35e0-73431160a1b9
            ;;Valid example value:'xx:xx:xx:xx:xx:xx'
            ;;
            ;;<BLOCK_THIRD_PARTY_SERVERS>
            ;;Determine if you want or not to block the annoying IP ranges from servers that shouldn't be detected.
            ;;
            ;;<PROGRAM_PRESET>
            ;;A program preset that will help capturing the right packets for
            ;;your program and make <PROTECTION_RESTART_GAME_PATH> works.
            ;;Supported program presets are only 'GTA5' and 'Minecraft'.
            ;;Note that it supports Minecraft UWP and not the Java edition.
            ;;
            ;;<PROTECTION>
            ;;Determine if you want or not a protection when a blacklisted user is found.
            ;;Set it to 'False' to disable it or pick one from:
            ;;'Restart_Game'
            ;;'Exit_Game'
            ;;'Restart_PC'
            ;;'Shutdown_PC'
            ;;
            ;;<PROTECTION_RESTART_GAME_PATH>
            ;;The file that will be started when the <PROTECTION> is enable, from your desired <PROGRAM_PRESET>.
            ;;Note that for UWP apps, I've not been able to start them except for Minecraft <PROGRAM_PRESET>.
            ;;
            ;;<PYSHARK_PACKET_COUNT>
            ;;The chosen number of packet counted in the Python pyshark module.
            ;;Valid values are any number greater than 0.
            ;;Setting it to '0' will make it unlimitted.
            ;;Be aware that this is not recommended because when you are looking for many IPs at the same time,
            ;;the script will take longer to scan the IPs as the IPs will keep coming in at the same time,
            ;;which will cause the information provided by the script to be updated later than they should.
            ;;-----------------------------------------------------------------------------
            BLACKLIST_PATH={BLACKLIST_PATH}
            INTERFACE_NAME={INTERFACE_NAME}
            STDOUT_DEBUG={STDOUT_DEBUG}
            STDOUT_LOGGING={STDOUT_LOGGING}
            STDOUT_LOGGING_PATH={STDOUT_LOGGING_PATH}
            NOTIFICATIONS={NOTIFICATIONS}
            NOTIFICATIONS_TIMER={NOTIFICATIONS_TIMER}
            NOTIFICATIONS_PACKETS_INTERVAL={NOTIFICATIONS_PACKETS_INTERVAL}
            NOTIFICATIONS_PACKETS_INTERVAL_TIMER={NOTIFICATIONS_PACKETS_INTERVAL_TIMER}
            IP_AND_MAC_ADDRESS_AUTOMATIC={IP_AND_MAC_ADDRESS_AUTOMATIC}
            IP_ADDRESS={IP_ADDRESS}
            MAC_ADDRESS={MAC_ADDRESS}
            BLOCK_THIRD_PARTY_SERVERS={BLOCK_THIRD_PARTY_SERVERS}
            PROGRAM_PRESET={PROGRAM_PRESET}
            PROTECTION={PROTECTION}
            PROTECTION_RESTART_GAME_PATH={PROTECTION_RESTART_GAME_PATH}
            PYSHARK_PACKET_COUNT={PYSHARK_PACKET_COUNT}
        """
        text = textwrap.dedent(text).removeprefix("\n")
        file.write(text)

def apply_settings(settings_list):
    global need_rewrite_settings, settings_file_not_found
    settings_file_not_found = False
    need_rewrite_settings = False

    try:
        SETTINGS = SETTINGS_PATH.read_text("utf-8").splitlines(keepends=False)
    except FileNotFoundError:
        settings_file_not_found = True
        need_rewrite_settings = True

    for setting in (settings_list):
        def rewrite_settings():
            global need_rewrite_settings
            if need_rewrite_settings is False:
                need_rewrite_settings = True

        def return_setting(setting):
            if settings_file_not_found:
                return None

            for line in SETTINGS:
                line = line.rstrip("\n")
                corrected_line = line.strip()

                if corrected_line.startswith(";;"):
                    continue

                parts = corrected_line.split("=")
                try:
                    setting_name = parts[0]
                    setting_value = parts[1]
                except IndexError:
                    rewrite_settings()
                    continue

                if not line == corrected_line:
                    rewrite_settings()

                if setting_name == setting:
                    return setting_value

            return None

        # TODO:
        # DETECTION_TYPE_DYNAMIC_IP_PRECISION
        global BLACKLIST_PATH, INTERFACE_NAME, STDOUT_DEBUG, STDOUT_LOGGING, STDOUT_LOGGING_PATH, NOTIFICATIONS, NOTIFICATIONS_TIMER, NOTIFICATIONS_PACKETS_INTERVAL, NOTIFICATIONS_PACKETS_INTERVAL_TIMER, IP_AND_MAC_ADDRESS_AUTOMATIC, IP_ADDRESS, MAC_ADDRESS, BLOCK_THIRD_PARTY_SERVERS, PROGRAM_PRESET, PROTECTION, PROTECTION_RESTART_GAME_PATH, PYSHARK_PACKET_COUNT

        if setting == "BLACKLIST_PATH":
            BLACKLIST_PATH = return_setting(setting)
            if (
                BLACKLIST_PATH is None
                or BLACKLIST_PATH == "None"
            ):
                rewrite_settings()
                BLACKLIST_PATH = Path("Blacklist.ini")
            else:
                BLACKLIST_PATH = Path(BLACKLIST_PATH)
        elif setting == "INTERFACE_NAME":
            INTERFACE_NAME = return_setting(setting)
            if INTERFACE_NAME is None:
                rewrite_settings()
            elif INTERFACE_NAME == "None":
                INTERFACE_NAME = None
        elif setting == "STDOUT_DEBUG":
            STDOUT_DEBUG = return_setting(setting)
            if STDOUT_DEBUG == "True":
                STDOUT_DEBUG = True
            elif STDOUT_DEBUG == "False":
                STDOUT_DEBUG = False
            else:
                rewrite_settings()
                STDOUT_DEBUG = True
        elif setting == "STDOUT_LOGGING":
            STDOUT_LOGGING = return_setting(setting)
            if STDOUT_LOGGING == "True":
                STDOUT_LOGGING = True
            elif STDOUT_LOGGING == "False":
                STDOUT_LOGGING = False
            else:
                rewrite_settings()
                STDOUT_LOGGING = True
        elif setting == "STDOUT_LOGGING_PATH":
            STDOUT_LOGGING_PATH = return_setting(setting)
            if (
                STDOUT_LOGGING_PATH is None
                or STDOUT_LOGGING_PATH == "None"
            ):
                rewrite_settings()
                STDOUT_LOGGING_PATH = Path("Logs.txt")
            else:
                STDOUT_LOGGING_PATH = Path(STDOUT_LOGGING_PATH)
        elif setting == "NOTIFICATIONS":
            NOTIFICATIONS = return_setting(setting)
            if NOTIFICATIONS == "True":
                NOTIFICATIONS = True
            elif NOTIFICATIONS == "False":
                NOTIFICATIONS = False
            else:
                rewrite_settings()
                NOTIFICATIONS = True
        elif setting == "NOTIFICATIONS_TIMER":
            reset_current_setting__flag = False
            try:
                NOTIFICATIONS_TIMER = int(return_setting(setting))
            except (ValueError, TypeError):
                reset_current_setting__flag = True
            else:
                if NOTIFICATIONS_TIMER < 0:
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                rewrite_settings()
                NOTIFICATIONS_TIMER = 0
        elif setting == "NOTIFICATIONS_PACKETS_INTERVAL":
            NOTIFICATIONS_PACKETS_INTERVAL = return_setting(setting)
            if NOTIFICATIONS_PACKETS_INTERVAL == "True":
                NOTIFICATIONS_PACKETS_INTERVAL = True
            elif NOTIFICATIONS_PACKETS_INTERVAL == "False":
                NOTIFICATIONS_PACKETS_INTERVAL = False
            else:
                rewrite_settings()
                NOTIFICATIONS_PACKETS_INTERVAL = True
        elif setting == "NOTIFICATIONS_PACKETS_INTERVAL_TIMER":
            reset_current_setting__flag = False
            try:
                NOTIFICATIONS_PACKETS_INTERVAL_TIMER = int(return_setting(setting))
            except (ValueError, TypeError):
                reset_current_setting__flag = True
            else:
                if NOTIFICATIONS_PACKETS_INTERVAL_TIMER < 0:
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                rewrite_settings()
                NOTIFICATIONS_PACKETS_INTERVAL_TIMER = 0
        elif setting == "IP_AND_MAC_ADDRESS_AUTOMATIC":
            IP_AND_MAC_ADDRESS_AUTOMATIC = return_setting(setting)
            if IP_AND_MAC_ADDRESS_AUTOMATIC == "True":
                IP_AND_MAC_ADDRESS_AUTOMATIC = True
            elif IP_AND_MAC_ADDRESS_AUTOMATIC == "False":
                IP_AND_MAC_ADDRESS_AUTOMATIC = False
            else:
                rewrite_settings()
                IP_AND_MAC_ADDRESS_AUTOMATIC = True
        elif setting == "IP_ADDRESS":
            reset_current_setting__flag = False
            IP_ADDRESS = return_setting(setting)
            if IP_ADDRESS is None:
                reset_current_setting__flag = True
            elif IP_ADDRESS == "None":
                IP_ADDRESS = None
            else:
                if not is_ip_address(IP_ADDRESS):
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                rewrite_settings()
                IP_ADDRESS = None
        elif setting == "MAC_ADDRESS":
            reset_current_setting__flag = False
            MAC_ADDRESS = return_setting(setting)
            if MAC_ADDRESS is None:
                reset_current_setting__flag = True
            elif MAC_ADDRESS == "None":
                MAC_ADDRESS = None
            else:
                if not is_mac_address(MAC_ADDRESS):
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                rewrite_settings()
                MAC_ADDRESS = None
        elif setting == "BLOCK_THIRD_PARTY_SERVERS":
            BLOCK_THIRD_PARTY_SERVERS = return_setting(setting)
            if BLOCK_THIRD_PARTY_SERVERS == "True":
                BLOCK_THIRD_PARTY_SERVERS = True
            elif BLOCK_THIRD_PARTY_SERVERS == "False":
                BLOCK_THIRD_PARTY_SERVERS = False
            else:
                rewrite_settings()
                BLOCK_THIRD_PARTY_SERVERS = True
        elif setting == "PROGRAM_PRESET":
            reset_current_setting__flag = False
            PROGRAM_PRESET = return_setting(setting)
            if PROGRAM_PRESET is None:
                reset_current_setting__flag = True
            elif PROGRAM_PRESET == "None":
                PROGRAM_PRESET = None
            else:
                if not PROGRAM_PRESET in ["GTA5", "Minecraft"]:
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                rewrite_settings()
                PROGRAM_PRESET = None
        elif setting == "PROTECTION":
            PROTECTION = return_setting(setting)
            if PROTECTION == "False":
                PROTECTION == False
            else:
                if not PROTECTION in ["Restart_Game", "Exit_Game", "Restart_PC", "Shutdown_PC"]:
                    rewrite_settings()
                    PROTECTION = False
        elif setting == "PROTECTION_RESTART_GAME_PATH":
            reset_current_setting__flag = False
            PROTECTION_RESTART_GAME_PATH = return_setting(setting)
            if PROTECTION_RESTART_GAME_PATH is None:
                reset_current_setting__flag = True
            elif PROTECTION_RESTART_GAME_PATH == "None":
                PROTECTION_RESTART_GAME_PATH = None
            else:
                PROTECTION_RESTART_GAME_PATH = Path(PROTECTION_RESTART_GAME_PATH)
            if reset_current_setting__flag:
                rewrite_settings()
                PROTECTION_RESTART_GAME_PATH = None
        # TODO:
        #elif setting == "DETECTION_TYPE_DYNAMIC_IP_PRECISION":
        #    reset_current_setting__flag = False
        #    try:
        #        DETECTION_TYPE_DYNAMIC_IP_PRECISION = int(return_setting(setting))
        #    except (ValueError, TypeError):
        #        reset_current_setting__flag = True
        #    else:
        #        if not (0 <= DETECTION_TYPE_DYNAMIC_IP_PRECISION <= 4):
        #            reset_current_setting__flag = True
        #    if reset_current_setting__flag:
        #        rewrite_settings()
        #        DETECTION_TYPE_DYNAMIC_IP_PRECISION = 3
        elif setting == "PYSHARK_PACKET_COUNT":
            reset_current_setting__flag = False
            try:
                PYSHARK_PACKET_COUNT = int(return_setting(setting))
            except (ValueError, TypeError):
                reset_current_setting__flag = True
            else:
                if PYSHARK_PACKET_COUNT < 0:
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                rewrite_settings()
                PYSHARK_PACKET_COUNT = 30

    if need_rewrite_settings:
        reconstruct_settings()

TITLE = "PC Blacklist Sniffer"
VERSION = "v1.0.0 - 10/01/2023"

cls()
title(f"Searching for a new update - {TITLE}")
print("\nSearching for a new update ...\n")

error_updating__flag = False

try:
    response = s.get("https://raw.githubusercontent.com/Illegal-Services/PC-Blacklist-Sniffer/version/version.txt")
except:
    error_updating__flag = True
if not error_updating__flag:
    if response.status_code == 200:
        current_version = Version(VERSION)
        latest_version = Version(response.text)
        if Updater(current_version).check_for_update(latest_version):
            msgbox_title = TITLE
            msgbox_text = f"""
                New version found. Do you want to update ?

                Current version: {VERSION}
                Latest version : {latest_version}
            """
            msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
            msgbox_style = Msgbox.YesNo | Msgbox.Question
            errorlevel = show_message_box(msgbox_title, msgbox_text, msgbox_style)
            if errorlevel == 6:
                try:
                    response = s.get("https://raw.githubusercontent.com/Illegal-Services/PC-Blacklist-Sniffer/main/PC_Blacklist_Sniffer.py")
                except:
                    error_updating__flag = True
                else:
                    if response.status_code == 200:
                        Path(f"{Path(__file__).name}").write_bytes(response.content)
                        subprocess.Popen(["start", "python", f"{Path(__file__).name}"], shell=True)
                        exit()
                    else:
                        error_updating__flag = True
    else:
        error_updating__flag = True

if error_updating__flag:
    msgbox_title = TITLE
    msgbox_text = f"""
        ERROR: {TITLE} Failed updating itself.

        Do you want to open the '{TITLE}' project download page ?
        You can then download and run the latest version from there.
    """
    msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
    msgbox_style = Msgbox.YesNo | Msgbox.Exclamation
    errorlevel = show_message_box(msgbox_title, msgbox_text, msgbox_style)
    if errorlevel == 6:
        webbrowser.open("https://github.com/Illegal-Services/PC-Blacklist-Sniffer")
        exit()

cls()
title(f"Checking that 'Npcap' or 'WinpCap' driver is installed on your system - {TITLE}")
print("\nChecking that 'Npcap' or 'WinpCap' driver is installed on your system ...\n")

while True:
    if npcap_or_winpcap_installed():
        break
    else:
        webbrowser.open("https://nmap.org/npcap/")
        msgbox_title = TITLE
        msgbox_text = f"""
            ERROR: {TITLE} could not detect the 'Npcap' or 'WinpCap' driver installed on your system.

            Opening the 'Npcap' project download page for you.
            You can then download and install it from there and press "Retry".
        """
        msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
        msgbox_style = Msgbox.RetryCancel | Msgbox.Exclamation
        errorlevel = show_message_box(msgbox_title, msgbox_text, msgbox_style)
        if errorlevel == 2:
            exit()

cls()
title(f"Applying your custom settings from 'Settings.ini' - {TITLE}")
print("\nApplying your custom settings from 'Settings.ini' ...\n")

SETTINGS_PATH = Path("Settings.ini")

# TODO:
#"DETECTION_TYPE_DYNAMIC_IP_PRECISION"
apply_settings(["BLACKLIST_PATH","INTERFACE_NAME","STDOUT_DEBUG","STDOUT_LOGGING","STDOUT_LOGGING_PATH","NOTIFICATIONS","NOTIFICATIONS_TIMER","NOTIFICATIONS_PACKETS_INTERVAL","NOTIFICATIONS_PACKETS_INTERVAL_TIMER","IP_AND_MAC_ADDRESS_AUTOMATIC","IP_ADDRESS","MAC_ADDRESS","BLOCK_THIRD_PARTY_SERVERS","PROGRAM_PRESET","PROTECTION","PROTECTION_RESTART_GAME_PATH","PYSHARK_PACKET_COUNT"])

cls()
title(f"Capture network interface selection - {TITLE}")
print(f"\nCapture network interface selection ...\n")
interfaces = psutil.net_io_counters(pernic=True)

if INTERFACE_NAME in interfaces:
    iface_name = INTERFACE_NAME
else:
    cls()
    print()
    for i, item in enumerate(interfaces):
        print(f"{Fore.YELLOW}{i+1}{Fore.RESET}: {item}")
    print()
    while True:
        try:
            selection = int(input(f"Select your desired capture network interface ({Fore.YELLOW}1{Fore.RESET}-{Fore.YELLOW}{len(interfaces)}{Fore.RESET}): {Fore.YELLOW}"))
        except ValueError:
            print(f"{Fore.RED}ERROR{Fore.RESET}: You didn't provide a number.")
            continue
        if (
            selection >= 1
            and selection <= len(interfaces)
        ):
            break
        print(f"{Fore.RED}ERROR{Fore.RESET}: The number you provided is not matching with the available network interfaces.")
        continue
    iface_name = list(interfaces.keys())[selection-1]

cls()
title(f"Initializing addresses and establishing connection to your PC - {TITLE}")
print(f"\nInitializing addresses and establishing connection to your PC ...\n")

if IP_AND_MAC_ADDRESS_AUTOMATIC:
    old_ip_address = IP_ADDRESS
    old_mac_address = MAC_ADDRESS

    try:
        IP_ADDRESS = get_local_ip_address()
    except:
        IP_ADDRESS = None
    try:
        MAC_ADDRESS = get_mac_address()
    except:
        MAC_ADDRESS = None

    if not IP_ADDRESS:
        IP_ADDRESS = None
    elif IP_ADDRESS == "127.0.0.1":
        IP_ADDRESS = None
    if not MAC_ADDRESS:
        MAC_ADDRESS = None

    if (
        not old_ip_address == IP_ADDRESS
        or not old_mac_address == MAC_ADDRESS
    ):
        reconstruct_settings()

while True:
    if not IP_ADDRESS:
        msgbox_title = TITLE
        msgbox_text = """
        ERROR: Unable to establish connection to your computer's local IP Address.

        Open the file "Settings.ini" and enter your computer's local IP Address in <IP_ADDRESS> setting.
        """
        msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
        msgbox_style = Msgbox.RetryCancel | Msgbox.Exclamation
        show_message_box(msgbox_title, msgbox_text, msgbox_style)
        apply_settings(["IP_ADDRESS", "MAC_ADDRESS"])
    else:
        break

while True:
    if not MAC_ADDRESS:
        msgbox_title = TITLE
        msgbox_text = """
        ERROR: Unable to establish connection to your computer's MAC Address.

        Open the file "Settings.ini" and enter your computer's MAC Address in <MAC_ADDRESS> setting.
        """
        msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
        msgbox_style = Msgbox.RetryCancel | Msgbox.Exclamation
        show_message_box(msgbox_title, msgbox_text, msgbox_style)
        apply_settings(["IP_ADDRESS", "MAC_ADDRESS"])
    else:
        break

BPF_FILTER = f"dst or src host {IP_ADDRESS} and ether dst or src {MAC_ADDRESS} and ip and udp and not broadcast and not multicast and not port 53 and not port 80 and not port 443"

if BLOCK_THIRD_PARTY_SERVERS:
    ip_ranges_blocking_list = []

    for server in ThirdPartyServers:
        for ip_range in server.value:
            if ip_range not in ip_ranges_blocking_list:
                ip_ranges_blocking_list.append(ip_range)

    if ip_ranges_blocking_list:
        BPF_FILTER += f" and not net {' and not net '.join(ip_ranges_blocking_list)}"
else:
    if PROGRAM_PRESET == "GTA5":
        if ThirdPartyServers.GTA5.value:
            BPF_FILTER += f" and not net {' and not net '.join(ThirdPartyServers.GTA5.value)}"
    elif PROGRAM_PRESET == "Minecraft":
        if ThirdPartyServers.Minecraft.value:
            BPF_FILTER += f" and not net {' and not net '.join(ThirdPartyServers.Minecraft.value)}"

if PROGRAM_PRESET == "GTA5":
    DISPLAY_FILTER = "frame.len>=71 and frame.len<=999"
elif PROGRAM_PRESET == "Minecraft":
    DISPLAY_FILTER = "frame.len>=49 and frame.len<=1498"
else:
    DISPLAY_FILTER = None

title(f"Analyzing <BLACKLIST_PATH> setting failure(s) - {TITLE}")

while True:
    cls()
    print(f"\nAnalyzing <BLACKLIST_PATH> setting failure(s) ...\n")
    found_a_valid_entry__flag = False
    found_an_invalid_entry__flag = False

    try:
        blacklist = BLACKLIST_PATH.read_text("utf-8").splitlines(keepends=False)
    except FileNotFoundError:
        with open(BLACKLIST_PATH, "w", encoding="utf-8") as file:
            text = """
                ;;-----------------------------------------------------------------------
                ;;Lines starting with ";;" symbols are commented lines.
                ;;
                ;;This is the blacklist file for 'PC Blacklist Sniffer' configuration.
                ;;
                ;;Your blacklist MUST be formatted in the following way in order to work:
                ;;<USERNAME>=<IP ADDRESS>
                ;;-----------------------------------------------------------------------
            """
            dedented_text = textwrap.dedent(text).removeprefix("\n")
            file.write(dedented_text)
    else:
        for line in blacklist:
            line = line.rstrip().strip()
            if line.startswith(";;"):
                continue
            parts = line.split("=", maxsplit=2)
            if len(parts) < 2 or len(parts) > 2:
                print(f"Blacklisted entry [{line}] does not contain a username and IP address.")
                continue
            current_blacklisted_name = parts[0]
            current_blacklisted_ip = parts[1]

            if not current_blacklisted_name:
                if not current_blacklisted_ip:
                    print(f"Blacklisted entry [{line}] does not contain a username and IP address.")
                    continue

            if current_blacklisted_name:
                if current_blacklisted_ip:
                    if is_ip_address(current_blacklisted_ip):
                        if found_a_valid_entry__flag is False:
                            found_a_valid_entry__flag = True
                        continue
                    else:
                        if found_an_invalid_entry__flag is False:
                            found_an_invalid_entry__flag = True
                        print(f"Blacklisted entry [{current_blacklisted_name}={current_blacklisted_ip}] does not contain a valid IP address.")
                        continue
                else:
                    if found_an_invalid_entry__flag is False:
                        found_an_invalid_entry__flag = True
                    print(f"Blacklisted entry [{current_blacklisted_name}={current_blacklisted_ip}] does not contain a valid IP address.")
            else:
                if found_an_invalid_entry__flag is False:
                    found_an_invalid_entry__flag = True
                print(f"Blacklisted entry [{current_blacklisted_name}={current_blacklisted_ip}] does not contain a valid username.")

        if found_an_invalid_entry__flag:
            print("^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^")
            print("Unable to proceess this entrie(s) in your <BLACKLIST_PATH> setting.")
            print("Your blacklist MUST be formatted in the following way in order to work:")
            print("<USERNAME>=<IP ADDRESS>")
            print("Ensure that the IP address is correct, and check for the following errors:")
            print("The IP address must be composed of 4 octets of a number from 0 to 255 each separated by a dot.")
            print("^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^\n")

        if found_a_valid_entry__flag:
            break

    msgbox_title = TITLE
    msgbox_text = f"""
        ERROR: {TITLE} could not find any valid users in your <BLACKLIST_PATH> setting.

        Add your first entry and press "Retry" to start scanning.
    """
    msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
    msgbox_style = Msgbox.RetryCancel | Msgbox.Exclamation
    errorlevel = show_message_box(msgbox_title, msgbox_text, msgbox_style)
    if errorlevel == 2:
        exit()

cls()
title(f"Checking that 'Tshark' is installed on your system - {TITLE}")
print("\nChecking that 'Tshark' is installed on your system ...\n")

while True:
    try:
        capture = pyshark.LiveCapture(
            interface = iface_name,
            bpf_filter = BPF_FILTER,
            display_filter = DISPLAY_FILTER
        )
    except pyshark.tshark.tshark.TSharkNotFoundException:
        webbrowser.open("https://www.wireshark.org/download.html")
        msgbox_title = TITLE
        msgbox_text = f"""
            ERROR: 'pyshark' Python module could not detect 'Tshark' installed on your system.

            Opening the 'Tshark' project download page for you.
            You can then download and install it from there and press "Retry".
        """
        msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
        msgbox_style = Msgbox.RetryCancel | Msgbox.Exclamation
        errorlevel = show_message_box(msgbox_title, msgbox_text, msgbox_style)
        if errorlevel == 2:
            exit()
    else:
        break

ip_timers = {}
ip_lookup = {}

cls()
title(f"Sniffin' my babies IPs.   |IP:{IP_ADDRESS}|   |MAC:{MAC_ADDRESS}|   |Interface:{iface_name}| - {TITLE}")
print(f'\nStarted capturing on network interface "{iface_name}" ...\n')

while True:
    time.sleep(0.1)
    for packet in capture.sniff_continuously(packet_count=PYSHARK_PACKET_COUNT):
        # Skip Real-time Control Protocol (RTCP)
        # RTCP is used together with RTP e.g. for VoIP (see also VOIPProtocolFamily).
        # Block for example Discord IPs while you're in a voice call.
        if getattr(packet, "rtcp", False):
            continue

        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport

        if source_address == IP_ADDRESS:
            target = dict(
                ip = destination_address,
                port = destination_port
            )
        else:
            target = dict(
                ip = source_address,
                port = source_port
            )

        # Skip local and private IP Ranges.
        #https://stackoverflow.com/questions/45365482/python-ip-range-to-ip-range-match
        if any(IPv4Address(target["ip"]) in IPv4Network(ip) for ip in ["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"]):
            continue

        if STDOUT_DEBUG:
            print(f"[DEBUG]  {target['ip']:<16} ({target['port']})")

        blacklisited_names_list = []
        for line in BLACKLIST_PATH.read_text("utf-8").splitlines(keepends=False):
            line = line.rstrip().strip()
            if line.startswith(";;"):
                continue
            parts = line.split("=", maxsplit=2)
            if len(parts) < 2 or len(parts) > 2:
                continue
            current_blacklisted_name = parts[0]
            current_blacklisted_ip = parts[1]

            if target["ip"] == current_blacklisted_ip:
                blacklisted_detection_type = "Static IP"
                blacklisited_names_list.append(f"[{current_blacklisted_name}]")

        if not blacklisited_names_list:
            continue

        ip = target["ip"]
        port = target["port"]

        def requests_ip_lookup():
            def use_the_right_value_from(value1, value2):
                if value1 is None:
                    return value2
                return value1

            ip_lookup_main = dict(json.loads(s.get(f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query", verify=False, timeout=60).text))
            ip_lookup_main_backup = dict(json.loads(s.get(f"https://ipinfo.io/{ip}/json", verify=False, timeout=60).text))
            ip_lookup_vpn_and_type = dict(json.loads(s.get(f"https://proxycheck.io/v2/{ip}?vpn=1&port=1", verify=False, timeout=60).text))

            ip_lookup[ip] = {}

            # Python is trash:
            for item in ["status", "continent", "continentCode", "country", "countryCode", "region", "regionName", "city", "district", "zip", "lat", "lon", "timezone", "offset", "currency", "isp", "org", "as", "asname", "reverse", "mobile", "proxy", "hosting", "query"]:
                ip_lookup_main[item] = ip_lookup_main.get(item)
            for item in ["country", "region", "city", "timezone", "org", "hostname", "anycast", "loc", "postal"]:
                ip_lookup_main_backup[item] = ip_lookup_main_backup.get(item)
            for item in ["status", "proxy", "type"]:
                ip_lookup_vpn_and_type[ip][item] = dict(ip_lookup_vpn_and_type[ip]).get(item)

            ip_lookup[ip]["status"] = use_the_right_value_from(ip_lookup_main["status"], ip_lookup_vpn_and_type["status"])
            ip_lookup[ip]["continent"] = use_the_right_value_from(ip_lookup_main["continent"], None)
            ip_lookup[ip]["continentCode"] = use_the_right_value_from(ip_lookup_main["continentCode"], None)
            ip_lookup[ip]["country"] = use_the_right_value_from(ip_lookup_main["country"], None)
            ip_lookup[ip]["countryCode"] = use_the_right_value_from(ip_lookup_main["countryCode"], ip_lookup_main_backup["country"])
            ip_lookup[ip]["region"] = use_the_right_value_from(ip_lookup_main["region"], ip_lookup_main_backup["region"])
            ip_lookup[ip]["regionName"] = use_the_right_value_from(ip_lookup_main["regionName"], None)
            ip_lookup[ip]["city"] = use_the_right_value_from(ip_lookup_main["city"], ip_lookup_main_backup["city"])
            ip_lookup[ip]["district"] = use_the_right_value_from(ip_lookup_main["district"], None)
            ip_lookup[ip]["zip"] = use_the_right_value_from(ip_lookup_main["zip"], None)
            ip_lookup[ip]["lat"] = use_the_right_value_from(ip_lookup_main["lat"], None)
            ip_lookup[ip]["lon"] = use_the_right_value_from(ip_lookup_main["lon"], None)
            ip_lookup[ip]["timezone"] = use_the_right_value_from(ip_lookup_main["timezone"], ip_lookup_main_backup["timezone"])
            ip_lookup[ip]["offset"] = use_the_right_value_from(ip_lookup_main["offset"], None)
            ip_lookup[ip]["currency"] = use_the_right_value_from(ip_lookup_main["currency"], None)
            ip_lookup[ip]["isp"] = use_the_right_value_from(ip_lookup_main["isp"], None)
            ip_lookup[ip]["org"] = use_the_right_value_from(ip_lookup_main["org"], ip_lookup_main_backup["org"])
            ip_lookup[ip]["as"] = use_the_right_value_from(ip_lookup_main["as"], None)
            ip_lookup[ip]["asname"] = use_the_right_value_from(ip_lookup_main["asname"], None)
            ip_lookup[ip]["reverse"] = use_the_right_value_from(ip_lookup_main["reverse"], ip_lookup_main_backup["hostname"])
            ip_lookup[ip]["mobile"] = use_the_right_value_from(ip_lookup_main["mobile"], None)
            ip_lookup[ip]["proxy"] = use_the_right_value_from(ip_lookup_main["proxy"], None)
            ip_lookup[ip]["hosting"] = use_the_right_value_from(ip_lookup_main["hosting"], None)
            ip_lookup[ip]["query"] = use_the_right_value_from(ip_lookup_main["query"], None)
            ip_lookup[ip]["anycast"] = use_the_right_value_from(ip_lookup_main_backup["anycast"], None)
            ip_lookup[ip]["loc"] = use_the_right_value_from(ip_lookup_main_backup["loc"], None)
            ip_lookup[ip]["postal"] = use_the_right_value_from(ip_lookup_main_backup["postal"], None)
            ip_lookup[ip]["proxy_2"] = use_the_right_value_from(ip_lookup_vpn_and_type[ip]["proxy"], None)
            ip_lookup[ip]["type"] = use_the_right_value_from(ip_lookup_vpn_and_type[ip]["type"], None)

            if ip_lookup[ip]["status"] == "ok":
                ip_lookup[ip]["status"] = "success"
            elif ip_lookup[ip]["status"] == "error":
                ip_lookup[ip]["status"] = "fail"

            if ip_lookup[ip]["proxy_2"] == "yes":
                ip_lookup[ip]["proxy_2"] = "True"
            elif ip_lookup[ip]["proxy_2"] == "no":
                ip_lookup[ip]["proxy_2"] = "False"

            if ip_lookup[ip]["anycast"] is None:
                ip_lookup[ip]["anycast"] = False

            return ip_lookup[ip]

        def write_stdout():
            return f"User{plural(len(blacklisited_names_list))}:{usernames} | ReverseIP:{ip_lookup[ip]['reverse']} | IP:{ip} | Port:{port} | Time:{date_time} | Country:{ip_lookup[ip]['countryCode']} | Detection Type:{blacklisted_detection_type}"

        def protection():
            def protection_exit_game():
                for process in psutil.process_iter():
                    def terminate_process():
                        try:
                            process.terminate()
                            time.sleep(1)
                        except psutil.NoSuchProcess:
                            pass

                    if PROGRAM_PRESET == "GTA5":
                        if process.name() in ["GTA5.exe", "PlayGTAV.exe", "SocialClubHelper.exe", "Launcher.exe"]:
                            terminate_process()
                    elif PROGRAM_PRESET == "Minecraft":
                        if process.name() == "Minecraft.Windows.exe":
                            terminate_process()
                return False

            if PROTECTION in ["Restart_Game", "Exit_Game"]:
                while True:
                    time.sleep(0.1)
                    if not protection_exit_game():
                        break
                if PROTECTION == "Restart_Game":
                    if PROTECTION_RESTART_GAME_PATH:
                        time.sleep(3)
                        # I couldn't find a proper code to detect and start UWP apps properly. Only supporting Minecraft <PROGRAM_PRESET> for now.
                        # https://stackoverflow.com/questions/43696735/how-can-i-open-a-windows-10-app-with-a-python-script
                        # https://stackoverflow.com/questions/36293051/get-installed-application-list-in-uwp
                        # https://stackoverflow.com/questions/37085452/how-to-get-list-of-installed-windows-universal-apps
                        if PROGRAM_PRESET == "Minecraft":
                            os.system("start Minecraft:") # os.system(f"start explorer shell:appsfolder\{PROTECTION_RESTART_GAME_PATH}")
                        else:
                            os.startfile(f"{PROTECTION_RESTART_GAME_PATH}")
            elif PROTECTION == "Restart_PC":
                subprocess.run(["shutdown", "-r"])
            elif PROTECTION == "Shutdown_PC":
                subprocess.run(["shutdown", "-s"])

        t2 = time.perf_counter()
        now = datetime.now()
        hour_time = now.strftime("%H:%M:%S")
        date_time = now.strftime("%Y-%m-%d_%H:%M:%S")
        usernames = ", ".join(map(str, blacklisited_names_list))

        if not ip in ip_lookup:
            ip_lookup[ip] = requests_ip_lookup()

        print(write_stdout())

        if ip_timers:
            while True:
                time.sleep(0.1)
                retry__flag = False
                for current_ip in ip_timers:
                    if current_ip == ip:
                        continue
                    t1 = ip_timers[current_ip]
                    seconds_elapsed = round(t2 - t1)
                    if seconds_elapsed > NOTIFICATIONS_PACKETS_INTERVAL_TIMER:
                        del ip_timers[current_ip]
                        retry__flag = True
                        break
                if not retry__flag:
                    break

        if ip in ip_timers:
            t1 = ip_timers[ip]
            seconds_elapsed = round(t2 - t1)
            if seconds_elapsed < NOTIFICATIONS_PACKETS_INTERVAL_TIMER:
                ip_timers[ip] = t2
                continue
        ip_timers[ip] = t2

        if PROTECTION:
            protection()

        if STDOUT_LOGGING:
            with open(STDOUT_LOGGING_PATH, "a", encoding="utf-8") as file:
                if is_file_need_newline_ending(STDOUT_LOGGING_PATH):
                    newline = "\n"
                else:
                    newline = ""
                file.write(f"{newline}{write_stdout()}\n")

        msgbox_text = f"""
            #### Blacklisted user detected at {hour_time} ####
            User{plural(len(blacklisited_names_list))}: {usernames}
            IP: {ip}
            Port: {port}
            Country Code: {ip_lookup[ip]["countryCode"]}
            Detection Type: {blacklisted_detection_type}
            ############# IP Lookup ##############
            Reverse IP: {ip_lookup[ip]["reverse"]}
            Continent: {ip_lookup[ip]["continent"]}
            Country: {ip_lookup[ip]["country"]}
            City: {ip_lookup[ip]["city"]}
            Organization: {ip_lookup[ip]["org"]}
            ISP: {ip_lookup[ip]["isp"]}
            AS: {ip_lookup[ip]["as"]}
            AS Name: {ip_lookup[ip]["asname"]}
            Type: {ip_lookup[ip]["type"]}
            Proxy: {ip_lookup[ip]["proxy_2"]}
            Anycast: {ip_lookup[ip]["anycast"]}
            Mobile (cellular) connection: {ip_lookup[ip]["mobile"]}
            Proxy, VPN or Tor exit address: {ip_lookup[ip]["proxy"]}
            Hosting, colocated or data center: {ip_lookup[ip]["hosting"]}
        """
        msgbox_title = TITLE
        msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
        msgbox_text = textwrap.indent(msgbox_text, "    ")
        msgbox_style = Msgbox.OKOnly | Msgbox.Exclamation | Msgbox.SystemModal | Msgbox.MsgBoxSetForeground
        threading.Thread(target=show_message_box, args=(msgbox_title, msgbox_text, msgbox_style)).start()