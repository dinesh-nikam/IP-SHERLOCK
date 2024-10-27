
import shodan
import requests
import os
import socket
import argparse
import time
import json
from censys.search.v2 import CensysHosts
from censys.search import CensysCerts

from censys.common.exceptions import CensysException
import re
from colorama import Fore, Style, init

author = "Dinesh Nikam"
version = "1.0.1"

# Initialize colorama for colored output
init(autoreset=False)

# Constants for configuration file
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "security_tools")
CONFIG_FILE = os.path.join(CONFIG_DIR, "api.conf")

# Ensure configuration directory exists
os.makedirs(CONFIG_DIR, exist_ok=True)

# Professional tool-like banner
def print_banner():
    banner = f"""
{Fore.BLUE}
 ██▓ ██▓███       ██████  ██░ ██ ▓█████  ██▀███   ██▓     ▒█████   ▄████▄   ██ ▄█▀
▓██▒▓██░  ██▒   ▒██    ▒ ▓██░ ██▒▓█   ▀ ▓██ ▒ ██▒▓██▒    ▒██▒  ██▒▒██▀ ▀█   ██▄█▒ 
▒██▒▓██░ ██▓▒   ░ ▓██▄   ▒██▀▀██░▒███   ▓██ ░▄█ ▒▒██░    ▒██░  ██▒▒▓█    ▄ ▓███▄░ 
░██░▒██▄█▓▒ ▒     ▒   ██▒░▓█ ░██ ▒▓█  ▄ ▒██▀▀█▄  ▒██░    ▒██   ██░▒▓▓▄ ▄██▒▓██ █▄ 
░██░▒██▒ ░  ░   ▒██████▒▒░▓█▒░██▓░▒████▒░██▓ ▒██▒░██████▒░ ████▓▒░▒ ▓███▀ ░▒██▒ █▄
░▓  ▒▓▒░ ░  ░   ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░▓  ░░ ▒░▒░▒░ ░ ░▒ ▒  ░▒ ▒▒ ▓▒
 ▒ ░░▒ ░        ░ ░▒  ░ ░ ▒ ░▒░ ░ ░ ░  ░  ░▒ ░ ▒░░ ░ ▒  ░  ░ ▒ ▒░   ░  ▒   ░ ░▒ ▒░
 ▒ ░░░          ░  ░  ░   ░  ░░ ░   ░     ░░   ░   ░ ░   ░ ░ ░ ▒  ░        ░ ░░ ░ 
 ░                    ░   ░  ░  ░   ░  ░   ░         ░  ░    ░ ░  ░ ░      ░  ░   
                                                                  ░               


{Style.RESET_ALL}
    """
    print(f"   {Fore.BLUE}Author{Style.RESET_ALL}   : {author}")
    print(f"   {Fore.BLUE}Version{Style.RESET_ALL}  : v{version}\n")
    print(banner)

# Argument parsing
def parse_arguments():
    parser = argparse.ArgumentParser(description="Security scanner using Shodan, Censys, GreyNoise, IPinfo, and VirusTotal.")
    parser.add_argument('-s', '--shodan', action='store_true', help='Use Shodan as the scanning service.')
    parser.add_argument('-c', '--censys', action='store_true', help='Use Censys as the scanning service.')
    parser.add_argument('-g', '--greynoise', action='store_true', help='Use GreyNoise as the scanning service.')
    parser.add_argument('-v', '--virustotal', action='store_true', help='Use VirusTotal as the scanning service.')
    parser.add_argument('-i', '--ipinfo', action='store_true', help='Use IPinfo as the scanning service.')
    parser.add_argument('-ip', '--ip', help='Target IP address to query.')
    parser.add_argument('-a', '--all', action='store_true', help='Generate a summarized report from all available APIs.')
    parser.add_argument('-d', '--domain', help='Target domain to query.')
    parser.add_argument('-p', '--port-info', action='store_true', help='Fetch port information (Shodan only).')

    return parser.parse_args()


def ip_validation(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

# Domain validation
def domain_validation(domain):
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9]'  
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'  
        r'+[a-zA-Z]{2,6}\.?$'  
    )
    return bool(domain_regex.match(domain))


def load_api_credentials():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as file:
            lines = file.readlines()
            credentials = {line.split('=')[0]: line.split('=')[1].strip() for line in lines}
            required_keys = ['shodan_api', 'censys_api_id', 'censys_api_secret', 
                             'greynoise_api', 'ipinfo_api', 'virustotal_api']
            
            # Check for missing keys
            missing_keys = [key for key in required_keys if key not in credentials]
            if missing_keys:
                print(f"{Fore.RED}Missing API keys: {', '.join(missing_keys)}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Please update your config file or input the missing keys.{Style.RESET_ALL}")
                exit(1)  # Exit the program if keys are missing
            
            return credentials
    else:
        api_key = input("Please enter your Shodan API key: ")
        api_id = input("Please enter your Censys API ID: ")
        api_secret = input("Please enter your Censys API Secret: ")
        greynoise_key = input("Please enter your GreyNoise API key: ")
        ipinfo_key = input("Please enter your IPinfo API key: ")
        virustotal_key = input("Please enter your VirusTotal API key: ")
        with open(CONFIG_FILE, 'w') as file:
            file.write(f"shodan_api={api_key}\n")
            file.write(f"censys_api_id={api_id}\n")
            file.write(f"censys_api_secret={api_secret}\n")
            file.write(f"greynoise_api={greynoise_key}\n")
            file.write(f"ipinfo_api={ipinfo_key}\n")
            file.write(f"virustotal_api={virustotal_key}\n")
        return {"shodan_api": api_key, "censys_api_id": api_id, "censys_api_secret": api_secret, 
                "greynoise_api": greynoise_key, "ipinfo_api": ipinfo_key, "virustotal_api": virustotal_key}

def print_result(json_data):
    print(f"\n{Fore.CYAN}=== API Response ==={Style.RESET_ALL}\n")  # Title for clarity
    if isinstance(json_data, dict) and json_data:  # Check if json_data is a non-empty dictionary
        for key, value in json_data.items():
            print(f"{Fore.CYAN}{key}{Style.RESET_ALL}: ", end="")  # Print the key
            if isinstance(value, dict):  # If the value is a dictionary, print it in a structured format
                print(f"\n{Fore.GREEN}{json.dumps(value, indent=4)}{Style.RESET_ALL}")  # Pretty print the dict
            else:
                print(f"{Fore.YELLOW}{value}{Style.RESET_ALL}")  # Print non-dict values
            print("-" * 50)  # Separator for each key-value pair
    else:
        print(f"{Fore.RED}No data found or invalid response.{Style.RESET_ALL}")  # Handle empty or invalid data


# def print_result(json_data):
    for key, value in json_data.items():
        print(f"{Fore.CYAN}{key}{Style.RESET_ALL}: ", end="")
        if isinstance(value, dict):
            print(f"{Fore.GREEN}{value}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}{value}{Style.RESET_ALL}")
# def print_result(data, color_output=True):
  
#     init(autoreset=True)

#     json_data = json.dumps(data, indent=4)

#     if color_output:
      
#         key_color = Fore.GREEN
#         value_color = Fore.CYAN
#         separator_color = Fore.RED

       
#         colored_json = ""
#         inside_key = False
#         inside_value = False
#         for char in json_data:
#             if char == '"':
#                 if not inside_key and not inside_value:  # Start of a key
#                     colored_json += key_color + char
#                     inside_key = True
#                 elif inside_key:  # End of a key
#                     colored_json += char + Style.RESET_ALL
#                     inside_key = False
#                 elif not inside_key and not inside_value:  # Start of a value
#                     colored_json += value_color + char
#                     inside_value = True
#                 else:  # End of a value
#                     colored_json += char + Style.RESET_ALL
#                     inside_value = False
#             elif inside_key or inside_value:
#                 colored_json += char
#             else:
#                 # For separators like colons, commas, brackets, etc.
#                 if char == ":":
#                     colored_json += f"{separator_color}{char}{Style.RESET_ALL}"
#                 else:
#                     colored_json += char

#         print(colored_json)
#     else:
#         # If color_output is False, just print regular JSON (no colors)
#         print(json_data)


def shodan_ip_info(api, ip_address):
    try:
        info = api.host(ip_address)
        print(f"\n{Fore.CYAN}=== Shodan IP Information for {ip_address} ==={Style.RESET_ALL}\n")
        print_result(info)
    except shodan.APIError as e:
        print(f"{Fore.RED}Shodan API error: {e}{Style.RESET_ALL}")


def shodan_port_info(ip_address):
    try:
        host = requests.get(f"https://internetdb.shodan.io/{ip_address}").json()
        print(f"\n{Fore.CYAN}=== Shodan Port Information for {ip_address} ==={Style.RESET_ALL}\n")
        print_result(host)
    except Exception as e:
        print(f"{Fore.RED}Error retrieving port information: {e}{Style.RESET_ALL}")


def censys_ip_info(client, ip_address):
    try:
        info = client.view(ip_address)
        print(f"\n{Fore.CYAN}=== Censys IP Information for {ip_address} ==={Style.RESET_ALL}\n")
        print_result(info)
    except CensysException as e:
        print(f"{Fore.RED}Censys API error: {e}{Style.RESET_ALL}")


def censys_ip_cert_info(client, ip_address):
    try:
        host_info = client.view(ip_address)
        print(f"\n{Fore.CYAN}=== Censys Host Information for {ip_address} ==={Style.RESET_ALL}\n")
        print_result(host_info)

        # Check if the certificates method exists
        if hasattr(client, 'certificates'):
            certs = client.certificates(ip_address)
            print(f"\n{Fore.CYAN}=== Censys Certificate Information for {ip_address} ==={Style.RESET_ALL}\n")
            print_result(certs)
        else:
            print(f"{Fore.YELLOW}Warning: 'certificates' method not found in client{Style.RESET_ALL}")
    
    except CensysException as e:
        print(f"{Fore.RED}Censys API error: {e}{Style.RESET_ALL}")



# GreyNoise IP information
def greynoise_ip_info(api_key, ip_address):
    try:
        headers = {"key": api_key}
        response = requests.get(f"https://api.greynoise.io/v3/community/{ip_address}", headers=headers)
        if response.status_code == 200:
            info = response.json()
            print(f"\n{Fore.CYAN}=== GreyNoise IP Information for {ip_address} ==={Style.RESET_ALL}\n")
            print_result(info)
        else:
            print(f"{Fore.RED}GreyNoise API error: {response.status_code} - {response.text}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error with GreyNoise API: {e}{Style.RESET_ALL}")

# IPinfo IP information
def ipinfo_ip_info(api_key, ip_address):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}?token={api_key}")
        if response.status_code == 200:
            info = response.json()
            print(f"\n{Fore.CYAN}=== IPinfo IP Information for {ip_address} ==={Style.RESET_ALL}\n")
            print_result(info)
        else:
            print(f"{Fore.RED}IPinfo API error: {response.status_code} - {response.text}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error with IPinfo API: {e}{Style.RESET_ALL}")

# VirusTotal IP information
def virustotal_ip_info(api_key, ip_address):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            info = response.json()
            print(f"\n{Fore.CYAN}=== VirusTotal IP Information for {ip_address} ==={Style.RESET_ALL}\n")
            print_result(info)
        else:
            print(f"{Fore.RED}VirusTotal API error: {response.status_code} - {response.text}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error with VirusTotal API: {e}{Style.RESET_ALL}")


# Summarized report function for all APIs
def summarize_all_apis(credentials, ip_address):
    # Shodan
    try:
        print(f"\n{Fore.CYAN}=== Shodan Summary for {ip_address} ==={Style.RESET_ALL}\n")
        api = shodan.Shodan(credentials['shodan_api'])
        shodan_ip_info(api, ip_address)
        shodan_port_info(ip_address)
    except Exception as e:
        print(f"{Fore.RED}Error with Shodan: {e}{Style.RESET_ALL}")

    # Censys
    try:
        print(f"\n{Fore.CYAN}=== Censys Summary for {ip_address} ==={Style.RESET_ALL}\n")
        client = CensysHosts(api_id=credentials['censys_api_id'], api_secret=credentials['censys_api_secret'])
        censys_ip_cert_info(client, ip_address)
    except Exception as e:
        print(f"{Fore.RED}Error with Censys: {e}{Style.RESET_ALL}")

    # GreyNoise
    try:
        print(f"\n{Fore.CYAN}=== GreyNoise Summary for {ip_address} ==={Style.RESET_ALL}\n")
        greynoise_ip_info(credentials['greynoise_api'], ip_address)
    except Exception as e:
        print(f"{Fore.RED}Error with GreyNoise: {e}{Style.RESET_ALL}")

    # IPinfo
    try:
        print(f"\n{Fore.CYAN}=== IPinfo Summary for {ip_address} ==={Style.RESET_ALL}\n")
        ipinfo_ip_info(credentials['ipinfo_api'], ip_address)
    except Exception as e:
        print(f"{Fore.RED}Error with IPinfo: {e}{Style.RESET_ALL}")

    # VirusTotal
    try:
        print(f"\n{Fore.CYAN}=== VirusTotal Summary for {ip_address} ==={Style.RESET_ALL}\n")
        virustotal_ip_info(credentials['virustotal_api'], ip_address)
    except Exception as e:
        print(f"{Fore.RED}Error with VirusTotal: {e}{Style.RESET_ALL}")

   


# Rate limiting to avoid hitting API request limits
def rate_limit():
    print(f"{Fore.YELLOW}Rate limiting: Sleeping for 1 second to avoid API request limits.{Style.RESET_ALL}")
    time.sleep(1)

# Main logic
def main():
    print_banner()
    args = parse_arguments()
    credentials = load_api_credentials()





    if args.all:
        if args.ip and ip_validation(args.ip):
            summarize_all_apis(credentials, args.ip)
        elif args.domain and domain_validation(args.domain):
            ip_address = socket.gethostbyname(args.domain)
            summarize_all_apis(credentials, ip_address)
        else:
            print(f"{Fore.RED}Invalid IP or domain. Please check your input.{Style.RESET_ALL}")
        return

    # Shodan logic
    if args.shodan:
        api_key = credentials['shodan_api']
        api = shodan.Shodan(api_key)

        if args.ip and ip_validation(args.ip):
            shodan_ip_info(api, args.ip)
            if args.port_info:
                shodan_port_info(args.ip)
        elif args.domain and domain_validation(args.domain):
            ip_address = socket.gethostbyname(args.domain)
            shodan_ip_info(api, ip_address)
            if args.port_info:
                shodan_port_info(ip_address)
        else:
            print(f"{Fore.RED}Invalid IP or domain. Please check your input.{Style.RESET_ALL}")

    # Censys logic
    elif args.censys:
        api_id, api_secret = credentials['censys_api_id'], credentials['censys_api_secret']
        client = CensysHosts(api_id=api_id, api_secret=api_secret)

        if args.ip and ip_validation(args.ip):
            censys_ip_info(client, args.ip)
        
        elif args.domain and domain_validation(args.domain):
            ip_address = socket.gethostbyname(args.domain)
            censys_ip_info(client, ip_address)
        else:
            print(f"{Fore.RED}Invalid IP or domain. Please check your input.{Style.RESET_ALL}")
        
    # GreyNoise logic
    elif args.greynoise:
        api_key = credentials['greynoise_api']

        if args.ip and ip_validation(args.ip):
            greynoise_ip_info(api_key, args.ip)
        elif args.domain and domain_validation(args.domain):
            ip_address = socket.gethostbyname(args.domain)
            greynoise_ip_info(api_key, ip_address)
        else:
            print(f"{Fore.RED}Invalid IP or domain. Please check your input.{Style.RESET_ALL}")

    # IPinfo logic
    elif args.ipinfo:
        api_key = credentials['ipinfo_api']

        if args.ip and ip_validation(args.ip):
            ipinfo_ip_info(api_key, args.ip)
        elif args.domain and domain_validation(args.domain):
            ip_address = socket.gethostbyname(args.domain)
            ipinfo_ip_info(api_key, ip_address)
        else:
            print(f"{Fore.RED}Invalid IP or domain. Please check your input.{Style.RESET_ALL}")

    # VirusTotal logic
    elif args.virustotal:
        api_key = credentials['virustotal_api']

        if args.ip and ip_validation(args.ip):
            virustotal_ip_info(api_key, args.ip)
        elif args.domain and domain_validation(args.domain):
            ip_address = socket.gethostbyname(args.domain)
            virustotal_ip_info(api_key, ip_address)
        else:
            print(f"{Fore.RED}Invalid IP or domain. Please check your input.{Style.RESET_ALL}")

    rate_limit()

if __name__ == "__main__":
    main()



