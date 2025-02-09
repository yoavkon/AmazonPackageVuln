#!/usr/bin/python3
import subprocess
import requests
import json
import argparse
import os
import osquery
from datetime import datetime

LOG_DIR = "/var/log/al_package_vuln"
LOG_FILE = f"{LOG_DIR}/report_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.log"
os.makedirs(LOG_DIR, exist_ok=True)

# Log a message into the log file and print it
def log_message(msg, error=False, warning=False):
    with open(LOG_FILE, "a") as log:
        log.write(msg + "\n")
    
    if (error):
        print("\033[1mERROR:    \033[91m" + msg + "\033[0m")
    if (warning):
        print("\033[1mWARN:     \033[33m" + msg + "\033[0m")
    else:
        print("\033[1mLOG:      \033[92m" + msg + "\033[0m")


# Use osquery to find all installed RPM pacakges
def get_installed_packages():
    try:
        instance = osquery.SpawnInstance()
        instance.open()

        """ res.response is a list of dicts containing
            packages e.g. {'name': 'openssl', 'version':'1.0.2k'} """
        res = instance.client.query("SELECT name, version FROM rpm_packages;")
        if res.status.code != 0:
            log_message(f"osquery failed to fetch query, status code: {res.status.code}", error=True)
            return []
        return res.response

    except Exception as e:
        log_message(f"Error while querying with osquery: {e}", error=True)
        return []


def get_installed_package(name):
    try:
        instance = osquery.SpawnInstance()
        instance.open()

        res = instance.client.query(f"SELECT name, version FROM rpm_packages WHERE name = '{name}';")
        if res.status.code != 0:
            log_message(f"osquery failed to fetch query, status code: {res.status.code}", error=True)
            return None
        if not res.response:
            log_message(f"Could not find package {name}", error=True)
            return None
        return res.response[0]

    except Exception as e:
        log_message(f"Error while querying with osquery: {e}", error=True)
        return None


def check_nvd_vulns(pkg):
    name = pkg['name']
    version = pkg['version']
    if name == 'kernel':
        part = "o"
        vendor = "linux"
        product = "linux_kernel"
    else:
        part = "a"
        vendor = name
        product = name

    cpe = f"cpe:2.3:{part}:{vendor}:{product}:{version}"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        json_data = response.json()
        cve_list = json_data.get("vulnerabilities", [])
        return [item["cve"]["id"] for item in cve_list]

    except Exception as e:
        log_message(f"NVD API request failed for {cpe}: {e}", error=True)
        return []


def check_osv_vulns(pkg):
    url = "https://api.osv.dev/v1/query"

    name = pkg['name']
    version = pkg['version']
    if name == 'kernel':
        ecosystem = "Linux"
    else:
        ecosystem = "Red Hat"

    data={
        "package": {"name": name, "ecosystem": ecosystem},
        "version": version
    }

    try:
        response = requests.post(url, json=data, timeout=10)
        response_data_json = response.json()
        vulns = [v["id"] for v in response_data_json.get("vulns", [])]
        return vulns
    
    except Exception as e:
        log_message(f"OSV API request failed for {pkg}: {e}", error=True)
        return []

    
def main():
    parser = argparse.ArgumentParser(
        description="Check installed software vulnerabilities"
    )
    parser.add_argument("-p", "--package", help="Check a specific RPM package", type=str)
    parser.add_argument("-k", "--kernel", help="Only check the kernel version", action='store_true')
    parser.add_argument("-d", "--database",
                        choices=["nvd", "osv"],
                        help="Choose vulnerability database. default: [osv]",
                        type=str)
    
    args = parser.parse_args()
    log_message(f"Today's date: {datetime.now().strftime('%d/%m/%Y')}")
    log_message("Starting vulnerability scan..")

    pkgs = []
    if args.kernel:
        package = get_installed_package('kernel')
        log_message(f"Running Linux kernel version {package['version']}")
        pkgs.append(package)
    elif args.package:
        package = get_installed_package(args.package)
        if package:
            log_message(f"Found package {args.package}: {package}")
            pkgs.append(package)
    else:
        pkgs = get_installed_packages()

    for pkg in pkgs:
        print(pkg)

        if args.database == "nvd":
            vulns = check_nvd_vulns(pkg)
        else:
            vulns = check_osv_vulns(pkg)

        if vulns:
            log_message(f"{pkg['name']} version {pkg['version']} is vulnerable: {vulns}", warning=True)
        else:
            log_message(f"No vulnerabilities found for {pkg}")


if __name__ == '__main__':
    main()


