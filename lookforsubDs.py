import csv
import os
import requests
import dns.resolver
import socket
import json
from datetime import datetime
from alive_progress import alive_bar


def get_subdomains_from_web(domain):
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url)
        response.raise_for_status()

        if response.headers.get('Content-Type') != 'application/json':
            return [(None, "Web", None, None, None, None, None, None, "Invalid content type in response")]

        if not response.content:
            return [(None, "Web", None, None, None, None, None, None, "Empty response from crt.sh")]

        certificates = response.json()
        subdomains = []

        for cert in certificates:
            common_name = cert["common_name"].lower()
            if common_name.endswith(f".{domain}"):
                subdomains.append((common_name, "Web", None, None, None, None, None, None, None))

        return subdomains
    except requests.RequestException as e:
        return [(None, "Web", None, None, None, None, None, None, f"Error fetching subdomains from the web: {e}")]


def get_subdomains_from_dns(domain):
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(domain, "CNAME", lifetime=10)
        subdomains = [(str(answer.target)[:-1], "DNS", None, None, None, None, None, None, None) for answer in answers]
        return subdomains
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout) as e:
        return [(None, "DNS", None, None, None, None, None, None, f"DNS error for {domain}: {e}")]


def get_location(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        response.raise_for_status()
        data = response.json()
        return data.get('country', None), data.get('regionName', None), data.get('city', None)
    except requests.RequestException as e:
        return None, None, None


def get_isp_and_cloud_service(ip_address):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        response.raise_for_status()
        data = response.json()
        return data.get('org', None), data.get('company', {}).get('name', None)
    except requests.RequestException as e:
        return None, None


if __name__ == "__main__":
    import argparse

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Scan hosts from a file and gather information")
    parser.add_argument("-f", "--file", required=True, help="Path to the file containing list of hosts to scan")
    parser.add_argument("-o", "--output", default="Foundsubs.csv", help="Output filename (default: Foundsubs.csv)")
    args = parser.parse_args()

    all_subdomains = set()

    with open(args.file, "r") as file:
        domains = file.read().splitlines()

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    reports_dir = "Reports"

    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    csv_output_filename = os.path.join(reports_dir, f"{args.output}_{timestamp}.csv")

    with open(csv_output_filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Subdomain", "Source", "IP Address", "Country", "Region", "City", "ISP", "Cloud Service", "Error"])

        total_domains = len(domains)
        with alive_bar(total_domains, title="Processing domains", bar="smooth", spinner="dots_waves") as bar:
    # Your code using the 'bar' object goes here
            for domain in domains:
                subdomains_from_web = get_subdomains_from_web(domain)
                subdomains_from_dns = get_subdomains_from_dns(domain)
                all_subdomains.update(subdomains_from_web)
                all_subdomains.update(subdomains_from_dns)

                for subdomain, source, _, _, _, _, _, _, error in all_subdomains:
                    if subdomain:
                        try:
                            ip_address = socket.gethostbyname(subdomain)
                            country, region, city = get_location(ip_address)
                            isp, cloud_service = get_isp_and_cloud_service(ip_address)
                            writer.writerow([subdomain, source, ip_address, country, region, city, isp, cloud_service, error])
                        except socket.gaierror as e:
                            writer.writerow([subdomain, source, None, None, None, None, None, None, f"Socket error: {e}"])
                bar()
