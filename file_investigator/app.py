from flask import Flask, request
from markupsafe import escape
import ipaddress
import httpx
import os


abuseipdb_api_key = os.environ.get("ABUSEIPDB_API_KEY")
virustotal_api_key = os.environ.get("VIRUSTOTAL_API_KEY")

app = Flask(__name__)


@app.route("/")
def index():
    return "<p>Welcome To the Index Page</p>"


@app.route("/check-ip-abuseipdb")
def check_ip_abuseipdb():
    ip = request.args.get("ip")

    if not ip:
        return "<p> No IP address provided"

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return "<p> Invalid IP address provided </p>"


    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip}
    headers = {"Accept": "application/json", "Key": abuseipdb_api_key}

    response = httpx.get(url, params=params, headers=headers)

    if not response.is_success:
        return "<p> Failed to get IP scores </p>"

    response_json = response.json()["data"]

    return (
        f"<p>IP Address: {ip}, Country Code: {response_json.get('countryCode')}, "
        f"Usage Type: {response_json.get('usageType')}, Domain: {response_json.get('domain')}, "
        f"Abuse Confidence Score: {response_json.get('abuseConfidenceScore')}, "
        f"Total Reports: {response_json.get('totalReports')}<p>"
    )


@app.route("/check-ip-virustotal")
def check_ip_virustotal():
    ip = request.args.get("ip")

    if not ip:
        return "<p> No IP address provided"

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return "<p> Invalid IP address provided </p>"

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "Accept": "application/json",
        "x-apikey": virustotal_api_key
    }

    response = httpx.get(url, headers=headers)

    if not response.is_success:
        return "<p> Failed to get IP results </p>"

    response_data = response.json()["data"]
    response_data_attributes = response_data.get("attributes")

    country = response_data_attributes.get("country")
    continent = response_data_attributes.get("continent")
    asn = response_data_attributes.get("asn")
    as_owner = response_data_attributes.get("as_owner")
    network = response_data_attributes.get("network")
    regional_internet_registry = response_data_attributes.get("regional_internet_registry")
    reputation_score = response_data_attributes.get("reputation")
    last_analysis_stats = response_data_attributes.get("last_analysis_stats")
    whois_data = response_data_attributes.get("whois")

    whois_dict = {}

    # Filter whoisdata
    for line in whois_data.splitlines():
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        whois_dict[key] = value

    whois_org_name = whois_dict.get("org-name")
    whois_abuse_mailbox = whois_dict.get("abuse-mailbox")

    whois_date = response_data_attributes.get("last_modification_date") or response_data_attributes.get("whois_data")

    return str(
        {
            "Country": country,
            "Continent": continent,
            "ASN": asn,
            "AS Owner": as_owner,
            "Network": network,
            "Regional Internet Registry": regional_internet_registry,
            "Reputation Score": reputation_score,
            "Last Analysis Stats": last_analysis_stats,
            "WHOIS": whois_org_name,
            "Abuse Mailbox": whois_abuse_mailbox,
            "WHOIS Data": whois_date
        }
    )
