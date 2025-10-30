from flask import Flask, request, render_template
from markupsafe import escape
from datetime import datetime
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

    response_data = response.json()["data"]

    results = {
        "ip": ip,
        "country_code": response_data.get("countryCode"),
        "usage_type": response_data.get("usageType"),
        "isp": response_data.get("isp"),
        "domain": response_data.get("domain"),
        "abuse_confidence_score": response_data.get("abuseConfidenceScore"),
        "total_reports": response_data.get("totalReports"),
        "source": "AbuseIPDB API",
        "retrieved_at": datetime.now().isoformat(),
    }

    return render_template("check_ip_abuseipdb.html", results=results)


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

    whois_data = response_data_attributes.get("whois")

    whois_dict = {}

    # Parse whoisdata
    for line in whois_data.splitlines():
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        whois_dict[key] = value

    whois_org_name = whois_dict.get("org-name")
    whois_abuse_mailbox = whois_dict.get("abuse-mailbox")

    results = {
        "ip": ip,
        "country": response_data_attributes.get("country"),
        "continent": response_data_attributes.get("continent"),
        "asn": response_data_attributes.get("asn"),
        "as_owner": response_data_attributes.get("as_owner"),
        "network": response_data_attributes.get("network"),
        "regional_internet_registry": response_data_attributes.get("regional_internet_registry"),
        "reputation_score": response_data_attributes.get("reputation"),
        "last_analysis_stats": response_data_attributes.get("last_analysis_stats"),
        "whois_org_name": whois_org_name,
        "abuse_mailbox": whois_abuse_mailbox,
        "whois_date": (
            response_data_attributes.get("last_modification_date")
            or response_data_attributes.get("whois_data")
        ),
        "source": "VirusTotal API",
        "retrieved_at": datetime.now().isoformat(),
    }

    return render_template("check_ip_virustotal.html", results=results)
