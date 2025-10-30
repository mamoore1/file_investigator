import httpx
import ipaddress
import os
from datetime import datetime

from dotenv import load_dotenv
from flask import Flask, request, render_template
from markupsafe import escape

load_dotenv()

abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")
virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")

app = Flask(__name__)


@app.route("/")
def index():
    return "index"


@app.route("/check-ip", methods=["GET", "POST"])
def check_ip():
    if request.method == "GET":
        source = None
        results = None
    else:
        ip = request.form.get("ip")
        source = request.form.get("source")

        if not ip:
            return "<p> No IP address provided </p>"

        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            return "<p> Invalid IP address provided </p>"

        if source == "abuseipdb":
            results = check_ip_abuseipdb(ip)
        elif source == "virustotal":
            results = check_ip_virustotal(ip)
        else:
            return "<p> Invalid source provided </p>"

    return render_template("check_ip.html", results=results, source=source)

def check_ip_abuseipdb(ip: str):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip}
    headers = {"Accept": "application/json", "Key": abuseipdb_api_key}

    response = httpx.get(url, params=params, headers=headers)

    if not response.is_success:
        return "<p> Failed to get IP scores </p>"

    response_data = response.json()["data"]

    results = {
        "ip": response_data.get("ipAddress"),
        "country_code": response_data.get("countryCode"),
        "usage_type": response_data.get("usageType"),
        "isp": response_data.get("isp"),
        "domain": response_data.get("domain"),
        "abuse_confidence_score": response_data.get("abuseConfidenceScore"),
        "total_reports": response_data.get("totalReports"),
        "source": "AbuseIPDB API",
        "retrieved_at": datetime.now().isoformat(),
    }

    return results


def check_ip_virustotal(ip: str):
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
        "ip": response_data.get("id"),
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

    return results
