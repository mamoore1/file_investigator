import dataclasses
import httpx
import ipaddress
import os
import re
from datetime import datetime

from dotenv import load_dotenv
from flask import Flask, request, render_template


load_dotenv()

abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")
virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/check-ip", methods=["GET", "POST"])
def check_ip():
    source = None
    results = None
    error = None

    if request.method == "POST":
        ip = request.form.get("ip")
        source = request.form.get("source")

        if not ip:
            error = "No IP address provided."
        else:
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                error = "Invalid IP address provided."

        if not error:
            if source == "abuseipdb":
                results = check_ip_abuseipdb(ip)
            elif source == "virustotal":
                results = check_ip_virustotal(ip)
            else:
                raise ValueError("Invalid source provided.")

    return render_template("check_ip.html", results=results, source=source, error=error)


def check_ip_abuseipdb(ip: str):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip}
    headers = {"Accept": "application/json", "Key": abuseipdb_api_key}

    response = httpx.get(url, params=params, headers=headers)

    if not response.is_success:
        raise RuntimeError("IP scores not found.")

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
        raise RuntimeError("Failed to get IP results.")

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

# TODO: add caching so we don't burn through API calls
@app.route("/file-report", methods=["GET", "POST"])
def file_report():

    file_id = None
    summary = None
    error = None
    mitre_data = None

    if request.method == "POST":
        file_id = request.form.get("file_id")

        if not is_valid_hash(file_id):
            error = "Invalid file hash provided. Must be MD5, SHA-1 or SHA256"

        if not error:
            url = f"https://www.virustotal.com/api/v3/files/{file_id}"
            headers = {"x-apikey": virustotal_api_key}
            response = httpx.get(url, headers=headers)

            if response.is_success:
                response_json = response.json()

                first_seen = response_json["data"]["attributes"]["first_submission_date"]
                first_seen = datetime.fromtimestamp(first_seen).isoformat()

                summary = {
                    "file_name": response_json["data"]["attributes"].get("meaningful_name"),
                    "sha256": response_json["data"]["attributes"].get("sha256"),
                    "file_type": response_json["data"]["attributes"].get("type_description"),
                    "size": response_json["data"]["attributes"].get("size"),
                    "malicious": response_json["data"]["attributes"].get("last_analysis_stats", {}).get("malicious"),
                    "total_engines": sum(response_json["data"]["attributes"].get("last_analysis_stats", {}).values()),
                    "reputation": response_json["data"]["attributes"].get("reputation"),
                    "first_seen": first_seen,
                    "compiler": response_json["data"]["attributes"].get("detectiteasy", {}).get("values", []),
                    "tags": response_json["data"]["attributes"].get("tags", []),
                    "source": "VirusTotal API",
                    "retrieved_at": datetime.now().isoformat(),
                }

                # TODO: separate this out into separate handler
                # Get MITRE ATT&CK components
                mitre_url = f"https://www.virustotal.com/api/v3/files/{file_id}/behaviour_mitre_trees"
                mitre_response = httpx.get(mitre_url, headers=headers)

                # It's fine if there's no MITRE data
                if mitre_response.is_success:
                    mitre_response_json = mitre_response.json()

                    # Deduplicate tactics
                    mitre_data = {}

                    for data in mitre_response_json["data"].values():
                        for tactic in data["tactics"]:

                            if not mitre_data.get(tactic["id"]):
                                mitre_data[tactic["id"]] = {
                                    "id": tactic["id"],
                                    "name": tactic["name"],
                                    "link": tactic["link"],
                                    "description": tactic["description"],
                                    # "techniques": tactic["techniques"],
                                }

                                techniques = {}
                                for technique in tactic["techniques"]:
                                    techniques[technique["id"]] = {
                                        "id": technique["id"],
                                        "name": technique["name"],
                                        "link": technique["link"],
                                        "description": technique["description"],
                                    }

                                mitre_data[tactic["id"]]["techniques"] = techniques

                            else:
                                # TODO: deduplicate techniques
                                for technique in tactic["techniques"]:
                                    if not mitre_data[tactic["id"]]["techniques"].get(technique["id"]):
                                        mitre_data[tactic["id"]]["techniques"][technique["id"]] = {
                                            "id": technique["id"],
                                            "name": technique["name"],
                                            "link": technique["link"],
                                            "description": technique["description"],
                                        }


                    # Order all the techniques by id
                    for tactic in mitre_data.values():
                        tactic["techniques"] = sorted(tactic["techniques"].values(), key=lambda x: x["id"])

                    # Convert to list and order by tactics (using dataclass to keep dot notation)
                    mitre_data = [Tactic(**tactic) for tactic in mitre_data.values()]
                    mitre_data.sort(key=lambda x: x.id)

            else:
                error = "File results not found."

    return render_template("file_report.html", summary=summary, error=error, mitre_data=mitre_data)


def is_valid_hash(s: str) -> bool:
    md5_re = re.compile(r'^[A-Fa-f0-9]{32}$')
    sha1_re = re.compile(r'^[A-Fa-f0-9]{40}$')
    sha256_re = re.compile(r'^[A-Fa-f0-9]{64}$')

    s = s.strip()
    return bool(md5_re.fullmatch(s) or sha1_re.fullmatch(s) or sha256_re.fullmatch(s))


@dataclasses.dataclass
class Tactic:
    id: str
    name: str
    link: str
    description: str
    techniques: list
