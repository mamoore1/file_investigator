import ipaddress
import os
import re

from dotenv import load_dotenv
from flask import Flask, request, render_template

from .abuseipdb_handler import AbuseIPDBHandler
from .exceptions import ResultsNotFoundError
from .virustotal_handler import VirusTotalHandler

load_dotenv()

abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")
virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")


app = Flask(__name__)
abuseipdb_handler = AbuseIPDBHandler(abuseipdb_api_key)
virustotal_handler = VirusTotalHandler(virustotal_api_key)


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
        elif not is_valid_ip(ip):
            error = "Invalid IP address provided."
        elif not source:
            error = "No source provided."
        elif source not in ["abuseipdb", "virustotal"]:
            error = "Invalid source provided."
        else:
            try:
                if source == "abuseipdb":
                    results = abuseipdb_handler.get_ip_data(ip)
                else:
                    results = virustotal_handler.get_ip_data(ip)
            except ResultsNotFoundError:
                error = "No results found for IP address."

    return render_template("check_ip.html", results=results, source=source, error=error)


@app.route("/file-report", methods=["GET", "POST"])
def file_report():

    summary = None
    mitre_data = None
    error = None

    if request.method == "POST":
        file_id = request.form.get("file_id")

        if not is_valid_hash(file_id):
            error = "Invalid file hash provided. Must be MD5, SHA-1 or SHA256"
            return render_template(
                "file_report.html",
                summary=summary,
                mitre_data=mitre_data,
                error=error
            )

        try:
            summary = virustotal_handler.get_file_hash_summary(file_id)
            mitre_data = virustotal_handler.get_file_mitre_details(file_id)
        except ResultsNotFoundError:
            error = "No results found for file hash."

    return render_template(
        "file_report.html",
        summary=summary,
        error=error,
        mitre_data=mitre_data
    )


def is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
    except ValueError:
        return False

    return True


def is_valid_hash(s: str) -> bool:
    md5_re = re.compile(r'^[A-Fa-f0-9]{32}$')
    sha1_re = re.compile(r'^[A-Fa-f0-9]{40}$')
    sha256_re = re.compile(r'^[A-Fa-f0-9]{64}$')

    s = s.strip()
    return bool(md5_re.fullmatch(s) or sha1_re.fullmatch(s) or sha256_re.fullmatch(s))
