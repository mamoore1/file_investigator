from flask import Flask, request
from markupsafe import escape
import ipaddress
import httpx
import os


abuseipdb_api_key = os.environ.get("ABUSEIPDB_API_KEY")


app = Flask(__name__)


@app.route("/")
def index():
    return "<p>Welcome To the Index Page</p>"


@app.route("/check-ip")
def check_ip():
    ip = request.args.get("ip", None)

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
