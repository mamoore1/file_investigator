import httpx
from functools import cache
from datetime import datetime

from .exceptions import ResultsNotFoundError

class AbuseIPDBResultsNotFoundError(ResultsNotFoundError):
    pass


class AbuseIPDBHandler:
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def generate_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Key": self.api_key,
        }

    def _get(self, url: str, params: dict[str, str]) -> httpx.Response:
        headers = self.generate_headers()
        response = httpx.get(url, params=params, headers=headers)

        print(f"AbuseIPDB: GET {response.url} {response.status_code}")

        return response

    @cache
    def get_ip_data(self, ip: str) -> dict:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip}

        response = self._get(url, params)

        if not response.is_success:
            raise AbuseIPDBResultsNotFoundError("IP scores not found.")

        response_data: dict = response.json()["data"]

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
