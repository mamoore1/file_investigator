import dataclasses
from datetime import datetime
from functools import cache

import httpx

from .exceptions import ResultsNotFoundError

class IPResultsNotFoundError(ResultsNotFoundError):
    pass

class FileHashResultsNotFoundError(ResultsNotFoundError):
    pass


@dataclasses.dataclass
class Tactic:
    id: str
    name: str
    link: str
    description: str
    techniques: list


class VirusTotalHandler:

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def generate_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "x-apikey": self.api_key,
        }

    def _get(self, url: str) -> httpx.Response:
        headers = self.generate_headers()
        response = httpx.get(url, headers=headers)

        # Log the response
        print(f"VirusTotal: GET {response.url} {response.status_code}")

        return response

    @cache
    def get_ip_data(self, ip: str) -> dict:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

        response = self._get(url)

        if not response.is_success:
            raise IPResultsNotFoundError("Failed to get IP results.")

        response_data: dict = response.json()["data"]
        response_data_attributes: dict = response_data.get("attributes", {})

        whois_data: str = response_data_attributes.get("whois", "")

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

    @cache
    def get_file_hash_summary(self, file_hash: str) -> dict:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = self._get(url)

        if not response.is_success:
            raise FileHashResultsNotFoundError("Failed to get file hash results.")

        response_json = response.json()
        response_data_attributes: dict = response_json["data"]["attributes"]

        first_seen: dict = response_data_attributes["first_submission_date"]
        first_seen = datetime.fromtimestamp(first_seen).isoformat()

        summary = {
            "file_name": response_data_attributes.get("meaningful_name"),
            "sha256": response_data_attributes.get("sha256"),
            "file_type": response_data_attributes.get("type_description"),
            "size": response_data_attributes.get("size"),
            "malicious": response_data_attributes.get("last_analysis_stats", {}).get("malicious"),
            "total_engines": sum(response_data_attributes.get("last_analysis_stats", {}).values()),
            "reputation": response_data_attributes.get("reputation"),
            "first_seen": first_seen,
            "compiler": response_data_attributes.get("detectiteasy", {}).get("values", []),
            "tags": response_data_attributes.get("tags", []),
            "source": "VirusTotal API",
            "retrieved_at": datetime.now().isoformat(),
        }

        return summary

    @cache
    def get_file_mitre_details(self, file_hash: str) -> list[Tactic]:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_mitre_trees"
        mitre_response = self._get(url)

        mitre_data = None
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

        return mitre_data