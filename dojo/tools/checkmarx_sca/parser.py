import hashlib
import json
import logging
import re
from datetime import datetime

from cvss import CVSS3

from dojo.models import Finding, Test

logger = logging.getLogger(__name__)


class CheckmarxSCAParser:

    """
    Checkmarx SCA JSON Scan Report
    """

    def get_scan_types(self):
        return ["Checkmarx SCA Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Checkmarx SCA Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Checkmarx SCA report file can be imported in JSON format (option --json)."

    def get_findings(self, file, test: Test | None):
        data = json.load(file)

        dupes = {}
        for vuln in data["Vulnerabilities"]:
            if vuln["IsIgnored"]:
                continue

            finding = Finding(
                title=data["RiskReportSummary"]["ProjectName"] + " " + vuln["Id"],
                cve=vuln["CveName"],
                description=vuln["Description"],
                severity=vuln["Severity"],
                static_finding=True,
                dynamic_finding=False,
                cvssv3_score=vuln["Score"],
                references="\n".join(vuln["References"]),
                test=test,
            )

            if vuln["Cvss3"]:
                finding.cvssv3_score = vuln["Cvss3"]["BaseScore"]
                finding.severity = vuln["Cvss3"]["Severity"]
                try:
                    cvss = self.build_cvss_vector(vuln)
                    if cvss != "":
                        vector = CVSS3("CVSS:3.0/" + cvss)
                        finding.cvssv3 = vector.clean_vector()
                except Exception as e:
                    logger.warning("CVSS Error in file %s: %s", data["RiskReportSummary"]["ProjectName"], e)

            if vuln.get("Cwe"):
                cwe = self.extract_cwe_number(vuln["Cwe"])
                if cwe is not None:
                    finding.cwe = cwe

            if vuln.get("Epss"):
                finding.epss_score = vuln["EpssValue"]
                finding.epss_percentile = vuln["EpssPercentile"]

            if vuln.get("PackageName"):
                finding.component_name = vuln["PackageName"]
            else:
                finding.component_name = vuln["PackageId"]

            if vuln.get("PackageVersion"):
                finding.component_version = vuln["PackageVersion"]

            if vuln.get("FirstFoundAt"):
                finding.date = self.parse_iso_date(vuln["FirstFoundAt"])
            else:
                finding.date = self.parse_iso_date(data["RiskReportSummary"]["CreatedOn"])

            # internal de-duplication
            dupe_key = hashlib.sha256(str(vuln["PackageId"] + vuln["Id"]).encode("utf-8")).hexdigest()
            if dupe_key in dupes:
                find = dupes[dupe_key]
                if finding.description:
                    find.description += "\n" + finding.description
                dupes[dupe_key] = find
            else:
                dupes[dupe_key] = finding

        return list(dupes.values())

    def parse_iso_date(self, iso_date_str):
        # Parse the ISO formatted date string
        dt = datetime.fromisoformat(iso_date_str)
        return dt.date()  # Return only the date part

    def extract_cwe_number(self, input_string):
        # Use a regular expression to find the pattern 'CWE-<number>'
        match = re.search(r"CWE-(\d+)", input_string)
        if match:
            return int(match.group(1))  # Convert the extracted number to an integer
        return None

    def build_cvss_vector(self, vuln):
        # Create a list to hold the vector components
        components = []

        # Define a mapping of fields to their corresponding CVSS attributes
        cvss_attributes = {
            "AV": vuln["Cvss3"].get("AttackVector", None),
            "AC": vuln["Cvss3"].get("AttackComplexity", None),
            "S": vuln["Cvss3"].get("Scope", None),
            "C": vuln["Cvss3"].get("Confidentiality", None),
            "A": vuln["Cvss3"].get("Availability", None),
            "I": vuln["Cvss3"].get("Integrity", None),
            "PR": vuln["Cvss3"].get("PrivilegesRequired", None),
            "UI": vuln["Cvss3"].get("UserInteraction", None),
        }

        # Loop through the attributes and add them to the components list if they are not "NONE"
        for key, value in cvss_attributes.items():
            if value is not None:
                components.append(f"{key}:{value[0]}")

        # Join the components into a single CVSS vector string
        return "/".join(components)
