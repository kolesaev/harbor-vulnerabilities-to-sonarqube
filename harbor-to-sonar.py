#!/usr/bin/env python3

import json
import os
import sys
import requests

IMPACT_SEVERITY = {
    "Unknown": "INFO",
    "Info": "INFO",
    "Low": "LOW",
    "Medium": "MEDIUM",
    "High": "HIGH",
    "Critical": "BLOCKER",
}

RULE_SEVERITY = {
    "Unknown": "INFO",
    "Info": "INFO",
    "Low": "MINOR",
    "Medium": "MAJOR",
    "High": "CRITICAL",
    "Critical": "BLOCKER",
}

def load_harbor_report(harbor_report):
    with open(harbor_report) as fobj:
        return json.loads(fobj.read())

def make_sonar_issues(vulnerabilities, file_path=None, opencve_user="", opencve_pwd=""):
    seen_rules = set()
    res = {"rules": [], "issues": []}
    for vuln in vulnerabilities:
        title = vuln["id"]
        if opencve_user != "" and opencve_pwd != "":
            session = requests.Session()
            session.auth = (opencve_user, opencve_pwd)
            response = session.get(f"https://app.opencve.io/api/cve/{vuln['id']}")
            responsejson = response.json()
            if responsejson["title"] is not None:
                title = responsejson["title"]
        if vuln["id"] not in seen_rules:
            res["rules"].append(
                {
                    "id": vuln["id"],
                    "name": title,
                    "description": f"{vuln['description']} | Details: {vuln['links'][0]}",
                    "engineId": "Harbor",
                    "type": "VULNERABILITY",
                    "cleanCodeAttribute": "LOGICAL",
                    "severity": RULE_SEVERITY[vuln["severity"]],
                    "impacts": [
                        {
                            "softwareQuality": "SECURITY",
                            "severity": IMPACT_SEVERITY[vuln["severity"]],
                        }
                    ],
                }
            )
            seen_rules.add(vuln["id"])

        issue_message = f"Package: {vuln['package']}@{vuln['version']}"

        if vuln["id"] != title:
            issue_message = issue_message + f" | Title: {title}"
            
        issue_message = issue_message + f" | Reference: {vuln['links'][0]}"

        cvss = None

        # find v3 score
        if vuln["preferred_cvss"]["score_v3"] is not None and vuln["preferred_cvss"]["score_v3"] > 0:
            cvss = vuln['preferred_cvss']['score_v3']
        elif vuln["vendor_attributes"] is not None:
            if "nvd" in vuln["vendor_attributes"]["CVSS"] and "V3Score" in vuln["vendor_attributes"]["CVSS"]["nvd"] and vuln["vendor_attributes"]["CVSS"]["nvd"]["V3Score"] > 0:
                cvss = vuln["vendor_attributes"]["CVSS"]["nvd"]["V3Score"]
            elif "ghsa" in vuln["vendor_attributes"]["CVSS"] and "V3Score" in vuln["vendor_attributes"]["CVSS"]["ghsa"] and vuln["vendor_attributes"]["CVSS"]["ghsa"]["V3Score"] > 0:
                cvss = vuln["vendor_attributes"]["CVSS"]["ghsa"]["V3Score"]
            elif "bitnami" in vuln["vendor_attributes"]["CVSS"] and "V3Score" in vuln["vendor_attributes"]["CVSS"]["bitnami"] and vuln["vendor_attributes"]["CVSS"]["bitnami"]["V3Score"] > 0:
                cvss = vuln["vendor_attributes"]["CVSS"]["bitnami"]["V3Score"]
            elif "redhat" in vuln["vendor_attributes"]["CVSS"] and "V3Score" in vuln["vendor_attributes"]["CVSS"]["redhat"] and vuln["vendor_attributes"]["CVSS"]["redhat"]["V3Score"] > 0:
                cvss = vuln["vendor_attributes"]["CVSS"]["redhat"]["V3Score"]

        # find v2 only if v3 is empty
        if cvss is None:
            if vuln["preferred_cvss"]["score_v2"] is not None and vuln["preferred_cvss"]["score_v2"] > 0:
                cvss = vuln['preferred_cvss']['score_v2']
            elif vuln["vendor_attributes"] is not None:
                if "nvd" in vuln["vendor_attributes"]["CVSS"] and "V2Score" in vuln["vendor_attributes"]["CVSS"]["nvd"] and vuln["vendor_attributes"]["CVSS"]["nvd"]["V2Score"] > 0:
                    cvss = vuln["vendor_attributes"]["CVSS"]["nvd"]["V2Score"]
                elif "ghsa" in vuln["vendor_attributes"]["CVSS"] and "V2Score" in vuln["vendor_attributes"]["CVSS"]["ghsa"] and vuln["vendor_attributes"]["CVSS"]["ghsa"]["V2Score"] > 0:
                    cvss = vuln["vendor_attributes"]["CVSS"]["ghsa"]["V2Score"]
                elif "bitnami" in vuln["vendor_attributes"]["CVSS"] and "V2Score" in vuln["vendor_attributes"]["CVSS"]["bitnami"] and vuln["vendor_attributes"]["CVSS"]["bitnami"]["V2Score"] > 0:
                    cvss = vuln["vendor_attributes"]["CVSS"]["bitnami"]["V2Score"]
                elif "redhat" in vuln["vendor_attributes"]["CVSS"] and "V2Score" in vuln["vendor_attributes"]["CVSS"]["redhat"] and vuln["vendor_attributes"]["CVSS"]["redhat"]["V2Score"] > 0:
                    cvss = vuln["vendor_attributes"]["CVSS"]["redhat"]["V2Score"]

        if cvss is not None:
            issue_message = issue_message + f" | CVSS Score: {cvss}"

        if vuln["cwe_ids"][0] is not None and vuln["cwe_ids"][0] != "":
            if len(vuln["cwe_ids"]) > 1 and vuln["cwe_ids"][1] != "":
                issue_message = issue_message + f" | Category: {vuln['cwe_ids'][0]}, {vuln['cwe_ids'][1]}"
            else:
                issue_message = issue_message + f" | Category: {vuln['cwe_ids'][0]}"

        issue_message = issue_message + f" | Description: {vuln['description']}"
        issue_message = issue_message + f" | Current version: {vuln['version']}"
        issue_message = issue_message + f" | Fixed in: {vuln['fix_version']}"

        res["issues"].append(
            {
                "ruleId": vuln["id"],
                "primaryLocation": {
                    "message": issue_message,
                    "filePath": file_path,
                },
            }
        )
    return res


def make_sonar_report(res):
    return json.dumps(res, indent=2)


def main(args):
    harbor_report = None
    issues_file = None
    opencve_user = None
    opencve_pwd = None

    for arg in args[1:]:
        if "harborreport" in arg:
            harbor_report = arg.split("=")[-1].strip()
        if "issuesfile" in arg:
            issues_file = arg.split("=")[-1].strip()
        if "opencveuser" in arg:
            opencve_user = arg.split("=")[-1].strip()
        if "opencvepassword" in arg:
            opencve_pwd = arg.split("=")[-1].strip()

    if not os.path.exists(harbor_report):
        sys.exit(f"Harbor report not found in path: {harbor_report}")

    if issues_file is None:
        sys.exit(f"Project file to link issues not found in path: {issues_file}")

    report = load_harbor_report(harbor_report)

    res = make_sonar_issues(report["application/vnd.security.vulnerability.report; version=1.1"]["vulnerabilities"], issues_file, opencve_user, opencve_pwd)
    report = make_sonar_report(res)
    print(report)


if __name__ == "__main__":
    main(sys.argv)
