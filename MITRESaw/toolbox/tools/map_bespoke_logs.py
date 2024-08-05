#!/usr/bin/env python3 -tt
import json
import os
import re
import requests
import time


def remove_logsource(logsource, data):
    for each in data:
        logsource = [x for x in logsource if x != each]
    return logsource


def obtain_cve_details(evidence):
    cves = []
    for cve in evidence:
        cve_details = requests.get(
            "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{}/{}xxx/{}.json".format(
                cve.split("-")[1],
                cve.split("-")[2][0],
                cve,
            )
        )
        if cve_details.status_code >= 200 and cve_details.status_code < 300:
            cve_content = cve_details.content
            with open(f"{cve}.json", "wb") as cve_file_b:
                cve_file_b.write(cve_content)
            with open(f"{cve}.json", "r") as cve_file:
                # json.load: read JSON data from a file object.
                # json.loads: read JSON data from a string.
                cve_data = json.load(cve_file)
            # extracting cve data from repository
            vendor = cve_data["containers"]["cna"]["affected"][0]["vendor"]
            versions = str(
                re.findall(
                    r"'affected', 'version': '([^']+)",
                    str(cve_data["containers"]["cna"]["affected"][0]["versions"]),
                )
            )[2:-2].replace("', '", ";")
            description = (
                cve_data["containers"]["cna"]["descriptions"][0]["value"]
                .strip()
                .replace(",", "")
                .replace("\n", " ")
                .replace("'", "`")
                .strip()
            )
            cve_details = f"{cve},{vendor},{versions},{description}"
            cves.append(cve_details)
            os.remove(f"{cve}.json")
        else:
            print(f"\t{cve} returned a {cve_details.status_code} error.")
            time.sleep(1)
    return cves


def bespoke_mapping(technique_id, platform, logsource, evidence_type, evidence):
    # provide logsource.append() for applicable splunk indexes, Sentinel tables etc.
    """logsource.append("")"""

    # removing (and replacing) ATT&CK log sources
    if "File: File " in str(logsource):
        remove_logsource(
            logsource,
            ["File: File Access", "File: File Creation", "File: File Modification"],
        )
        logsource.append("FILE_LOGS")
    if "Process: Process Creation" in str(logsource):
        remove_logsource(logsource, ["Process: Process Creation"])
        logsource.append("PROCESS_LOGS")

    # removing generic/unspecified log sources
    if "Process monitoring" in str(logsource):
        remove_logsource(logsource, ["Process Monitoring"])

    # removing data sources not applicable to our environment
    """if "Zeek conn.log" in str(logsource):
        remove_logsource(logsource, ["Zeek conn.log"])"""

    # assigning data sources based on platform
    if "Azure" in platform or "IaaS" in platform:
        logsource.append(
            "AZURE_LOGS",
        )
    if "IaaS" in platform:
        logsource.append(
            "AWS_LOGS",
        )

    # assigning data sources based on evidence-type uncovered and environment-relevant data sources
    if evidence_type == "reg":
        logsource.append("REG_LOGS")
    elif evidence_type == "cmd" or evidence_type == "software":
        if "Windows" in platform:
            logsource.append("WIN_LOGS")
        else:  # Linux and macOS
            logsource.append("NIX_LOGS")
    elif (
        evidence_type == "ports"
    ):  # consider location of appliances and technology stack inc. logical architecture (internal/external)
        if (
            technique_id == "T1090.002" or technique_id == "T1105"
        ):  # external data sources only
            logsource.append("NETWORK_LOGS")
        elif (
            technique_id == "T1047"
            or technique_id == "T1082"
            or technique_id == "T1112"
        ):  # internal data sources only
            logsource.append("NETWORK_LOGS")
        elif (
            technique_id == "T1090.003" or "T1110" in technique_id
        ):  # both internal and external data sources
            logsource.append("NETWORK_LOGS")
    elif evidence_type == "evt":
        logsource.append("EVT_LOGS")
    elif evidence_type == "cve":
        logsource = obtain_cve_details(evidence[2:-2].split("', '"))
    logsource = re.sub(
        r"('[^']+)\\?(', )\"([^']+)(', ')", r"\1\2'\3\4", str(logsource)
    )[2:-2].split("', '")

    # assigning data sources based on technique id and environment-relevant data sources
    if technique_id == "T1566.001" or technique_id == "T1566.002":
        logsource.append("EMAIL_LOGS")
    if (
        technique_id == "T1098.005"
        or technique_id == "T1111"
        or technique_id == "T1556.006"
        or technique_id == "T1621"
    ):
        logsource.append("MFA_LOGS")

    # merging duplicate data sources
    counter = 0
    while counter < 20:
        logsource = re.sub(
            r"', '([^:]+)([^']+)', '\1: ([^']+)", r"', '\1\2;\3", str(logsource)
        )
        logsource = re.sub(r"', '([^:]+)', '\1", r"', '\1", str(logsource))
        counter += 1
    logsource = sorted(list(filter(None, logsource[2:-2].split("', '"))))
    return sorted(list(set(logsource)))
