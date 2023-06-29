#!/usr/bin/env python3 -tt
import argparse
import os
import pandas
import random
import re
import requests
import shutil
import subprocess
import time
from argparse import RawTextHelpFormatter
from collections import Counter
from datetime import datetime


parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
parser.add_argument(
    "platforms",
    nargs=1,
    help="Filter results based on provided platforms e.g. Windows,Linux,IaaS,Azure_AD (use _ instead of spaces)\n Use . to not filter i.e. obtain all Platforms\n Valid options are: 'Azure_AD', 'Containers', 'Google_Workspace', 'IaaS', 'Linux', 'Network', 'Office_365', 'PRE', 'SaaS', 'Windows', 'macOS'\n\n",
)
parser.add_argument(
    "searchterms",
    nargs=1,
    help="Filter Threat Actor results based on specific industries e.g. mining,technology,defense,law (use _ instead of spaces)\n Use . to not filter i.e. obtain all Threat Actors\n\n",
)
parser.add_argument(
    "groupsorsoftware",
    nargs=1,
    help="Filter Threat Actor results based on specific group names and/or Software e.g. APT29,HAFNIUM,Lazurus_Group,Turla,AppleJeus,Brute Ratel C4 (use _ instead of spaces)\n Use . to not filter i.e. obtain all Threat Actors\n",
)
parser.add_argument(
    "-a",
    "--asciiart",
    help="Don't show ASCII Art of the saw.\n\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-n",
    "--navlayers",
    help="Obtain ATT&CK Navigator layers for Groups and Software identified during extraction of identifable evidence\n\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-o",
    "--overwrite",
    help="Remove all files and folder within the MITRESaw/MITRESaw directory\n\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-q",
    "--queries",
    help="Build search queries based on results - to be imported into Splunk; Azure Sentinel; Elastic/Kibana\n\n",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-t",
    "--truncate",
    help="Truncate printing of indicators for a cleaner output (they are still written to output file)\n\n",
    action="store_const",
    const=True,
    default=False,
)


args = parser.parse_args()
operating_platforms = args.platforms
search_terms = args.searchterms
softwareorgroups = args.groupsorsoftware
art = args.asciiart
writeover = args.overwrite
navlayers = args.navigationlayers
queries = args.queries
truncate = args.truncate

attack_framework = "enterprise"
attack_version = "13.1"
sheet_tabs = [
    "techniques-techniques",
    "techniques-procedure examples",
    "groups-groups",
    "groups-techniques used",
    "software-software",
    "software-techniques used",
]
port_indicators = []
evts_indicators = []
terms_indicators = []
collected_indicators = []
group_techniques = {}


def print_saw(saw, tagline, spacing):
    subprocess.Popen(["clear"]).communicate()
    print(tagline)
    if spacing != "-" and spacing != "partial":
        print(saw.replace("@", spacing))
        time.sleep(0.1)
    elif spacing == "partial":
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s])", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{2})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{4})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{6})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{8})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{10})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{12})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{14})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{16})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{18})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{20})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{22})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{24})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{26})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{28})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{30})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{32})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{34})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{36})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{38})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{40})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{42})", r"", saw))
        time.sleep(0.2)
    else:
        pass


def report_finding_to_stdout(
    technique_name,
    software_group_name,
    evidence_type,
    identifiers,
    software_group_terms,
    terms,
    truncate,
):
    if evidence_type == "ports":
        evidence_insert = " port(s): "
        identifiers = re.findall(r"\d+", str(identifiers))
    elif evidence_type == "evt":
        evidence_insert = " event log ID(s): "
        identifiers = re.findall(r"\d+", str(identifiers))
    else:
        evidence_insert = ": "
    if str(terms) != "['.']":
        extracted_terms = re.findall(r"\w+", str(software_group_terms))
        software_group_terms_insert = sorted(list(set(extracted_terms)))
        terms_insert = " -> '\033[1;36m{}\033[1;m' ->".format(
            str(software_group_terms_insert)[2:-2]
            .replace("_", " ")
            .replace("', '", "\033[1;m', '\033[1;36m")
        )
    else:
        terms_insert = " ->"
    identifiers = (
        str(identifiers)[2:-2]
        .replace("\\\\\\\\\\\\\\\\", "\\\\\\\\")
        .replace("\\\\\\\\", "\\\\")
        .replace('"reg" add ', "reg add ")
    )
    print_statement = "      -> '\033[1;33m{}\033[1;m'{} '\033[1;32m{}\033[1;m'{}'\033[1;31m{}\033[1;m'".format(
        software_group_name,
        terms_insert,
        technique_name,
        evidence_insert,
        identifiers.replace("', '", "\033[1;m', '\033[1;31m"),
    )
    if truncate:
        print(print_statement.split(": ")[0])
    else:
        print(print_statement)
    time.sleep(0.2)
    return identifiers.replace("', '", "++")


def extract_port_indicators(description):
    description = re.sub(
        r"\(Citation[^\)]+\)",
        r"",
        re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", description),
    )
    description = (
        description.replace('""', '"')
        .replace(". . ", ". ")
        .replace(".. ", ". ")
        .replace("\\\\\\'", "'")
        .replace("\\\\'", "'")
        .replace("\\'", "'")
        .strip(",")
        .strip('"')
        .strip(",")
        .strip('"')
    )
    port_identifiers = re.findall(
        r"(?:(?:[Pp]orts?(?: of)? |and |& |or |, |e\.g\.? |tcp: ?|udp: ?)|(?:\())(\d{2,})(?: |/|\. |,|\<)",
        description,
    )
    port_identifiers = list(
        filter(
            lambda port: "365" != port,
            list(filter(lambda port: "10" != port, port_identifiers)),
        )
    )  # remove string from list
    return port_identifiers


def extract_evt_indicators(description):
    description = re.sub(
        r"\(Citation[^\)]+\)",
        r"",
        re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", description),
    )
    description = (
        description.replace('""', '"')
        .replace(". . ", ". ")
        .replace(".. ", ". ")
        .replace("\\\\\\'", "'")
        .replace("\\\\'", "'")
        .replace("\\'", "'")
        .strip(",")
        .strip('"')
        .strip(",")
        .strip('"')
    )
    evt_identifiers = re.findall(
        r"(?:(?:Event ?|E)I[Dd]( ==)? ?\"?(\d{1,5}))", description
    )
    return evt_identifiers


def extract_reg_indicators(
    description,
):
    description = re.sub(
        r"\(Citation[^\)]+\)",
        r"",
        re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", description),
    )
    description = (
        description.replace('""', '"')
        .replace(". . ", ". ")
        .replace(".. ", ". ")
        .replace("\\\\\\'", "'")
        .replace("\\\\'", "'")
        .replace("\\'", "'")
        .strip(",")
        .strip('"')
        .strip(",")
        .strip('"')
    )
    reg_identifiers = re.findall(
        r"([Hh][Kk](?:[Ll][Mm]|[Cc][Uu]|[Ee][Yy])[^\{\}!$<>`]+)", description
    )
    registry_identifiers = list(set(reg_identifiers))
    return registry_identifiers


def extract_cmd_indicators(description):
    terms_identifiers = re.findall(
        r"(?:(?:<code> ?([^\{\}!$<>`]{3,}) ?<\/code>)|(?:` ?([^\{\}!$<>`]{3,}) ?`)|(?:\[ ?([^\{\}!$<>`]{3,}) ?\]\(https:\/\/attack\.mitre\.org\/software))",
        description,
    )
    cmd_identifiers = []
    all_identifiers = list(set(terms_identifiers))
    for identifier_set in all_identifiers:
        for each_identifier in identifier_set:
            if (
                len(each_identifier) > 0
                and "](https://attack.mitre.org/" not in each_identifier
                and "example" not in each_identifier.lower()
                and "citation" not in each_identifier.lower()
                and not each_identifier.startswith(")")
                and not each_identifier.endswith("(")
                and not each_identifier.startswith("hklm")
                and not each_identifier.startswith("hkcu")
                and not each_identifier.startswith("hkey")
                and not each_identifier.startswith("HKLM")
                and not each_identifier.startswith("HKCU")
                and not each_identifier.startswith("HKEY")
                and not each_identifier.startswith("[hklm")
                and not each_identifier.startswith("[hkcu")
                and not each_identifier.startswith("[hkey")
                and not each_identifier.startswith("[HKLM")
                and not each_identifier.startswith("[HKCU")
                and not each_identifier.startswith("[HKEY")
                and not each_identifier == ", and "
            ):
                cmd_identifiers.append(
                    each_identifier.lower()
                    .replace("\\\\\\\\\\\\\\\\", "\\\\\\\\")
                    .replace("\\\\\\\\\\\\", "\\\\\\")
                    .replace("\\\\\\\\", "\\\\")
                    .replace("£\\\\t£", "\\\\t")
                    .replace('""', '"')
                    .replace("  ", " ")
                    .replace("[.]", ".")
                    .replace("[:]", ":")
                    .replace("&#42;", "*")
                    .replace("&lbrace;", "{")
                    .replace("&rbrace;", "}")
                    .replace("[username]", "%username%")
                    .replace("\\]\\", "]\\")
                    .replace("“", '"')
                    .replace("”", '"')
                    .strip("\\")
                )
            else:
                pass
    return cmd_identifiers


def extract_indicators(
    valid_procedure,
    terms,
    evidence_found,
    identifiers,
    previous_findings,
    truncate,
):
    software_group_name = valid_procedure.split("||")[1]
    technique_id = valid_procedure.split("||")[2]
    technique_name = valid_procedure.split("||")[3]
    software_group_usage = valid_procedure.split("||")[4]
    software_group_terms = valid_procedure.split("||")[6]
    technique_description = valid_procedure.split("||")[7]
    technique_detection = valid_procedure.split("||")[8]
    description = "{}||{}||{}".format(
        software_group_usage, technique_description, technique_detection
    )
    # extracting ports
    port_identifiers = extract_port_indicators(description)
    if len(port_identifiers) > 0:
        evidence_type = "ports"
        evidence = "{}||{}||{}".format(
            valid_procedure,
            evidence_type,
            str(port_identifiers),
        )
        if "{}||{}||{}||{}".format(
            technique_id, technique_name, software_group_name, evidence_type
        ) not in str(previous_findings):
            identifiers = report_finding_to_stdout(
                technique_name,
                software_group_name,
                evidence_type,
                port_identifiers,
                software_group_terms,
                terms,
                truncate,
            )
            previous_findings[
                "{}||{}||{}||{}".format(
                    technique_id, technique_name, software_group_name, evidence_type
                )
            ] = "-"
            evidence = "{}||{}||{}".format(
                valid_procedure,
                evidence_type,
                identifiers,
            )
            evidence_found.append(evidence)
        else:
            pass
    else:
        evidence_type = ""
    # extracting event IDs
    if "Event ID" in description or "EID" in description or "EventId" in description:
        evt_identifiers = extract_evt_indicators(description)
    else:
        evt_identifiers = []
    if len(evt_identifiers) > 0:
        evidence_type = "evt"
        evidence = "{}||{}||{}".format(
            valid_procedure,
            evidence_type,
            str(evt_identifiers),
        )
        if "{}||{}||{}||{}".format(
            technique_id, technique_name, software_group_name, evidence_type
        ) not in str(previous_findings):
            identifiers = report_finding_to_stdout(
                technique_name,
                software_group_name,
                evidence_type,
                evt_identifiers,
                software_group_terms,
                terms,
                truncate,
            )
            previous_findings[
                "{}||{}||{}||{}".format(
                    technique_id, technique_name, software_group_name, evidence_type
                )
            ] = "-"
            evidence = "{}||{}||{}".format(
                valid_procedure,
                evidence_type,
                identifiers,
            )
            evidence_found.append(evidence)
        else:
            pass
    else:
        evidence_type = ""
    # extracting registry artefacts
    if (
        "hklm\\" in description.lower()
        or "hkcu\\" in description.lower()
        or "hkey\\" in description.lower()
        or "hkey_" in description.lower()
        or "hklm]" in description.lower()
        or "hkcu]" in description.lower()
        or "hkey_local_machine]" in description.lower()
        or "hkey_current_user]" in description.lower()
    ):
        reg_identifiers = extract_reg_indicators(description)
    else:
        reg_identifiers = []
    if len(reg_identifiers) > 0:
        evidence_type = "reg"
        evidence = "{}||{}||{}".format(
            valid_procedure,
            evidence_type,
            str(reg_identifiers),
        )
        if "{}||{}||{}||{}".format(
            technique_id, technique_name, software_group_name, evidence_type
        ) not in str(previous_findings):
            identifiers = report_finding_to_stdout(
                technique_name,
                software_group_name,
                evidence_type,
                reg_identifiers,
                software_group_terms,
                terms,
                truncate,
            )
            previous_findings[
                "{}||{}||{}||{}".format(
                    technique_id, technique_name, software_group_name, evidence_type
                )
            ] = "-"
            evidence = "{}||{}||{}".format(
                valid_procedure,
                evidence_type,
                identifiers,
            )
            evidence_found.append(evidence)
        else:
            pass
    else:
        evidence_type = ""
    # extracting commands
    if "<code>" in description or "`" in description:
        cmd_identifiers = extract_cmd_indicators(description)
    else:
        cmd_identifiers = []
    if len(cmd_identifiers) > 0:
        evidence_type = "cmd"
        evidence = "{}||{}||{}".format(
            valid_procedure,
            evidence_type,
            str(cmd_identifiers),
        )
        if "{}||{}||{}||{}".format(
            technique_id, technique_name, software_group_name, evidence_type
        ) not in str(previous_findings):
            identifiers = report_finding_to_stdout(
                technique_name,
                software_group_name,
                evidence_type,
                cmd_identifiers,
                software_group_terms,
                terms,
                truncate,
            )
            previous_findings[
                "{}||{}||{}||{}".format(
                    technique_id, technique_name, software_group_name, evidence_type
                )
            ] = "-"
            evidence = "{}||{}||{}".format(
                valid_procedure,
                evidence_type,
                identifiers,
            )
            evidence_found.append(evidence)
        else:
            pass
    else:
        evidence_type = ""
    return evidence_found, identifiers, previous_findings


def upper_repl(match):
    return match.group(1).upper()


def lower_repl(match):
    return match.group(1).lower()


def elastic_query_repl(match):
    upper_match = upper_repl(match)
    lower_match = lower_repl(match)
    return "[{}{}]".format(upper_match, lower_match)


def main():
    mitresaw_root = "./MITRESaw"
    if not os.path.exists(mitresaw_root):
        os.makedirs(mitresaw_root)
    else:
        pass
    if writeover:
        shutil.rmtree(mitresaw_root)
    else:
        pass
    if not os.path.exists(mitresaw_root):
        os.makedirs(mitresaw_root)
    else:
        pass
    mitresaw_mitre_files = os.path.join(
        mitresaw_root, "{}_mitre-attack-files".format(str(datetime.now())[0:10])
    )
    if not os.path.exists(mitresaw_mitre_files):
        os.makedirs(mitresaw_mitre_files)
        time.sleep(0.1)
        print()
        print("    -> Obtaining MITRE ATT&CK files...")
        # obtaining framework
        for sheet_tab in sheet_tabs:
            sheet, tab = sheet_tab.split("-")
            filename = os.path.join(
                mitresaw_mitre_files,
                "enterprise-attack-v{}-{}".format(attack_version, sheet),
            )
            spreadsheet = "{}.xlsx".format(filename)
            if not os.path.exists(
                os.path.join(
                    mitresaw_mitre_files,
                    "enterprise-attack-v{}/{}".format(attack_version, spreadsheet),
                )
            ):
                mitre_spreadsheet = requests.get(
                    "https://attack.mitre.org/docs/enterprise-attack-v{}/{}".format(
                        attack_version, spreadsheet.split("/")[-1]
                    )
                )
                with open(spreadsheet, "wb") as spreadsheet_file:
                    spreadsheet_file.write(mitre_spreadsheet.content)
            else:
                pass
            temp_csv = "{}temp.csv".format(filename)
            xlsx_file = pandas.read_excel(spreadsheet, tab, engine="openpyxl")
            xlsx_file.to_csv(temp_csv, index=None, header=True)
            with open(temp_csv) as csv_with_new_lines:
                malformed_csv = str(csv_with_new_lines.readlines())[2:-2]
                malformed_csv = re.sub(r"\\t", r"£\\t£", malformed_csv)
                if "-groups" not in filename:
                    malformed_csv = re.sub(r"\\n', '(T\d{4})", r"\n\1", malformed_csv)
                    malformed_csv = re.sub(
                        r"\\n['\"], ['\"]\\n['\"], ['\"]", r".  ", malformed_csv
                    )
                    formated_csv = malformed_csv
                else:
                    malformed_csv = re.sub(r"\\n', '", r"\n", malformed_csv)
                    malformed_csv = re.sub(r"\n\"\\n', \"", r"\"\n", malformed_csv)
                    malformed_csv = re.sub(r"\n\"\n", r"\"\n", malformed_csv)
                    malformed_csv = re.sub(r"\n( ?[^G|S])", r"\1", malformed_csv)
                    malformed_csv = re.sub(r"\\n', \"", r"\"\n", malformed_csv)
                    malformed_csv = re.sub(r"\\n\", '", r"\"\n", malformed_csv)
                    formated_csv = malformed_csv.replace('\\"', '"')
            with open(
                "{}-{}.csv".format(filename, tab.replace(" ", "_")), "w"
            ) as final_csv:
                final_csv.write(formated_csv)
            os.remove(temp_csv)
    else:
        pass
    time.sleep(0.1)
    saw = """
@                                                         ,
@                 ╓╗╗,                          ,╓▄▄▄Φ▓▓██▌╫D
@                ║▌ `▓L            ,,, ╓▄▄▄Φ▓▓▀▀▀╫╫╫╫╫╫╫▀▀╫▓▓▄
@                 ▓▄▓▓▓        ,▄▄B░▀╫Ñ╬░░╫╫▓▓▓▓╫╫╫╫▓▓▓╫╫╫╫╣▓▓▓▄
@                 ║████L   ,╓#▀▀▀╨╫ÑÑ╦▄▒▀╣▓▄▄▀╣▌╫▀    ██╫╫╫╫▓▓╫▓▓φ
@                  ▓╫╫╫▀]Ñ░░░░ÑÑÑÑ░░░░░╠▀W▄╠▀▓▒░╫Ñ╖   ╙└"╜▀▓▓▓▓▓█▓▓
@                  ║░░░╦╬╫╫╫╫╫╫╫╫╫╫╫╫╫ÑÑ░░░╠Ñ░╨╫Ñ░╫╫╫╫N     ▀▓▓▓╫██▓╕
@                ,]░╦╬╫╫╫╫╫╫╫▓▓▓▓▓▓╫╫╫╫╫╫╫Ñ░░╠░░╫M░╠╫╫╫╫╦,    ▀▓▓▓▓▓▓⌐
@       ╗▄╦     ]░░╬╫╫╫╫╫▓▓██████████▓▓▒╫╫╫╫Ñ░░╟▒╟▓▒ñ▓▓▓▓░N    ╙▓▓▓▓▓▓
@   ║███╫█╫    ]░░╫╫╫╫╫▓███▓▓▓▓▓▓▓▓▓▓███▓╫╫╫╫╫░░╟▒╟▓Ü╟▓▓▓▓░H    ╟▓▓▓▓▓L
@   ║███╫█╫   ]░░╫╫╫╫▓██▓╫▓▓▓▀▀╠╠╬▀▓▓▓╫▓██▓╫╫╫╫░░ÑÑ╠▄░╠▓▓▓▄▄▄▄▄▓▓▓╫╫╫╫
@    ╓▄▄╫█╫╖╖╖╦░╫╫╫╫╫██▓▓▓▓▀░╬Ñ╣╬╫Ñ░╟▓▓▓▓██╫╫╫╫Ñ░╦]░░░║████▀▀╫╫╫▓╩╨╟╫
@    ╟▓▓╫█╫▀▀▀╩╬╩╫╫▓██▓▓▓▓▌░╫░╟▓▓K╫Ñ░▓▓▓▓╫██▓▒╩╩╩╩ ╙╩╨▀▓M╨╩╨╙╝╣N╦╗Φ╝
@       ╫█╫     ▀███▀╣▓▓▓▓▓░╫Ñ░╠▀░╫Ü░▓▓▓▓▓▀▀███╕      ▐▓▌╖
@   ▄▄▄▄▓█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄╛
@                ▀╩╫╫╫╠╣▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▀░╫╫╫╫▌
@                 ╗▄╫╫Ñ░╠▀▓▓▓▓▓▓▓▓▓▓▓▓▀░╦╬╫╫∩
@                   `⌠╫╫╫Ñ░░Å╣▀▀▀▀▀▒░╦╬╫╫╫`█
@                    ╙╙""╫╫╫½╫╫╫╬╫╫╫╫╫M"▓╛
@                       └╙└ ▄▓╩`║▓╩ Å▀\n\n
    """
    titles = [
        """
       ███▄ ▄███▓ ██▓▄▄▄█████▓ ██▀███  ▓█████   ██████  ▄▄▄       █     █░
      ▓██▒▀█▀ ██▒▓██▒▓  ██▒ ▓▒▓██ ▒ ██▒▓█   ▀ ▒██    ▒ ▒████▄    ▓█░ █ ░█░
      ▓██    ▓██░▒██▒▒ ▓██░ ▒░▓██ ░▄█ ▒▒███   ░ ▓██▄   ▒██  ▀█▄  ▒█░ █ ░█ 
      ▒██    ▒██ ░██░░ ▓██▓ ░ ▒██▀▀█▄  ▒▓█  ▄   ▒   ██▒░██▄▄▄▄██ ░█░ █ ░█ 
      ▒██▒   ░██▒░██░  ▒██▒ ░ ░██▓ ▒██▒░▒████▒▒██████▒▒ ▓█   ▓██▒░░██▒██▓ 
      ░ ▒░   ░  ░░▓    ▒ ░░   ░ ▒▓ ░▒▓░░░ ▒░ ░▒ ▒▓▒ ▒ ░ ▒▒   ▓▒█░░ ▓░▒ ▒  
      ░  ░      ░ ▒ ░    ░      ░▒ ░ ▒░ ░ ░  ░░ ░▒  ░ ░  ▒   ▒▒ ░  ▒ ░ ░  
      ░      ░    ▒ ░  ░        ░░   ░    ░   ░  ░  ░    ░   ▒     ░   ░  
             ░    ░              ░        ░  ░      ░        ░  ░    ░    
""",
        """
      ______  ___________________________ __________________                   
      ___   |/  /____  _/___  __/___  __ \\___  ____/__  ___/______ ____      __
      __  /|_/ /  __  /  __  /   __  /_/ /__  __/   _____ \\ _  __ `/__ | /| / /
      _  /  / /  __/ /   _  /    _  _, _/ _  /___   ____/ / / /_/ / __ |/ |/ / 
      /_/  /_/   /___/   /_/     /_/ |_|  /_____/   /____/  \\__,_/  ____/|__/  
""",
        """
                   ______      ______    ____        ____       ____                              
       /'\\_/`\\    /\\__  _\\    /\\__  _\\  /\\  _`\\     /\\  _`\\    /\\  _`\\                            
      /\\      \\   \\/_/\\ \\/    \\/_/\\ \\/  \\ \\ \\L\\ \\   \\ \\ \\L\\_\\  \\ \\,\\L\\_\\      __      __  __  __  
      \\ \\ \\__\\ \\     \\ \\ \\       \\ \\ \\   \\ \\ ,  /    \\ \\  _\\L   \\/_\\__ \\    /'__`\\   /\\ \\/\\ \\/\\ \\ 
       \\ \\ \\_/\\ \\     \\_\\ \\__     \\ \\ \\   \\ \\ \\\\ \\    \\ \\ \\L\\ \\   /\\ \\L\\ \\ /\\ \\L\\.\\_ \\ \\ \\_/ \\_/ \\
        \\ \\_\\\\ \\_\\    /\\_____\\     \\ \\_\\   \\ \\_\\ \\_\\   \\ \\____/   \\ `\\____\\\\ \\__/.\\_\\ \\ \\___x___/'
         \\/_/ \\/_/    \\/_____/      \\/_/    \\/_/\\/ /    \\/___/     \\/_____/ \\/__/\\/_/  \\/__//__/  
""",
        """
         _____   .___ _____________________ ___________  _________                 
        /     \\  |   |\\__    ___/\\______   \\\\_   _____/ /   _____/_____   __  _  __
       /  \\ /  \\ |   |  |    |    |       _/ |    __)_  \\_____  \\ \\__  \\  \\ \\/ \\/ /
      /    Y    \\|   |  |    |    |    |   \\ |        \\ /        \\ / __ \\_ \\     / 
      \\____|__  /|___|  |____|    |____|_  //_______  //_______  /(____  /  \\/\\_/  
              \\/                         \\/         \\/         \\/      \\/          
""",
        """
        ___ ___   ___   _______   _______   _______   _______                    
       |   Y   | |   | |       | |   _   \\ |   _   | |   _   | .---.-. .--.--.--.
       |.      | |.  | |.|   | | |.  l   / |.  1___| |   1___| |  _  | |  |  |  |
       |. \\_/  | |.  | `-|.  |-' |.  _   1 |.  __)_  |____   | |___._| |________|
       |:  |   | |:  |   |:  |   |:  |   | |:  1   | |:  1   |                   
       |::.|:. | |::.|   |::.|   |::.|:. | |::.. . | |::.. . |                   
       `--- ---' `---'   `---'   `--- ---' `-------' `-------'                   
""",
    ]
    chosen_title = random.choice(titles)
    tagline = "{}        *ATT&CK for Enterprise v{}\n".format(
        chosen_title, attack_version
    )
    time.sleep(2)
    subprocess.Popen(["clear"]).communicate()
    if not art:
        print_saw(
            saw, tagline, "                                                        "
        )
        if saw:
            print_saw(
                saw, tagline, "                                                      "
            )
            print_saw(
                saw, tagline, "                                                    "
            )
            print_saw(
                saw, tagline, "                                                  "
            )
            print_saw(saw, tagline, "                                                ")
            print_saw(saw, tagline, "                                              ")
            print_saw(saw, tagline, "                                            ")
            print_saw(saw, tagline, "                                          ")
            print_saw(saw, tagline, "                                        ")
            print_saw(saw, tagline, "                                      ")
            print_saw(saw, tagline, "                                    ")
            print_saw(saw, tagline, "                                  ")
            print_saw(saw, tagline, "                                ")
            print_saw(saw, tagline, "                              ")
        else:
            pass
        print_saw(saw, tagline, "                            ")
    else:
        pass
    platforms = str(operating_platforms)[2:-2].split(",")
    platforms = list(filter(None, platforms))
    if not art:
        print_saw(saw, tagline, "                          ")
    else:
        pass
    terms = str(search_terms)[2:-2].split(",")
    terms = list(filter(None, terms))
    if not art:
        print_saw(saw, tagline, "                        ")
    else:
        pass
    softwaregroups = str(softwareorgroups)[2:-2].split(",")
    softwaregroups = list(filter(None, softwaregroups))
    if not art:
        print_saw(saw, tagline, "                      ")
    else:
        pass
    if saw:  # creating MITRESaw output file names
        if str(platforms) == "['.']":
            platforms_filename_insert = ""
        else:
            platforms_filename_insert = "{}".format(
                str(platforms)[2:-2].replace("', '", "-")
            )
        if str(terms) == "['.']":
            terms_filename_insert = ""
        else:
            terms_filename_insert = "{}".format(str(terms)[2:-2].replace("', '", "-"))
        if str(softwaregroups) == "['.']":
            softwaregroups_filename_insert = ""
        else:
            softwaregroups_filename_insert = "{}".format(
                str(softwaregroups)[2:-2].replace("', '", "-")
            )
        mitresaw_output_directory = os.path.join(
            mitresaw_root,
            "{}_{}_{}".format(
                str(datetime.now())[0:10],
                platforms_filename_insert.replace("_", ""),
                terms_filename_insert.replace("_", ""),
                softwaregroups_filename_insert.replace("_", ""),
            ),
        )
    else:
        pass
    additional_terms, evidence_found, valid_procedures, all_evidence, log_sources = (
        [] for i in range(5)
    )
    (
        group_procedures,
        groups,
        software_procedures,
        software,
        contextual_information,
        previous_findings,
    ) = ({} for i in range(6))
    identifiers = ""
    if not os.path.exists(os.path.join(mitresaw_output_directory)):
        os.makedirs(os.path.join(mitresaw_output_directory))
    else:
        pass
    if os.path.exists(os.path.join(mitresaw_output_directory, "techniques.csv")):
        os.remove(os.path.join(mitresaw_output_directory, "techniques.csv"))
    else:
        pass
    if saw:
        print_saw(saw, tagline, "                    ")
        print_saw(saw, tagline, "                  ")
        print_saw(saw, tagline, "                ")
        print_saw(saw, tagline, "              ")
        print_saw(saw, tagline, "            ")
        print_saw(saw, tagline, "          ")
        print_saw(saw, tagline, "        ")
        print_saw(saw, tagline, "      ")
        print_saw(saw, tagline, "    ")
        print_saw(saw, tagline, "  ")
        print_saw(saw, tagline, "partial")
        print_saw(saw, tagline, "-")  # remove saw
        print()
    if str(terms) != "['.']":
        terms_insert = " associated with '\033[1;36m{}\033[1;m'".format(
            str(terms)[2:-2].replace("_", " ").replace("', '", "\033[1;m', '\033[1;36m")
        )
    else:
        terms_insert = ""
    # obtaining group procedure
    for groupsfile in os.listdir(mitresaw_mitre_files):
        if groupsfile.endswith("-groups-techniques_used.csv"):
            with open(
                "{}".format(os.path.join(mitresaw_mitre_files, groupsfile)),
                encoding="utf-8",
            ) as groups_procedure_csv:
                for groups_procedure in groups_procedure_csv:
                    groups_procedure = re.sub(
                        r"\\n[\"'], [\"'](G\d{4},)",
                        r"\\n',<##>'\1",
                        groups_procedure,
                    )
                    for eachrow in groups_procedure.split("\\n',<##>'"):
                        for softwareorgroup in softwaregroups:
                            if softwareorgroup in eachrow and eachrow.startswith("G"):
                                row_elements = re.findall(
                                    r"^([^,]+),([^,]+),[^,]+,[^,]+,([^,]+),([^,]+),[^,]+,(.*)",
                                    eachrow.strip(),
                                )
                                if len(row_elements) > 0:
                                    group_id = row_elements[0][0]
                                    group_name = row_elements[0][1]
                                    technique_id = row_elements[0][2]
                                    technique_name = row_elements[0][3]
                                    procedure_description = row_elements[0][4]
                                    group_procedures[
                                        "{}||{}||{}||{}||{}".format(
                                            group_id,
                                            group_name,
                                            technique_id,
                                            technique_name,
                                            procedure_description,
                                        )
                                    ] = "-"
                                else:
                                    pass
                            else:
                                pass
        else:
            pass
    # obtaining group description
    for groupsfile in os.listdir(mitresaw_mitre_files):
        if groupsfile.endswith("-groups-groups.csv"):
            with open(
                "{}".format(os.path.join(mitresaw_mitre_files, groupsfile)),
                encoding="utf-8",
            ) as groupscsv:
                for groups_row in groupscsv:
                    groups_row = re.sub(
                        r"\\n[\"'], [\"'](G\d{4},)",
                        r"\\n',<##>'\1",
                        groups_row,
                    )
                    group_description_row = re.findall(
                        r"^([^,]+),([^,]+),([^\n]+),https:\/\/attack\.mitre\.org\/groups\/\1,\d{1,2} ",
                        groups_row.strip(),
                    )
                    if len(group_description_row) > 0:
                        group_id = group_description_row[0][0]
                        group_name = group_description_row[0][1]
                        group_description = group_description_row[0][2]
                        group_id_name = (
                            "[{}](https://attack.mitre.org/groups/{})".format(
                                group_name, group_id
                            )
                        )
                        if str(terms) == "['.']":
                            for group_procedure in group_procedures.keys():
                                if (
                                    group_procedure.split("||")[0] == group_id
                                    and group_procedure.split("||")[1] == group_name
                                    and group_id_name in str(group_procedure)
                                ):
                                    groups[
                                        "{}||{}||{}{}".format(
                                            group_procedure,
                                            group_description,
                                            term,
                                            additional_terms,
                                        )
                                    ] = "-"
                            additional_terms.clear()
                        else:
                            for term in terms:
                                if (
                                    term.lower().replace("_", " ")
                                    in group_description.lower()
                                ):
                                    for additional_term in terms:
                                        if (
                                            additional_term.lower()
                                            in group_description.lower()
                                        ):
                                            additional_terms.append(additional_term)
                                        else:
                                            pass
                                    for group_procedure in group_procedures.keys():
                                        if (
                                            group_procedure.split("||")[0] == group_id
                                            and group_procedure.split("||")[1]
                                            == group_name
                                            and group_id_name in str(group_procedure)
                                        ):
                                            groups[
                                                "{}||{}||{}{}".format(
                                                    group_procedure,
                                                    group_description,
                                                    term,
                                                    additional_terms,
                                                )
                                            ] = "-"
                                    additional_terms.clear()
                            else:
                                pass
                    else:
                        pass
        else:
            pass
    # obtaining software procedure
    for softwarefile in os.listdir(mitresaw_mitre_files):
        if softwarefile.endswith("-software-techniques_used.csv"):
            with open(
                "{}".format(os.path.join(mitresaw_mitre_files, softwarefile)),
                encoding="utf-8",
            ) as software_procedure_csv:
                for software_procedure in software_procedure_csv:
                    software_procedure = re.sub(
                        r"\\n[\"'], [\"'](S\d{4},)",
                        r"\\n',<##>'\1",
                        software_procedure,
                    )
                    for eachrow in software_procedure.split("\\n',<##>'"):
                        for softwareorgroup in softwaregroups:
                            if softwareorgroup in eachrow:
                                if eachrow.startswith("S"):
                                    row_elements = re.findall(
                                        r"^([^,]+),([^,]+),[^,]+,[^,]+,([^,]+),([^,]+),[^,]+,(.*)",
                                        eachrow.strip(),
                                    )
                                    if len(row_elements) > 0:
                                        software_id = row_elements[0][0]
                                        software_name = row_elements[0][1]
                                        technique_id = row_elements[0][2]
                                        technique_name = row_elements[0][3]
                                        procedure_description = row_elements[0][4]
                                        software_procedures[
                                            "{}||{}||{}||{}||{}".format(
                                                software_id,
                                                software_name,
                                                technique_id,
                                                technique_name,
                                                procedure_description,
                                            )
                                        ] = "-"
                                    else:
                                        pass
                                else:
                                    pass
                            else:
                                pass
        else:
            pass
    # obtaining software description
    for softwarefile in os.listdir(mitresaw_mitre_files):
        if softwarefile.endswith("-software-software.csv"):
            with open(
                "{}".format(os.path.join(mitresaw_mitre_files, softwarefile)),
                encoding="utf-8",
            ) as softwarecsv:
                for software_row in softwarecsv:
                    software_row = re.sub(
                        r"\\n[\"'], [\"'](S\d{4},)",
                        r"\\n',<##>'\1",
                        software_row,
                    )
                    software_description_row = re.findall(
                        r"^([^,]+),([^,]+),([^\n]+),https:\/\/attack\.mitre\.org\/software\/\1,\d{1,2} ",
                        software_row.strip(),
                    )
                    if len(software_description_row) > 0:
                        software_id = software_description_row[0][0]
                        software_name = software_description_row[0][1]
                        software_description = software_description_row[0][2]
                        software_id_name = (
                            "[{}](https://attack.mitre.org/software/{})".format(
                                software_name, software_id
                            )
                        )
                        if str(terms) == "['.']":
                            for software_procedure in software_procedures.keys():
                                if (
                                    software_procedure.split("||")[0] == software_id
                                    and software_procedure.split("||")[1]
                                    == software_name
                                    and software_id_name in str(software_procedure)
                                ):
                                    software[
                                        "{}||{}||{}{}".format(
                                            software_procedure,
                                            software_description,
                                            term,
                                            additional_terms,
                                        )
                                    ] = "-"
                            additional_terms.clear()
                        else:
                            for term in terms:
                                if (
                                    term.lower().replace("_", " ")
                                    in software_description.lower()
                                ):
                                    for additional_term in terms:
                                        if (
                                            additional_term.lower()
                                            in software_description.lower()
                                        ):
                                            additional_terms.append(additional_term)
                                        else:
                                            pass
                                    for (
                                        software_procedure
                                    ) in software_procedures.keys():
                                        if (
                                            software_procedure.split("||")[0]
                                            == software_id
                                            and software_procedure.split("||")[1]
                                            == software_name
                                            and software_id_name
                                            in str(software_procedure)
                                        ):
                                            software[
                                                "{}||{}||{}{}".format(
                                                    software_procedure,
                                                    software_description,
                                                    term,
                                                    additional_terms,
                                                )
                                            ] = "-"
                                    additional_terms.clear()
                                else:
                                    pass
                    else:
                        pass
        else:
            pass
    contextual_information = groups | software
    print()
    print(
        "    -> Extracting \033[1;31mIdentifiers\033[1;m from \033[1;32mTechniques\033[1;m based on \033[1;33mThreat Actors/Software\033[1;m{}".format(
            terms_insert
        )
    )
    for csvtechnique in os.listdir(mitresaw_mitre_files):
        if csvtechnique.endswith("-techniques-techniques.csv"):
            with open(
                "{}".format(os.path.join(mitresaw_mitre_files, csvtechnique)),
                encoding="utf-8",
            ) as techniquecsv:
                techniques_file_content = techniquecsv.readlines()
                for context in str(contextual_information)[2:-7].split(": '-', '"):
                    groupsoftware_id = context.split("||")[0]
                    groupsoftware_name = context.split("||")[1]
                    context_id = context.split("||")[2][1:]
                    if "T{},".format(context_id) in str(techniques_file_content):
                        replaced_technique_row = re.sub(
                            r"(,https://attack.mitre.org/techniques/T\d{4}(?:\/\d{3})?)(,)",
                            r"\1||\2",
                            str(techniques_file_content),
                        )
                        associated_technique = replaced_technique_row.split(
                            "T{},".format(context_id)
                        )[1].split("\"\\n', 'T")[0]
                        technique_name = associated_technique.split(",")[0]
                        technique_information = re.findall(
                            r",(.*),https:\/\/attack\.mitre\.org\/techniques\/T[\d\.\/]+\|\|,[^,]+,[^,]+,\d+\.\d+,\"?(?:Initial\ Access|Execution|Persistence|Privilege\ Escalation|Defense\ Evasion|Credential\ Access|Dicovery|Lateral\ Movement|Collection|Command\ and\ Control|Exfiltration|Impact)(?:(, (?:Initial\ Access|Execution|Persistence|Privilege\ Escalation|Defense\ Evasion|Credential\ Access|Dicovery|Lateral\ Movement|Collection|Command\ and\ Control|Exfiltration|Impact))?){0,13},(\"?.*\"?),(\"?(?:Azure AD|Containers|Google Workspace|IaaS|Linux|Network|Office 365|PRE|SaaS|Windows|macOS)(?:(?:, (?:Azure AD|Containers|Google Workspace|IaaS|Linux|Network|Office 365|PRE|SaaS|Windows|macOS))?){0,10}\"?),(\"[^\"]+\"),",
                            associated_technique,
                        )
                        if len(technique_information) > 0:
                            technique_description = technique_information[0][0]
                            technique_detection = technique_information[0][2]
                            technique_platforms = technique_information[0][3]
                            technique_data_sources = technique_information[0][4]
                            # obtaining navigation layers for all identified threat groups and software
                            if navlayers:
                                if groupsoftware_id.startswith("G"):
                                    groupsoftware = "groups"
                                elif groupsoftware_id.startswith("S"):
                                    groupsoftware = "software"
                                else:
                                    pass
                                navlayer_output_directory = os.path.join(
                                    mitresaw_root,
                                    "{}_navlayers".format(str(datetime.now())[0:10]),
                                )
                                navlayer_json = os.path.join(
                                    navlayer_output_directory,
                                    "{}_{}-enterprise-layer.json".format(
                                        groupsoftware_id, groupsoftware_name
                                    ),
                                )
                                if not os.path.exists(navlayer_json):
                                    if not os.path.exists(navlayer_output_directory):
                                        os.makedirs(navlayer_output_directory)
                                        print(
                                            "     -> Obtaining ATT&CK Navigator Layers for \033[1;33mThreat Actors/Software\033[1;m related to identified \033[1;32mTechniques\033[1;m...".format(
                                                groupsoftware_name
                                            )
                                        )
                                    else:
                                        pass
                                    groupsoftware_navlayer = requests.get(
                                        "https://attack.mitre.org/{}/{}/{}-enterprise-layer.json".format(
                                            groupsoftware,
                                            groupsoftware_id,
                                            groupsoftware_id,
                                        )
                                    )
                                    if not os.path.exists(navlayer_json):
                                        with open(navlayer_json, "wb") as navlayer_file:
                                            navlayer_file.write(
                                                groupsoftware_navlayer.content
                                            )
                                    else:
                                        pass
                                else:
                                    pass
                            else:
                                pass
                            if str(platforms) == "['.']":
                                valid_procedure = "{}||{}||{}||{}||{}".format(
                                    context,
                                    technique_description,
                                    technique_detection,
                                    technique_platforms,
                                    technique_data_sources,
                                )
                                valid_procedures.append(valid_procedure)
                            else:
                                for platform in platforms:
                                    if platform in technique_platforms:
                                        valid_procedure = "{}||{}||{}||{}||{}".format(
                                            context,
                                            technique_description,
                                            technique_detection,
                                            technique_platforms,
                                            technique_data_sources,
                                        )
                                        valid_procedures.append(valid_procedure)
                                    else:
                                        pass
                        else:
                            pass
                    else:
                        pass
        else:
            pass
    print()
    consolidated_procedures = sorted(list(set(valid_procedures)))
    for each_procedure in consolidated_procedures:
        (
            technique_findings,
            identifiers,
            previous_findings,
        ) = extract_indicators(
            each_procedure,
            terms,
            evidence_found,
            identifiers,
            previous_findings,
            truncate,
        )
    all_evidence.append(technique_findings)
    consolidated_techniques = all_evidence[0]
    if len(consolidated_techniques) > 0:
        query_pairings = []
        with open(
            os.path.join(mitresaw_output_directory, "techniques.csv"), "w"
        ) as opmitre_csv:
            opmitre_csv.write(
                "group_software_id,group_software_name,group_software_description,group_software_link,group_software_searchterms,technique_id,technique_name,groupsoftware_procedure,technique_description,technique_detection,technique_platforms,technique_datasources,evidence_type,evidence_indicators\n"
            )
        for dataset in consolidated_techniques:
            with open(
                os.path.join(mitresaw_output_directory, "techniques.csv"), "a"
            ) as opmitre_csv:
                opmitre_csv.write(
                    "{}\n".format(dataset.replace(",||,", ",").replace("||", ","))
                )
                if queries:
                    technique_id = dataset.split("||")[2]
                    technique_name = dataset.split("||")[3]
                    parameters = (
                        dataset.split("||")[-1].replace("\\\\\\\\", "\\\\").lower()
                    )
                    query_pairings.append(
                        "{}||{}||{}".format(technique_id, technique_name, parameters)
                    )
                else:
                    pass
            logsource = (
                dataset.split("||")[-3]
                .replace(
                    "Active Directory: Active Directory Credential Request",
                    "Command-line logging; Windows event logs",
                )
                .replace(
                    "Active Directory: Active Directory Object Access",
                    "Command-line logging; Windows event logs",
                )
                .replace(
                    "Active Directory: Active Directory Object Creation",
                    "Command-line logging; Windows event logs",
                )
                .replace(
                    "Active Directory: Active Directory Object Deletion",
                    "Command-line logging; Windows event logs",
                )
                .replace(
                    "Active Directory: Active Directory Object Modification",
                    "Command-line logging; Windows event logs",
                )
                .replace(
                    "Application Log: Application Log Content",
                    "Application Log Content",
                )
                .replace("Cloud Service: Cloud Service Disable", "Cloud API logging")
                .replace(
                    "Cloud Service: Cloud Service Enumeration", "Cloud API logging"
                )
                .replace(
                    "Cloud Service: Cloud Service Modification", "Cloud API logging"
                )
                .replace("Cloud Storage: Cloud Storage Access", "Cloud API logging")
                .replace("Cloud Storage: Cloud Storage Creation", "Cloud API logging")
                .replace("Cloud Storage: Cloud Storage Deletion", "Cloud API logging")
                .replace(
                    "Cloud Storage: Cloud Storage Enumeration", "Cloud API logging"
                )
                .replace(
                    "Cloud Storage: Cloud Storage Modification", "Cloud API logging"
                )
                .replace("Drive: Drive Access", "Windows event logs; setupapi.dev.log")
                .replace("Driver: Driver Load", "Sysmon")
                .replace("Command: Command Execution", "Command-line logging")
                .replace("Container: Container Creation", "Command-line logging")
                .replace("Container: Container Enumeration", "Command-line logging")
                .replace("Container: Container Start", "Command-line logging")
                .replace(
                    "File: File Access",
                    "Command-line logging; Windows event logs; Sysmon",
                )
                .replace(
                    "File: File Creation",
                    "Command-line logging; Windows event logs; Sysmon",
                )
                .replace(
                    "File: File Deletion",
                    "Command-line logging; Windows event logs; Sysmon",
                )
                .replace("File: File Metadata", "Artefact acquisition")
                .replace(
                    "File: File Modification",
                    "Command-line logging; Windows event logs; Sysmon",
                )
                .replace(
                    "Firewall: Firewall Disable",
                    "Command-line logging; Windows event logs",
                )
                .replace("Firewall: Firewall Enumeration", "Command-line logging")
                .replace(
                    "Firewall: Firewall Rule Modification",
                    "Command-line logging; Windows event logs",
                )
                .replace(
                    "Group: Group Enumeration",
                    "Command-line logging; Windows event logs",
                )
                .replace(
                    "Group: Group Modification",
                    "Command-line logging; Windows event logs",
                )
                .replace("Image: Image Creation", "Cloud API logging")
                .replace("Image: Image Deletion", "Cloud API logging")
                .replace("Image: Image Modification", "Cloud API logging")
                .replace("Instance: Instance Creation", "Cloud Audit logging")
                .replace("Instance: Instance Deletion", "Cloud Audit logging")
                .replace("Instance: Instance Enumeration", "Cloud Audit logging")
                .replace("Instance: Instance Modification", "Cloud Audit logging")
                .replace("Instance: Instance Start", "Cloud Audit logging")
                .replace("Instance: Instance Stop", "Cloud Audit logging")
                .replace("Kernel: Kernel Module Load", "/lib/module logging")
                .replace(
                    "Logon Session: Logon Session Creation",
                    "Windows event logs; *nix /var/log",
                )
                .replace("Module: Module Load", "Command-line logging; Sysmon")
                .replace(
                    "Named Pipe: Named Pipe Metadata", "Command-line logging; Sysmon"
                )
                .replace(
                    "Network Share: Network Share Access",
                    "Command-line logging; Windows event logs",
                )
                .replace(
                    "Network Traffic: Network Connection Creation",
                    "Process monitoring; Windows event logs; Sysmon; Zeek conn.log",
                )
                .replace("Network Traffic: Network Traffic Content", "PCAP")
                .replace("Network Traffic: Network Traffic Flow", "netflow")
                .replace(
                    "Process: OS API Execution",
                    "Process monitoring; PowerShell Script Block logging; Command-line logging",
                )
                .replace("Process: Process Access", "Sysmon")
                .replace(
                    "Process: Process Creation",
                    "Command-line logging; Windows event logs; Sysmon",
                )
                .replace(
                    "Process: Process Metadata",
                    "Sysmon",
                )
                .replace("Process: Process Modification", "Artefact acquisition")
                .replace("Process: Process Termination", "Windows event logs; Sysmon")
                .replace(
                    "Scheduled Job: Scheduled Job Creation",
                    "Windows event logs; *nix /var/log",
                )
                .replace(
                    "Scheduled Job: Scheduled Job Modification",
                    "Windows event logs; *nix /var/log",
                )
                .replace(
                    "Script: Script Execution",
                    "PowerShell Script Block logging; Command-line logging; Windows event logs; Microsoft-Windows-WMI-Activity/Trace & WMITracing.log",
                )
                .replace("Sensor Health: Host Status", "Host Availability logging")
                .replace(
                    "Service: Service Creation", "Windows event logs; *nix /var/log"
                )
                .replace(
                    "Service: Service Metadata",
                    "Command-line logging; Windows event logs; *nix /var/log",
                )
                .replace(
                    "Service: Service Modification", "Windows event logs; *nix /var/log"
                )
                .replace("Snapshot: Snapshot Creation", "Cloud API logging")
                .replace("Snapshot: Snapshot Deletion", "Cloud API logging")
                .replace("Snapshot: Snapshot Enumeration", "Cloud API logging")
                .replace("Snapshot: Snapshot Modification", "Cloud API logging")
                .replace(
                    "User Account: User Account Authentication",
                    "Windows event logs; *nix /var/log/auth.log",
                )
                .replace(
                    "User Account: User Account Creation",
                    "Windows event logs; *nix /etc/passwd logging",
                )
                .replace(
                    "User Account: User Account Deletion",
                    "Windows event logs; *nix /var/log/auth & access/authentication",
                )
                .replace(
                    "User Account: User Account Modification",
                    "Windows event logs; *nix /var/log/auth & access/authentication",
                )
                .replace("User Account: User Account Authentication", "")
                .replace("Volume: Volume Creation", "Cloud API logging")
                .replace("Volume: Volume Deletion", "Cloud API logging")
                .replace("Volume: Volume Enumeration", "Cloud API logging")
                .replace("Volume: Volume Modification", "Cloud API logging")
                .replace(
                    "Windows Registry: Windows Registry Key Access",
                    "Windows Registry monitoring",
                )
                .replace(
                    "Windows Registry: Windows Registry Key Creation",
                    "Windows Registry monitoring",
                )
                .replace(
                    "Windows Registry: Windows Registry Key Deletion",
                    "Windows Registry monitoring",
                )
                .replace(
                    "Windows Registry: Windows Registry Key Modification",
                    "Windows Registry monitoring",
                )
                .replace(
                    "WMI: WMI Creation",
                    "Command-line logging; Microsoft-Windows-WMI-Activity/Trace & WMITracing.log; Sysmon",
                )
            )
            log_sources.append(logsource)
        mitresaw_techniques = re.findall(r"\|\|(T\d{3}[\d\.]+)\|\|", str(consolidated_techniques))
        mitresaw_techniques = list(set(mitresaw_techniques))
        mitresaw_techniques_insert = str(mitresaw_techniques)[2:-2].replace("', '", '", "comment": "", "score": 1, "color": "#66b1ff", "showSubtechniques": false}}, {{"techniqueID": "')
        mitresaw_navlayer = '{{"description": "Enterprise techniques used by various Threat Actors/Software, produced by MITRESaw", "name": "{}", "domain": "enterprise-attack", "versions": {{"layer": "4.4", "attack": "13", "navigator": "4.8.1"}}, "techniques": [{{"techniqueID": "{}", "comment": "", "score": 1, "color": "#66b1ff", "showSubtechniques": false}}], "gradient": {{"colors": ["#ffffff", "#66b1ff"], "minValue": 0, "maxValue": 1}}, "legendItems": [{{"label": "identified from MITRESaw analysis", "color": "#66b1ff"}}]}}\n'.format(mitresaw_output_directory.split("/")[2][11:], mitresaw_techniques_insert)
        with open(os.path.join(mitresaw_output_directory, "enterprise-layer.json"), "w") as mitresaw_navlayer_json:
           mitresaw_navlayer_json.write(mitresaw_navlayer.replace("{{","{").replace("}}","}"))
        if queries:
            print(
                "\n     -> Building Queries for identified \033[1;32mTechniques\033[1;m...".format(
                    groupsoftware_name
                )
            )
            if os.path.exists(os.path.join(mitresaw_output_directory, "queries.conf")):
                os.remove(os.path.join(mitresaw_output_directory, "queries.conf"))
            else:
                pass
            with open(
                os.path.join(mitresaw_output_directory, "queries.conf"), "a"
            ) as opmitre_queries:
                for query in query_pairings:
                    query_combinations = []
                    queries_to_write = []
                    technique_id = query.split("||")[0]
                    technique_name = query.split("||")[1]
                    query_strings = query.split("||")[2]
                    if " " in query_strings:
                        if not query_strings.startswith("hk"):
                            if " " in query_strings:
                                andor_query = '("{}")'.format(
                                    query_strings.strip("'")
                                    .replace('"', '\\"')
                                    .replace(" ", '" and "')
                                    .replace("*", "")
                                    .strip('"')
                                    .strip("\\")
                                )
                    else:
                        andor_query = query_strings
                    if '"), ("' in andor_query and not andor_query.startswith('("'):
                        or_queries = '("{}")'.format(andor_query.replace("++", '", "'))
                    else:
                        or_queries = andor_query.replace("++", '", "')
                    if not or_queries.startswith('("') and not or_queries.endswith(
                        '")'
                    ):
                        or_queries = '("{}")'.format(or_queries)
                    else:
                        pass
                    or_queries = re.sub(r'(" and "[^\"]+")(, ")', r"\1§§\2", or_queries)
                    or_queries = re.sub(r'(" and "[^\"]+")(\))', r"\1)\2", or_queries)
                    or_queries = re.sub(r'(", )("[^\"]+" and ")', r"\1§§\2", or_queries)
                    or_queries = re.sub(r'(\()("[^\"]+" and ")', r"\1(\2", or_queries)
                    or_queries = or_queries.replace('(("', '("').replace('"))', '")')
                    multiple_queries = re.findall(r"§§([^§]+)(?:§§|\)$)", or_queries)
                    if len(multiple_queries) > 0:
                        and_queries = multiple_queries
                        or_queries = re.sub(r"§§[^§]+(?:§§|\)$)", "", or_queries)
                        or_queries = or_queries.replace('", , "', '", "')
                    else:
                        and_queries = or_queries
                    query_combinations.append("{}||{}".format(or_queries, and_queries))
                    if (
                        str(query_combinations)[2:-2].split("||")[0]
                        == str(query_combinations)[2:-2].split("||")[1]
                    ):
                        final_query = str(query_combinations)[2:-2].split("||")[0]
                    else:
                        final_query = (
                            str(query_combinations)[2:-2]
                            .replace("\", \\', \\', \"", '", "')
                            .replace("[\\', \"", '"')
                            .replace("\"\\']", '"')
                        )
                    final_query_combo = final_query.replace("\\\\\\\\", "\\\\").replace(
                        '""', '"'
                    )
                    stanza_title = str("[{}: {}]").format(technique_id, technique_name)
                    for query_combo_type in final_query_combo.split("||"):
                        if '" and "' in query_combo_type:
                            splunk_queries = (
                                "where {} IN(<field_name>)  // SPL [Splunk]".format(
                                    query_combo_type.strip("(")
                                    .strip(")")
                                    .replace("[\\'\"", '"')
                                    .replace("\\', \\'", "§§")
                                    .replace(" and ", " IN(<field_name>) AND where ")
                                    .replace(
                                        "§§",
                                        " IN(<field_name>)  // SPL [Splunk]\nwhere ",
                                    )
                                )
                            )
                            sentinel_queries = (
                                "<field_name> has_all{})  // KQL [Sentinel]".format(
                                    query_combo_type.replace('" and "', '", "')
                                    .replace("[\\'\"", '("')
                                    .replace(
                                        "\\', \\'",
                                        ")  // KQL [Sentinel]\n<field_name> has_all(",
                                    )
                                )
                            )
                            kql_queries = (
                                "<field_name>:({})  // KQL [Elastic/Kibana]".format(
                                    query_combo_type.strip("(")
                                    .strip(")")
                                    .replace("[\\'\"", '"')
                                    .replace("\\', \\'", "§§")
                                    .replace(
                                        "§§",
                                        ")  // KQL [elastic/Kibana]\n<field_name>:(",
                                    )
                                    .replace('", "', '" OR "')
                                    .replace('" and "', '" AND "')
                                )
                            )
                            lucene_queries = (
                                (
                                    "/.*{}.*/  // Lucene [elastic/Kibana]".format(
                                        re.sub(
                                            r"(\w)",
                                            elastic_query_repl,
                                            query_combo_type.replace(
                                                '" and "', "¬¬"
                                            ).replace("/", "\\\\/"),
                                        )
                                        .strip("(")
                                        .strip(")")
                                        .strip('"')
                                        .replace("[\\'\"", '"')
                                        .replace("\\', \\'", "§§")
                                        .replace(".", "\\\\.")
                                        .replace(" ", "\\\\ ")
                                        .replace('", "', '" or "')
                                        .replace(
                                            "§§",
                                            ".*/  // Lucene [elastic/Kibana]\n/.*",
                                        )
                                        .replace("¬¬", ".*")
                                        .replace(
                                            '*,\\\\ "',
                                            ".*/  // Lucene [elastic/Kibana]\n/.*",
                                        )
                                        .replace(
                                            '",\\\\ "',
                                            ".*/  // Lucene [elastic/Kibana]\n/.*",
                                        )
                                        .replace('/.*"', "/.*")
                                        .replace('".*/', ".*/")
                                    )
                                )
                                .replace('/.*"[', "/.*[")
                                .replace("-", "\\\\-")
                                .replace("(", "\\\\(")
                                .replace(")", "\\\\)")
                                .replace('"[remote" and "address]', "[remote address]")
                                .replace("\n/..*/  // Lucene [elastic/Kibana]\n", "")
                            )
                            dsl_queries = '{{"bool": {{"must": [{{"query_string": {{"query": "{}","fields": ["<field_name>","<field_name>"]}}}}]}}}}'.format(
                                lucene_queries.replace(" Lucene ", " Query DSL ")
                            )
                            elastic_api_queries = '{{"query": {{"terms": {{"<field name>": [ "{}" ]}}}}}}  // API [elastic/Kibana]'.format(
                                lucene_queries.replace(" Lucene ", " Query DSL ")
                            )
                            queries_to_write.append(
                                "{}\n{}\n{}\n{}\n{}\n{}\n{}\n\n\n".format(
                                    stanza_title,
                                    splunk_queries,
                                    sentinel_queries,
                                    lucene_queries,
                                    kql_queries,
                                    dsl_queries,
                                    elastic_api_queries,
                                )
                            )
                        else:
                            splunk_query = (
                                "where {} IN(<field_name>)  // SPL [Splunk]".format(
                                    query_combo_type
                                )
                            )
                            sentinel_query = (
                                "<field_name> has_any{}  // KQL [Sentinel]".format(
                                    query_combo_type
                                )
                            )
                            kql_query = (
                                "<field_name>:({})  // KQL [elastic/Kibana]".format(
                                    query_combo_type.replace("', '", '" or "')
                                )
                            )
                            lucene_query = (
                                "/.*{}.*/  // Lucene [elastic/Kibana]".format(
                                    re.sub(
                                        r"(\w)",
                                        elastic_query_repl,
                                        query_combo_type,
                                    ).replace("', '", '" OR "')
                                )
                            )
                            dsl_query = '{{"bool": {{"must": [{{"query_string": {{"query": "{}","fields": ["<field_name>","<field_name>"]}}}}]}}}}  // API [elastic/Kibana]'.format(
                                query_combo_type
                            )
                            elastic_api_query = '{{"query": {{"terms": {{"<field name>": [ "{}" ]}}}}}}  // Query DSL [elastic/Kibana]'.format(
                                query_combo_type
                            )
                            queries_to_write.append(
                                "{}\n{}\n{}\n{}\n{}\n{}\n{}\n\n\n".format(
                                    stanza_title,
                                    splunk_query,
                                    sentinel_query,
                                    lucene_query,
                                    kql_query,
                                    dsl_query,
                                    elastic_api_query,
                                )
                            )
                        for query_to_write in queries_to_write:
                            opmitre_queries.write(query_to_write)
        else:
            pass
        log_sources = sorted(
            str(log_sources)[3:-3]
            .replace(", ", "; ")
            .replace("'; '", "; ")
            .replace('"; "', "; ")
            .replace("; ", ", ")
            .split(", ")
        )
        counted_log_sources = Counter(log_sources)
        log_coverage = sorted(
            counted_log_sources.items(), key=lambda x: x[1], reverse=True
        )
        print(
            "\n     The following log sources are required to \033[4;37mdetect\033[1;m the aforementioned ATT&CK techniques:"
        )
        print()
        time.sleep(0.5)
        for log_count in log_coverage:
            log = log_count[0]
            count = log_count[1]
            percentage = str(int(count / len(log_sources) * 100))
            if percentage == "0":
                percentage = "<1"
            else:
                pass
            print("       - {}: \033[1;37m{}%\033[1;m".format(log, percentage))
    else:
        print("\n    -> No evidence could be found which match the provided criteria.")
    print("\n\n")


if __name__ == "__main__":
    main()
