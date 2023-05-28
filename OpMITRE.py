#!/usr/bin/env python3 -tt
import argparse
import os
import pandas
import re
import requests
import shutil
import subprocess
import sys
import time


parser = argparse.ArgumentParser()
parser.add_argument(
    "-n",
    "--make-nav",
    nargs=1,
    help="Make ATT&CK Navigator json file based on provided string list e.g. mining,technology,defense,law. Note: use . to obtain all Threat Actors",
)
parser.add_argument(
    "-q",
    "--queries",
    help="Build JSON queries for either all techniques or techniques affiliated with identified Threat Actors (depending on --make-nav parameter), to be imported into Elastic/Kibana",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-s",
    "--silent",
    help="Show no output",
    action="store_const",
    const=True,
    default=False,
)

args = parser.parse_args()
nav_terms = args.make_nav
queries = args.queries
silent = args.silent

mitre_version = "13.1"
data_type = ["techniques", "groups"]
field_mappings = {"Active Directory": "event.code, Command", "Domain Name": "dns.query.name.keyword, dns.answers.name.keyword", "File": "file.name, Command", "Firewall": "event.code, Command", "Group": "event.code", "Logon Session": "event.code, EventLogonType, Command", "Network Shares": "event.code, Command", "Network Traffic": "", "Scheduled Jobs": "event.code, Command", "Service": "event.code, Command", "User Account": "event.code, Command"}
port_indicators = []
code_indicators = []
collected_indicators = []

def extract_port_indicators(technique_id, technique_name, threat_actor, description):
    description = re.sub(r"\(Citation[^\)]+\)", r"", re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", description))
    description = description.replace('""','"').replace(". . ",". ").replace(".. ",". ").replace("\\\\\\'","'").replace("\\\\'","'").replace("\\'","'").strip(",").strip('"').strip(",").strip('"')
    description = re.sub(r"`([^`]+)`", r"<code>\1</code>", description)
    port_identifiers = re.findall(r"(?:(?:[Pp]orts?(?: of)? |and |& |or |, |e\.g\.? |tcp: ?|udp: ?)|(?:\())(\d{2,})(?: |/|\. |,|\<)", description)
    port_identifiers = list(filter(lambda port: '365' != port, list(filter(lambda port: '10' != port, port_identifiers)))) # remove string from list
    if len(port_identifiers) > 0:
        port_indicators.append("{}||{}||{}".format(technique_id, technique_name, threat_actor, str(list(set(port_identifiers)))))
    else:
        pass
    return port_indicators


def extract_code_indicators(technique_id, technique_name, threat_actor, description):
    code_identifiers = re.findall(r"<code> ?([^\[\]\(\)\{\}:!#$%<>]{3,})</code>", description)
    code_results = []
    identifiers = list(set(code_identifiers))
    for each_identifier in identifiers:
        if "id" != each_identifier.lower() and "dll" != each_identifier.lower() and "build" != each_identifier.lower() and "label" != each_identifier.lower() and "name" != each_identifier.lower() and "type" != each_identifier.lower() and "example" not in each_identifier.lower() and "evil" not in each_identifier.lower() and "test" not in each_identifier.lower() and "file" not in each_identifier.lower() and "executable" not in each_identifier.lower() and "ctrl" not in each_identifier.lower() and "script" not in each_identifier.lower() and "hack" not in each_identifier.lower() and "phish" not in each_identifier.lower() and "suspicious" not in each_identifier.lower() and "malware" not in each_identifier.lower() and "password" not in each_identifier.lower() and "function" not in each_identifier.lower() and "funcname" not in each_identifier.lower():
            code_results.append(re.sub(r"&lt;([^&]+)&gt;", r"\1", each_identifier.replace("\\\\\\\\\\\\\\\\","\\\\\\\\").replace("\\\\\\\\\\\\","\\\\\\").replace("\\\\\\\\","\\\\").replace("\\\\","\\")).lower())
        else:
            pass
    code_indicators.append("{}||{}||{}".format(technique_id, technique_name, threat_actor, code_results))
    return code_indicators


def upper_repl(match):
    return "[{}{}]".format(match.group(1).upper(), match.group(1).lower())


def main():
    subprocess.Popen(["clear"])
    time.sleep(0.2)
    if not silent:
        print(
            """
        _______          ______  ___________________________ __________
        __  __ \________ ___   |/  /____  _/___  __/___  __ \___  ____/
        _  / / /___  __ \__  /|_/ /  __  /  __  /   __  /_/ /__  __/   
        / /_/ / __  /_/ /_  /  / /  __/ /   _  /    _  _, _/ _  /___   
        \____/  _  .___/ /_/  /_/   /___/   /_/     /_/ |_|  /_____/   
                /_/ *ATT&CK v13
        """
        )
    else:
        print("\n\t🤫 *sssshhhhhh running in silent mode...*\n")
    for eachtype in data_type:
        filename = "enterprise-attack-v{}-{}.".format(mitre_version, eachtype)
        spreadsheet = "{}xlsx".format(filename)
        mitre_spreadsheet = requests.get("https://attack.mitre.org/docs/enterprise-attack-v{}/{}".format(mitre_version, spreadsheet))
        with open(spreadsheet, "wb") as spreadsheet_file:
            spreadsheet_file.write(mitre_spreadsheet.content)
        temp_csv = "{}temp.csv".format(filename)
        if eachtype == "techniques":
            xlsx_file = pandas.read_excel(spreadsheet, 'techniques')
        elif eachtype == "groups":
            xlsx_file = pandas.read_excel(spreadsheet, 'techniques used')
        else:
            pass
        xlsx_file.to_csv(temp_csv, index=None, header=True)
        with open(temp_csv) as csv_with_new_lines:
            malformed_csv = str(csv_with_new_lines.readlines())[2:-2]
            malformed_csv = re.sub(r"\\t", r"", malformed_csv)
            if "-techniques" in filename:
                malformed_csv = re.sub(r"\\n', '(T\d{4})", r"\n\1", malformed_csv)
                malformed_csv = re.sub(r"\\n['\"], ['\"]\\n['\"], ['\"]", r".  ", malformed_csv)
                formated_csv = malformed_csv
            else:
                malformed_csv = re.sub(r"\\n', '", r"\n", malformed_csv)
                malformed_csv = re.sub(r"\n\"\\n', \"", r"\"\n", malformed_csv)
                malformed_csv = re.sub(r"\n\"\n", r"\"\n", malformed_csv)
                malformed_csv = re.sub(r"\n( ?[^G])", r"\1", malformed_csv)
                malformed_csv = re.sub(r"\\n', \"", r"\"\n", malformed_csv)
                malformed_csv = re.sub(r"\\n\", '", r"\"\n", malformed_csv)
                formated_csv = malformed_csv.replace('\\"','"')
        with open("{}csv".format(filename), "w") as final_csv:
            final_csv.write(formated_csv)
        os.remove(temp_csv)
    for csvfilename in os.listdir("./"):
        if "-techniques.csv" in csvfilename:
            with open("{}".format(csvfilename)) as csv:
                for eachrow in csv:
                    row_elements = re.findall(r"^([^,]+),([^,]+),(.*)[\",]https://attack.mitre.org/techniques/T\d{4}(?:/\d{3})?,\d+ \w+ \d+,\d+ \w+ \d+,[\d\.]+,\"?[A-Za-z ,]+\"?,(.*),\"?(?:Azure AD|Containers|Google Workspace|IaaS|Linux|Network|Office 365|PRE|SaaS|Windows|macOS)[\",]", eachrow.strip())
                    if len(row_elements) > 0:
                        technique_id, technique_name, description, detection = row_elements[0]
                        technique_ports = extract_port_indicators(technique_id, technique_name, "Any", "{} && {}".format(description, detection))
                        if "<code>" in description:
                            technique_code = extract_code_indicators(technique_id, technique_name, "Any", description)
                        else:
                            pass
            technique_ports = port_indicators
        elif "-groups.csv" in csvfilename:
            with open("{}csv".format(filename)) as csv:
                for eachrow in csv:
                    row_elements = re.findall(r"^[^,]+,([^,]+),[^,]+,[^,]+,([^,]+),([^,]+),[^,]+,([^\n]+)", eachrow.strip())
                    threat_actor, technique_id, technique_name, description = row_elements[0]
                    group_ports = extract_port_indicators(technique_id, technique_name, threat_actor, description)
                    if "<code>" in description:
                        group_code = extract_code_indicators(technique_id, technique_name, threat_actor, description)
                    else:
                        pass
        else:
            pass
    # lopp through lists and merge/consolidate
    extracted_ports = technique_ports + group_ports
    extracted_code = technique_code + group_code


if __name__ == "__main__":
    main()
