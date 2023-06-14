#!/usr/bin/env python3 -tt
import argparse
import os
import pandas
import random
import re
import requests
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
    "threatgroups",
    nargs=1,
    help="Filter Threat Actor results based on specific group names e.g. APT29,HAFNIUM,Lazurus_Group,Turla (use _ instead of spaces)\n Use . to not filter i.e. obtain all Threat Actors\n",
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
actor_groups = args.threatgroups
queries = args.queries
truncate = args.truncate

attack_framework = "enterprise"
attack_version = "13.1"
sheet_tabs = ["techniques-techniques", "groups-groups", "groups-techniques used"]
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
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{44})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{46})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{48})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{50})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{52})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{54})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{56})", r"", saw))
        time.sleep(0.1)
        subprocess.Popen(["clear"]).communicate()
        print(tagline)
        print(re.sub(r"(@[\S\s]{58})", r"", saw))
        time.sleep(0.2)
    else:
        pass


def extract_port_indicators(
    technique_findings,
    technique_id,
    technique_name,
    description,
    threat_actor,
    threat_actor_method_description,
    data_sources,
    actor_terms,
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
    # description = re.sub(r"`([^`]+)`", r"<code>\1</code>", description)
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
    if len(port_identifiers) > 0:
        if actor_terms != "*":
            print_insert = "target '{}' using".format(actor_terms.replace("_", " "))
        else:
            print_insert = "use"
        print_statement = (
            "   -> '{}' has been known to {} '{}'; detectable via: {}".format(
                threat_actor, print_insert, technique_name, str(port_identifiers)[1:-1]
            )
        )
    else:
        print_statement = "-"
    technique_findings.append(
        "{}||{}||{}||{}||{}||ports||{}||{}||{}||{}".format(
            technique_id,
            technique_name,
            threat_actor,
            "||".join(threat_actor_method_description.split("||")[0:-1]),
            actor_terms.replace("_", " "),
            description.split(" && ")[1],
            str(list(set(port_identifiers))),
            data_sources,
            print_statement,
        )
    )
    return technique_findings, "ports"


def extract_evt_indicators(
    technique_findings,
    technique_id,
    technique_name,
    description,
    threat_actor,
    threat_actor_method_description,
    data_sources,
    actor_terms,
):
    evt_identifiers = re.findall(
        r"(?:(?:Event ?|E)I[Dd]( ==)? ?\"?(\d{1,5}))", description
    )
    evt_results = []
    wel_identifiers = list(set(evt_identifiers))
    for identifier_set in wel_identifiers:
        for each_identifier in identifier_set:
            if (
                len(each_identifier) > 0
                and "](https://attack.mitre.org/" not in each_identifier
                and "example" not in each_identifier.lower()
                and "citation" not in each_identifier.lower()
                and not each_identifier.startswith(")")
                and not each_identifier.endswith("(")
            ):
                evt_results.append(each_identifier)
            else:
                pass
    if len(evt_results) > 0:
        if actor_terms != "*":
            print_insert = "target '{}' using".format(actor_terms.replace("_", " "))
        else:
            print_insert = "use"
        print_statement = (
            "   -> '{}' has been known to {} '{}'; detectable via: {}".format(
                threat_actor, print_insert, technique_name, str(evt_results)[1:-1]
            )
        )
    else:
        print_statement = "-"
    technique_findings.append(
        "{}||{}||{}||{}||{}||evts||{}||{}||{}||{}".format(
            technique_id,
            technique_name,
            threat_actor,
            "||".join(threat_actor_method_description.split("||")[0:-1]),
            actor_terms.replace("_", " "),
            description.split(" && ")[1],
            evt_results,
            data_sources,
            print_statement,
        )
    )
    return technique_findings, "evts"


def extract_reg_indicators(
    technique_findings,
    technique_id,
    technique_name,
    description,
    threat_actor,
    threat_actor_method_description,
    data_sources,
    actor_terms,
):
    reg_identifiers = re.findall(
        r"([Hh][Kk](?:[Ll][Mm]|[Cc][Uu]|[Ee][Yy])[^\{\}!$<>`]+)", description
    )
    registry_identifiers = list(set(reg_identifiers))
    if len(registry_identifiers) > 0:
        if actor_terms != "*":
            print_insert = "target '{}' using".format(actor_terms.replace("_", " "))
        else:
            print_insert = "use"
        print_statement = (
            "   -> '{}' has been known to {} '{}'; detectable via: {}".format(
                threat_actor,
                print_insert,
                technique_name,
                str(registry_identifiers)[1:-1]
                .lower()
                .replace("\\\\\\\\\\\\\\\\", "\\\\\\\\")
                .replace("\\\\\\\\\\\\", "\\\\\\")
                .replace("\\\\\\\\", "\\\\")
                .replace("hkey_local_machine", "hklm")
                .replace("hkey_current_user", "hkcu")
                .replace("£\\\\t£", "\\\\t")
                .replace('""', '"')
                .replace("  ", " ")
                .replace("[.]", ".")
                .replace("[:]", ":")
                .replace("&#42;", "*")
                .replace("&lbrace;", "{")
                .replace("&rbrace;", "}")
                .replace("[username]", "%%username%%")
                .replace("\\]\\", "]\\")
                .replace("“", '"')
                .replace("”", '"')
                .strip("\\"),
            )
        )
    else:
        print_statement = "-"
    technique_findings.append(
        "{}||{}||{}||{}||{}||regs||{}||{}||{}||{}".format(
            technique_id,
            technique_name,
            threat_actor,
            "||".join(threat_actor_method_description.split("||")[0:-1]),
            actor_terms.replace("_", " "),
            description.split(" && ")[1],
            str(registry_identifiers)[1:-1]
            .lower()
            .replace("\\\\\\\\\\\\\\\\", "\\\\\\\\")
            .replace("\\\\\\\\\\\\", "\\\\\\")
            .replace("\\\\\\\\", "\\\\")
            .replace("hkey_local_machine", "hklm")
            .replace("hkey_current_user", "hkcu")
            .replace("£\\\\t£", "\\\\t")
            .replace('""', '"')
            .replace("  ", " ")
            .replace("[.]", ".")
            .replace("[:]", ":")
            .replace("&#42;", "*")
            .replace("&lbrace;", "{")
            .replace("&rbrace;", "}")
            .replace("[username]", "%%username%%")
            .replace("\\]\\", "]\\")
            .replace("“", '"')
            .replace("”", '"')
            .strip("\\"),
            data_sources,
            print_statement.replace("£\\\\t£", "\\\\t")
            .replace('""', '"')
            .replace("[username]", "%%username%%")
            .replace("\\]\\", "]\\")
            .replace("“", '"')
            .replace("”", '"')
            .strip("\\"),
        )
    )
    return technique_findings, "reg"


def extract_cmd_indicators(
    technique_findings,
    technique_id,
    technique_name,
    description,
    threat_actor,
    threat_actor_method_description,
    data_sources,
    actor_terms,
):
    terms_identifiers = re.findall(
        r"(?:(?:<code> ?([^\{\}!$<>`]{3,}) ?</code>)|(?:` ?([^\{\}!$<>`]{3,}) ?`)|(?:\[ ?([^\{\}!$<>`]{3,}) ?\]\(https://attack\.mitre\.org/software))",
        description,
    )
    terms_results = []
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
                terms_results.append(
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
    if len(terms_results) > 0:
        if actor_terms != "*":
            print_insert = "target '{}' using".format(actor_terms.replace("_", " "))
        else:
            print_insert = "use"
        print_statement = (
            "   -> '{}' has been known to {} '{}'; detectable via: {}".format(
                threat_actor,
                print_insert,
                technique_name,
                str(terms_results)[1:-1]
                .lower()
                .replace("\\\\\\\\\\\\\\\\", "\\\\\\\\")
                .replace("\\\\\\\\\\\\", "\\\\\\")
                .replace("\\\\\\\\", "\\\\")
                .replace("£\\\\t£", "\\\\t")
                .replace('""', '"')
                .replace("[username]", "%%username%%")
                .replace("\\]\\", "]\\")
                .replace("“", '"')
                .replace("”", '"')
                .strip("\\"),
            )
        )
    else:
        print_statement = "-"
    technique_findings.append(
        "{}||{}||{}||{}||{}||terms||{}||{}||{}||{}".format(
            technique_id,
            technique_name,
            threat_actor,
            "||".join(threat_actor_method_description.split("||")[0:-1]),
            actor_terms.replace("_", " "),
            description.split(" && ")[1],
            terms_results,
            data_sources,
            print_statement,
        )
    )
    return technique_findings, "terms"


def extract_indicators(
    truncate,
    technique_id,
    technique_name,
    threat_actor,
    actor_techniques_used,
    description,
    detection,
    data_sources,
    actor_terms,
    previous_findings,
):
    technique_findings = []
    if "{}||{}||{}||".format(technique_id, technique_name, threat_actor) in str(
        actor_techniques_used
    ):  # check if threat_actor matches entry in associated_threat_actors and retain contextual information
        threat_actor_method_description = (
            str(actor_techniques_used)
            .split(
                "{}||{}||{}||".format(
                    technique_id,
                    technique_name,
                    threat_actor,
                )
            )[1]
            .split("',")[0]
        )
        # extracting ports
        (
            technique_findings,
            evidence_type,
        ) = extract_port_indicators(
            technique_findings,
            technique_id,
            technique_name,
            "{} && {}".format(
                description,
                detection.replace("..  ", ".  "),
            ),
            threat_actor,
            threat_actor_method_description,
            data_sources,
            actor_terms,
        )
        (
            technique_findings,
            evidence_type,
        ) = extract_port_indicators(
            technique_findings,
            technique_id,
            technique_name,
            threat_actor_method_description.replace("||", " && "),
            threat_actor,
            threat_actor_method_description,
            data_sources,
            actor_terms,
        )
        # extracting event IDs
        if (
            "Event ID" in description
            or "EID" in description
            or "EventId" in description
            or "Event ID" in detection
            or "EID" in detection
            or "EventId" in detection
        ):  # extracting from technique description
            (
                technique_findings,
                evidence_type,
            ) = extract_evt_indicators(
                technique_findings,
                technique_id,
                technique_name,
                "{} && {}".format(
                    description,
                    detection.replace("..  ", ".  "),
                ),
                threat_actor,
                threat_actor_method_description,
                data_sources,
                actor_terms,
            )
        else:
            pass
        if (
            "Event ID" in threat_actor_method_description
            or "EID" in threat_actor_method_description
            or "EventId" in threat_actor_method_description
        ):  # extracting from threat actor description
            (
                technique_findings,
                evidence_type,
            ) = extract_evt_indicators(
                technique_findings,
                technique_id,
                technique_name,
                threat_actor_method_description.replace("||", " && "),
                threat_actor,
                threat_actor_method_description,
                data_sources,
                actor_terms,
            )
        else:
            pass
        # extracting registry artefacts
        if (
            "hklm\\" in description
            or "hkcu\\" in description
            or "HKLM\\" in description
            or "HKCU\\" in description
            or "hkey_local_machine\\" in description
            or "hkey_current_user\\" in description
            or "HKEY_LOCAL_MACHINE\\" in description
            or "HKEY_CURRENT_USER\\" in description
            or "hklm]" in description
            or "hkcu]" in description
            or "HKLM]" in description
            or "HKCU]" in description
            or "hkey_local_machine]" in description
            or "hkey_current_user]" in description
            or "HKEY_LOCAL_MACHINE]" in description
            or "HKEY_CURRENT_USER]" in description
        ):  # extracting from technique description
            (
                technique_findings,
                evidence_type,
            ) = extract_reg_indicators(
                technique_findings,
                technique_id,
                technique_name,
                "{} && {}".format(
                    description,
                    detection.replace("..  ", ".  "),
                ),
                threat_actor,
                threat_actor_method_description,
                data_sources,
                actor_terms,
            )
        else:
            pass
        if (
            "hklm\\" in threat_actor_method_description
            or "hkcu\\" in threat_actor_method_description
            or "HKLM\\" in threat_actor_method_description
            or "HKCU\\" in threat_actor_method_description
            or "hkey_local_machine\\" in threat_actor_method_description
            or "hkey_current_user\\" in threat_actor_method_description
            or "HKEY_LOCAL_MACHINE\\" in threat_actor_method_description
            or "HKEY_CURRENT_USER\\" in threat_actor_method_description
            or "hklm]" in threat_actor_method_description
            or "hkcu]" in threat_actor_method_description
            or "HKLM]" in threat_actor_method_description
            or "HKCU]" in threat_actor_method_description
            or "hkey_local_machine]" in threat_actor_method_description
            or "hkey_current_user]" in threat_actor_method_description
            or "HKEY_LOCAL_MACHINE]" in threat_actor_method_description
            or "HKEY_CURRENT_USER]" in threat_actor_method_description
        ):  # extracting from threat actor description
            (
                technique_findings,
                evidence_type,
            ) = extract_reg_indicators(
                technique_findings,
                technique_id,
                technique_name,
                threat_actor_method_description.replace("||", " && "),
                threat_actor,
                threat_actor_method_description,
                data_sources,
                actor_terms,
            )
        else:
            pass
        # extracting commands
        if (
            "<code>" in description or "`" in description
        ):  # extracting from technique description
            (
                technique_findings,
                evidence_type,
            ) = extract_cmd_indicators(
                technique_findings,
                technique_id,
                technique_name,
                "{} && {}".format(
                    description,
                    detection.replace("..  ", ".  "),
                ),
                threat_actor,
                threat_actor_method_description,
                data_sources,
                actor_terms,
            )
        else:
            pass
        if (
            "<code>" in threat_actor_method_description
            or "`" in threat_actor_method_description
        ):  # extracting from threat actor description
            (
                technique_findings,
                evidence_type,
            ) = extract_cmd_indicators(
                technique_findings,
                technique_id,
                technique_name,
                threat_actor_method_description.replace("||", " && "),
                threat_actor,
                threat_actor_method_description,
                data_sources,
                actor_terms,
            )
        else:
            pass
        if len(technique_findings) > 0:
            for each_finding in technique_findings:
                print_statement = str(each_finding).split("||")[-1].replace("\\'", "'")
                if print_statement != "-":
                    cleaned_statement = print_statement.replace(
                        "\\\\\\\\", "\\\\"
                    ).replace("", "")
                    if "'; detectable via" in cleaned_statement:
                        (
                            statement_prefix,
                            statement_suffix,
                        ) = cleaned_statement.split("'; detectable via")
                        if (
                            "{}::{}".format(
                                threat_actor,
                                technique_name,
                            ),
                            "{}::{}".format(
                                evidence_type,
                                statement_suffix[0:-1]
                                .replace("', \"", "', '")
                                .replace("\", '", "', '"),
                            ),
                        ) not in previous_findings.items():
                            if each_finding.split("||")[-5] == "ports":
                                print_insert = " Port(s)"
                            elif each_finding.split("||")[-5] == "evts":
                                print_insert = " Event ID(s)"
                            else:
                                print_insert = ""
                            statement_insert = "'\033[1;36m{}\033[1;m'".format(
                                statement_prefix.split("target '")[1]
                                .split("' using")[0]
                                .replace("', '", "\033[1;m', '\033[1;36m")
                            )
                            statement_prefix = "     -> '\033[1;33m{}\033[1;m' -> {} -> '\033[1;32m{}\033[1;m".format(
                                statement_prefix.split("'")[1],
                                statement_insert,
                                statement_prefix.split("'")[-1],
                            )
                            if not truncate:
                                print(
                                    "{}'; detectable via{}{}\033[1;m'".format(
                                        statement_prefix,
                                        print_insert,
                                        statement_suffix[0:-1]
                                        .replace("', \"", "', '")
                                        .replace("\", '", "', '")
                                        .replace(
                                            ": '",
                                            ": '\033[1;31m",
                                        )
                                        .replace(
                                            "', '",
                                            "\033[1;m', '\033[1;31m",
                                        )
                                        .strip("\\"),
                                    )
                                )
                            else:
                                print("{}'".format(statement_prefix))
                            previous_findings[
                                "{}::{}".format(
                                    threat_actor,
                                    technique_name,
                                )
                            ] = "{}::{}".format(
                                evidence_type,
                                statement_suffix[0:-1]
                                .replace("', \"", "', '")
                                .replace("\", '", "', '"),
                            )
                            time.sleep(0.2)
                    else:
                        pass
                    return technique_findings
                else:
                    pass
    else:
        pass


def main():
    time.sleep(0.5)
    saw = """
@                                                    ,╓▄▄#ΦN╥
@                ╓▓▀▀▓                     ,╓▄▄▄▓▓███╫╫▓██▌╫▓
@                ║▌,,▓▌           ,╦▄▄╦B▀▀██╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫▓▓█▄
@                 ▓████      ,▄███╫░░╫╫╫▓▓▄░╨███╫╫▀╜"╙█▓╫╫╫╫▓▓▓▓▄
@                 ╙███╫▌,╥╦]Ñ░░░░░░░░╨▀╗▄▒▀█▓▄░▀╫U    █▀▀▓▓▓▓▓▓██▓╕
@                  ▓Ñ░░░░░╦╫╫╫╫╫╫╫╫╫Ñ╦░░░░▀╦░▀▓╦░╨▓K╗▄,    ▀▓▓▓▓██▓▌
@                 ,╦░░╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫╫Ñ░░░╫░╫╫Ñ░╫╫╫╫N     ▀▓▓▓╫██▌
@               ,]░░╫╫╫╫╫╫▓▓████████▓▓╫╫╫╫╫Ñ░░░µ░╠▄░░▄▄▄▒Ñ╥    ▀▓▓▓▓▓▌
@   ╓▄▄▄╫█╫    ,Ñ░╫╫╫╫╫╫▓███████████████▓╫╫╫╫Ñ░░╬░╟▓░╟▓▓▓▌░     ╟▓▓▓▓▓
@   ║███╫█╫   .░░╫╫╫╫╫████▓▓▓▓█▓▓█▓▓▓▓████╫╫╫╫Ñ░░M░▀M░▀█▓▓░N  ,▄█▓▓▓▓▓M
@   ╙▀▀▀╫█╫   ]░╬╫╫╫╫███▓▓▓▓▀░╫╦╬░░╟▓▓▓▓███╫╫╫╫░░Ñ]╙▀░║████████╫╫╫╬Ñ╫Å
@    ║▓▓╫█╫▓▓▓░░╫╫╫╫▓██▓▓▓▓░╫Ñ░▄╬░╫Ñ░▓▓▓▓██▓╫╫╫Ñ░░└░░░▓█▀▀▀░╬╫╫▀╙,,╬M
@    ╙▀▀╫█╫    `██████▓▓▓▓▌░╫Ñ╟▓▓M╫Ñ░▓▓▓▓▓████▌       ▐▓Ω     `╙╜╜^
@    ,╩▀╫╥╦╦╦╦╬╨╨╨░╠▀▀▀▀▀░░░░░░╫░░░▀▀▀▀▀░░╨╨╨½╦╦╦╦╦╦╦▀▀▀╦╦
@   ▀▀▀▀▀▀▀▀▀▀▀▀▀████▀▀██████████████████▀▀████▀▀▀▀▀▀▀▀▀▀▀▀¬\n\n"""
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
    tagline = "{}        *ATT&CK for Enterprise v{}\n\n      Cutting through MITRE ATT&CK framework...\n".format(
        chosen_title, attack_version
    )
    time.sleep(2)
    subprocess.Popen(["clear"]).communicate()
    print_saw(saw, tagline, "                                                        ")
    # obtaining framework
    for sheet_tab in sheet_tabs:
        sheet, tab = sheet_tab.split("-")
        filename = "enterprise-attack-v{}-{}.".format(attack_version, sheet)
        spreadsheet = "{}xlsx".format(filename)
        if not os.path.exists(
            "enterprise-attack-v{}/{}".format(attack_version, spreadsheet)
        ):
            mitre_spreadsheet = requests.get(
                "https://attack.mitre.org/docs/enterprise-attack-v{}/{}".format(
                    attack_version, spreadsheet
                )
            )
            with open(spreadsheet, "wb") as spreadsheet_file:
                spreadsheet_file.write(mitre_spreadsheet.content)
        else:
            pass
        temp_csv = "{}temp.csv".format(filename)
        if sheet == "techniques":
            print_saw(
                saw, tagline, "                                                      "
            )
            xlsx_file = pandas.read_excel(spreadsheet, tab)
        elif sheet == "groups":
            xlsx_file = pandas.read_excel(spreadsheet, tab)
        else:
            pass
        xlsx_file.to_csv(temp_csv, index=None, header=True)
        with open(temp_csv) as csv_with_new_lines:
            malformed_csv = str(csv_with_new_lines.readlines())[2:-2]
            malformed_csv = re.sub(r"\\t", r"£\\t£", malformed_csv)
            if "-groups" not in filename:
                print_saw(
                    saw, tagline, "                                                    "
                )
                malformed_csv = re.sub(r"\\n', '(T\d{4})", r"\n\1", malformed_csv)
                malformed_csv = re.sub(
                    r"\\n['\"], ['\"]\\n['\"], ['\"]", r".  ", malformed_csv
                )
                formated_csv = malformed_csv
            else:
                malformed_csv = re.sub(r"\\n', '", r"\n", malformed_csv)
                malformed_csv = re.sub(r"\n\"\\n', \"", r"\"\n", malformed_csv)
                malformed_csv = re.sub(r"\n\"\n", r"\"\n", malformed_csv)
                malformed_csv = re.sub(r"\n( ?[^G])", r"\1", malformed_csv)
                malformed_csv = re.sub(r"\\n', \"", r"\"\n", malformed_csv)
                malformed_csv = re.sub(r"\\n\", '", r"\"\n", malformed_csv)
                formated_csv = malformed_csv.replace('\\"', '"')
                filename = "{}-{}.".format(filename[0:-1], tab.replace(" used", ""))
        with open("{}csv".format(filename), "w") as final_csv:
            final_csv.write(formated_csv)
        os.remove(temp_csv)
    if saw:
        print_saw(saw, tagline, "                                                  ")
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
    platforms = str(operating_platforms)[2:-2].split(",")
    platforms = list(filter(None, platforms))
    print_saw(saw, tagline, "                          ")
    terms = str(search_terms)[2:-2].split(",")
    terms = list(filter(None, terms))
    print_saw(saw, tagline, "                        ")
    groups = str(actor_groups)[2:-2].split(",")
    groups = list(filter(None, groups))
    print_saw(saw, tagline, "                      ")
    additional_terms = []
    associated_threat_actors = []
    techniques_used = []
    all_findings = []
    previous_findings = {}
    query_parameters = []
    print_saw(saw, tagline, "                    ")
    if os.path.exists(
        "{}_OpMITRE-groups-techniques.csv".format(str(datetime.now())[0:10])
    ):
        os.remove("{}_OpMITRE-groups-techniques.csv".format(str(datetime.now())[0:10]))
    else:
        pass
    print_saw(saw, tagline, "                  ")
    time.sleep(0.5)
    print_saw(saw, tagline, "                ")
    print_saw(saw, tagline, "              ")
    # filtering on search terms and threat groups
    for csvfilename in os.listdir("./"):
        if csvfilename.endswith("-groups-groups.csv"):
            for term in terms:
                for group in groups:
                    with open("{}".format(csvfilename), encoding="utf-8") as csv:
                        for eachrow in csv:
                            row_elements = re.findall(
                                r"^([^,]+),([^,]+),([^\n]+),https:\/\/attack\.mitre\.org\/groups\/\1,\d{1,2} ",
                                eachrow.strip(),
                            )
                            if len(row_elements) > 0:
                                _, threat_actor, description = row_elements[0]
                                if (
                                    term == "."
                                    or term in description.replace(" ", "_").lower()
                                    or term in description.replace(" ", "_").upper()
                                ):
                                    if group == "." or group == threat_actor:
                                        if term == ".":
                                            associated_threat_actors.append(
                                                "{}||{}||{}".format(
                                                    threat_actor, description, "*"
                                                )
                                            )
                                        else:
                                            for additional_term in terms:
                                                if additional_term in eachrow:
                                                    additional_terms.append(
                                                        additional_term
                                                    )
                                                else:
                                                    pass
                                            associated_threat_actors.append(
                                                "{}||{}||{}::{}".format(
                                                    threat_actor,
                                                    description,
                                                    term,
                                                    str(additional_terms),
                                                )
                                            )
                                            additional_terms.clear()
                                    else:
                                        pass
                            else:
                                pass
                        else:
                            pass
        else:
            pass
    print_saw(saw, tagline, "            ")
    associated_threat_actors = sorted(list(set(associated_threat_actors)))
    print_saw(saw, tagline, "          ")
    # collecting associated techniques
    for csvfilename in os.listdir("./"):
        if csvfilename.endswith("-groups-techniques.csv"):
            with open("{}".format(csvfilename), encoding="utf-8") as csv:
                for eachrow in csv:
                    row_elements = re.findall(
                        r"^[^,]+,([^,]+),[^,]+,[^,]+,([^,]+),([^,]+),[^,]+,([^\n]+)",
                        eachrow.strip(),
                    )
                    (
                        threat_actor,
                        technique_id,
                        technique_name,
                        threat_actor_method,
                    ) = row_elements[0]
                    if "'{}||".format(threat_actor) in str(
                        associated_threat_actors
                    ):  # check if threat_actor matches entry in associated_threat_actors
                        threat_actor_description = (
                            str(associated_threat_actors)
                            .split("'{}||".format(threat_actor))[1]
                            .split("']', '")[0]
                            .split("||")[0]
                        )
                        if str(associated_threat_actors).split("||")[-1] != "*":
                            actor_searchterms = re.findall(
                                r"(\w+)",
                                str(associated_threat_actors)
                                .split("'{}||".format(threat_actor))[1]
                                .split("']', '")[0]
                                .split("||")[1]
                                .split("', \"")[0]
                                .split("', '")[0],
                            )
                            actor_searchterms = sorted(list(set(actor_searchterms)))
                        else:
                            actor_searchterms = "*"
                        techniques_used.append(
                            "{}||{}||{}||{}||{}||{}".format(
                                technique_id,
                                technique_name,
                                threat_actor,
                                threat_actor_method,
                                threat_actor_description,
                                actor_searchterms,
                            )
                        )
                    else:
                        pass
        else:
            pass
    print_saw(saw, tagline, "        ")
    actor_techniques_used = sorted(list(set(techniques_used)))
    print_saw(saw, tagline, "      ")
    if str(associated_threat_actors).split("||")[-1][0:1] != "*":
        term_insert = "'\033[1;36m{}\033[1;m'...".format(
            str(terms)[2:-2].replace("', '", "\033[1;m', '\033[1;36m")
        )
    else:
        term_insert = "*"
    print_saw(saw, tagline, "    ")
    print_saw(saw, tagline, "  ")
    print_saw(saw, tagline, "partial")
    # extracting all pertentant information
    print_saw(saw, tagline, "-")  # remove saw
    print()
    print(
        "    -> Extracting \033[1;31midentifiers\033[1;m from \033[1;32mtechniques\033[1;m based on \033[1;33mthreat actors\033[1;m associated with {}".format(
            term_insert.replace("_", " ")
        )
    )
    print()
    time.sleep(0.5)
    for csvfilename in os.listdir("./"):
        if "-groups-" not in csvfilename and csvfilename.endswith(".csv"):
            for pairing in actor_techniques_used:
                threat_actor = pairing.split("||")[2]
                actor_terms = pairing.split("||")[-1][2:-2]
                with open("{}".format(csvfilename), encoding="utf-8") as csv:
                    for eachrow in csv:
                        if threat_actor in eachrow.strip():
                            row_elements = re.findall(
                                r"^([^,]+),([^,]+),(.*)[\",]https://attack.mitre.org/techniques/T\d{4}(?:/\d{3})?,\d+ \w+ \d+,\d+ \w+ \d+,[\d\.]+,\"?[A-Za-z ,]+\"?,(.*),\"?(Azure AD|Containers|Google Workspace|IaaS|Linux|Network|Office 365|PRE|SaaS|Windows|macOS),(\"[^\"]+\")[\",]",
                                eachrow.strip(),
                            )
                            if len(row_elements) > 0:
                                (
                                    technique_id,
                                    technique_name,
                                    description,
                                    detection,
                                    platform,
                                    data_sources,
                                ) = row_elements[0]
                                if (
                                    operating_platforms and platform in str(platforms)
                                ) or len(
                                    platforms
                                ) == 0:  # including only requested platforms
                                    if (
                                        ": " in technique_name
                                    ):  # including sub-techniques
                                        technique_findings = extract_indicators(
                                            truncate,
                                            technique_id,
                                            technique_name.split(": ")[0],
                                            threat_actor,
                                            actor_techniques_used,
                                            description,
                                            detection,
                                            data_sources,
                                            actor_terms,
                                            previous_findings,
                                        )
                                        technique_findings = extract_indicators(
                                            truncate,
                                            technique_id,
                                            technique_name.split(": ")[1],
                                            threat_actor,
                                            actor_techniques_used,
                                            description,
                                            detection,
                                            data_sources,
                                            actor_terms,
                                            previous_findings,
                                        )
                                    else:
                                        technique_findings = extract_indicators(
                                            truncate,
                                            technique_id,
                                            technique_name,
                                            threat_actor,
                                            actor_techniques_used,
                                            description,
                                            detection,
                                            data_sources,
                                            actor_terms,
                                            previous_findings,
                                        )
                                    all_findings.append(technique_findings)
                                else:
                                    pass
                            else:
                                pass
                        else:
                            pass
        else:
            pass
    filtered_findings = list(filter(None, all_findings))
    consolidated_techniques = []
    for technique_finding in filtered_findings:
        for every_technique in technique_finding:
            consolidated_techniques.append(every_technique)
    # consolidating results
    with open(
        "{}_OpMITRE-groups-techniques.csv".format(str(datetime.now())[0:10]), "w"
    ) as opmitre_csv:
        opmitre_csv.write(
            "technique_id,technique_name,indicators,indicator_type,threat_actor,threat_actor_method,threat_actor_description,detection\n"
        )
    log_sources = []
    for dataset in consolidated_techniques:
        logsource = (
            dataset.split("||")[-2]
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
            .replace("Cloud Service: Cloud Service Disable", "Cloud API logging")
            .replace("Cloud Service: Cloud Service Enumeration", "Cloud API logging")
            .replace("Cloud Service: Cloud Service Modification", "Cloud API logging")
            .replace("Cloud Storage: Cloud Storage Access", "Cloud API logging")
            .replace("Cloud Storage: Cloud Storage Creation", "Cloud API logging")
            .replace("Cloud Storage: Cloud Storage Deletion", "Cloud API logging")
            .replace("Cloud Storage: Cloud Storage Enumeration", "Cloud API logging")
            .replace("Cloud Storage: Cloud Storage Modification", "Cloud API logging")
            .replace("Drive: Drive Access", "Windows event logs; setupapi.dev.log")
            .replace("Driver: Driver Load", "Sysmon")
            .replace("Command: Command Execution", "Command-line logging")
            .replace("Container: Container Creation", "Command-line logging")
            .replace("Container: Container Enumeration", "Command-line logging")
            .replace("Container: Container Start", "Command-line logging")
            .replace(
                "File: File Access", "Command-line logging; Windows event logs; Sysmon"
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
                "Firewall: Firewall Disable", "Command-line logging; Windows event logs"
            )
            .replace("Firewall: Firewall Enumeration", "Command-line logging")
            .replace(
                "Firewall Rule Modification", "Command-line logging; Windows event logs"
            )
            .replace(
                "Group: Group Enumeration", "Command-line logging; Windows event logs"
            )
            .replace(
                "Group: Group Modification", "Command-line logging; Windows event logs"
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
            .replace("Named Pipe: Named Pipe Metadata", "Command-line logging; Sysmon")
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
                "PowerShell Script Block logging; Command-line logging; Windows event logs; WMI",
            )
            .replace("Service: Service Creation", "Windows event logs; *nix /var/log")
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
                "Windows event logs; *nix /var/log/auth; access/authentication",
            )
            .replace(
                "User Account: User Account Modification",
                "Windows event logs; *nix /var/log/auth; access/authentication",
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
                "WMI",
                "Command-line logging; Microsoft-Windows-WMI-Activity/Trace & WMITracing.log; Sysmon",
            )
            .replace(
                "WMI: WMI Creation",
                "Command-line logging; Microsoft-Windows-WMI-Activity/Trace & WMITracing.log; Sysmon",
            )
        )
        log_sources.append(logsource)
        if dataset.split("||")[8] != "[]" and dataset.split("||")[-2] != "-":
            group_techniques[
                "{}||{}||{}||{}||{}||{}||{}||{}||'{}'||{}".format(
                    dataset.split("||")[0],  # technique id
                    dataset.split("||")[1],  # technique name
                    dataset.split("||")[7],  # technique description
                    dataset.split("||")[6],  # identifer_type
                    logsource,  # log sources
                    dataset.split("||")[2],  # threat actor
                    dataset.split("||")[3],  # threat actor usage
                    dataset.split("||")[4],  # threat actor description
                    dataset.split("||")[5],  # threat actor keyword matches
                    dataset.split("||")[8]
                    .replace("\\\\\\\\", "\\\\")
                    .replace("\\\\£\\\\t£", "\\\\t")
                    .replace("[.]", ".")
                    .replace("[:]", ":")
                    .strip("\\")
                    .lower(),  # indicators
                )
            ] = "-"
            # building queries
            if queries:
                query_parameters.append(
                    "{}||{}".format(
                        dataset.split("||")[8]
                        .replace("\\\\\\\\", "\\\\")
                        .replace("\\\\£\\\\t£", "\\\\t")
                        .replace("[.]", ".")
                        .replace("[:]", ":")
                        .strip("\\"),
                        dataset.split("||")[1],
                    )
                )
            else:
                pass
    for data_entry in group_techniques.keys():
        with open(
            "{}_OpMITRE-groups-techniques.csv".format(str(datetime.now())[0:10]), "a"
        ) as opmitre_csv:
            opmitre_csv.write(
                data_entry.replace("\\\\\\\\", "\\\\")
                .replace("\\\\£\\\\t£", "\\\\t")
                .replace("[.]", ".")
                .replace("[:]", ":")
                .replace("\\n', '", ".. ")
                .replace(". .  ", ". ")
            )
    # creating queries
    if queries:
        query_parameters = list(set(query_parameters))
        if os.path.exists("{}_OpMITRE-queries.conf".format(str(datetime.now())[0:10])):
            os.remove("{}_OpMITRE-queries.conf".format(str(datetime.now())[0:10]))
        else:
            pass
        for query in query_parameters:
            with open(
                "{}_OpMITRE-queries.conf".format(str(datetime.now())[0:10]), "a"
            ) as opmitre_queries:
                andor_query = query.split("||")[0]
                has = "any"
                if " " in query.split("||")[0]:
                    for command_combo in query.split("||")[0].split("', '"):
                        if " " in command_combo and not command_combo.strip(
                            "'"
                        ).lower().startswith("hk"):
                            andor_query = '("{}")'.format(
                                command_combo[2:-2]
                                .strip("'")
                                .replace('"', '\\"')
                                .replace(" ", '" and "')
                                .replace("*", "")
                                .strip('"')
                                .strip("\\")
                            )
                            has = "all"
                        else:
                            pass
                else:
                    pass
                stanza_title = "[{}]\n".format(query.split("||")[1])
                if " and " in andor_query[1:-1]:
                    andor_query = 'where "{}" IN(<field_name>)'.format(
                        andor_query[1:-1].replace(
                            " and ", '" IN(<field_name>) AND where "'
                        )
                    )
                else:
                    andor_query = 'where "{}" IN(<field_name>)'.format(
                        andor_query[1:-1]
                    )
                splunk_query = "{}  // SPL [Splunk]\n".format(andor_query)
                if has == "any":
                    sentinel_query = (
                        '<field_name> has_{}("{}")  // KQL [Sentinel]\n'.format(
                            has, andor_query[2:-2]
                        )
                    )
                else:
                    sentinel_query = (
                        '<field_name> has_{}("{}")  // KQL [Sentinel]\n'.format(
                            has, andor_query.replace(" and ", ", ")
                        )
                    )
                lucene_query = (
                    '<field name>:("{}")  // elastic/kibana [lucene]\n'.format(
                        andor_query[1:-1].replace("', '", '" OR "')
                    )
                )
                kql_query = '<field name>:("{}")  // elastic/kibana [KQL]\n'.format(
                    andor_query[1:-1].replace("', '", '" or "')
                )
                querydsl_query = '{{"query": {{"terms": {{"<field name>": [ "{}" ]}}}}}}  // elastic/kibana [Query DSL]\n\n\n\n'.format(
                    andor_query[1:-1].replace("', '", '", "')
                )
                query = "{}{}{}{}{}{}".format(
                    stanza_title,
                    splunk_query,
                    sentinel_query,
                    lucene_query,
                    kql_query,
                    querydsl_query,
                )
                tidied_query = (
                    query.replace('""', '"')
                    .replace('""', '"')
                    .replace('("("', '("')
                    .replace('")")', '")')
                    .replace("'", '"')
                    .replace('"\\"', '"')
                    .replace('"klm\\', '"hklm\\')
                    .replace('"kcu\\', '"hkcu\\')
                    .replace('"key\\', '"hkey\\')
                )
                opmitre_queries.write(
                    tidied_query.replace('""', '"')
                    .replace('""', '"')
                    .replace('"")', '")')
                )
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
    log_coverage = sorted(counted_log_sources.items(), key=lambda x: x[1], reverse=True)
    print()
    print(
        "\n\n     The following log sources are required to \033[4;37mdetect\033[1;m the aforementioned ATT&CK techniques:"
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
    print("\n\n")


if __name__ == "__main__":
    main()
