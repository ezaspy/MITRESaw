#!/usr/bin/env python3 -tt
import re
import time


def extract_indicators(
    valid_procedure,
    terms,
    evidence_found,
    identifiers,
    previous_findings,
    truncate,
):
    def finding_to_stdout(
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
        port_identifiers = list(set(port_identifiers))
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
        evt_identifiers = list(set(evt_identifiers))
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
            r"([Hh][Kk](?:[Ll][Mm]|[Cc][Uu]|[Ee][Yy])[^\{\}\|\"'!$<>`]+)",
            description.lower()
            .replace("hkey_local_machine", "hklm")
            .replace("hkey_current_user", "hkcu")
            .replace("[hklm]", "hklm")
            .replace("[hkcu]", "hkcu")
            .replace("hklm]", "hklm")
            .replace("hkcu]", "hkcu")
            .replace("“", '"')
            .replace("”", '"')
            .replace("\\\\\\\\\\\\\\\\", "\\\\\\\\")
            .replace("\\\\\\\\\\\\\\\\", "\\")
            .replace("\\\\\\\\\\\\", "\\")
            .replace("\\\\\\\\", "\\")
            .replace("£\\\\t£", "\\\\t")
            .replace('""', '"')
            .replace("  ", " ")
            .replace("[.]", ".")
            .replace("[:]", ":")
            .replace("&#42;", "*")
            .replace("&lbrace;", "{")
            .replace("&rbrace;", "}")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("[username]", "%username%")
            .replace("\\]\\", "]\\")
            .replace('""', '"')
            .replace('""', '"')
            .strip("\\")
            .strip(),
        )
        registry_identifiers = list(set(reg_identifiers))
        return registry_identifiers

    def extract_cmd_indicators(description):
        terms_identifiers = re.findall(
            r"(?:(?:<code> ?([^\{\}!<>`]{3,}) ?<\/code>)|(?:` ?([^\{\}!<>`]{3,}) ?`)|(?:\[ ?([^\{\}!<>`]{3,}) ?\]\(https:\/\/attack\.mitre\.org\/software))",
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
                    and not each_identifier.lower().startswith("hklm")
                    and not each_identifier.lower().startswith("hkcu")
                    and not each_identifier.lower().startswith("hkey")
                    and not each_identifier.lower().startswith("[hklm")
                    and not each_identifier.lower().startswith("[hkcu")
                    and not each_identifier.lower().startswith("[hkey")
                    and not each_identifier == ", and "
                ):
                    identifier = (
                        each_identifier.lower()
                        .replace("“", '"')
                        .replace("”", '"')
                        .replace("\\\\\\\\\\\\\\\\", "\\\\\\\\")
                        .replace("\\\\\\\\\\\\\\\\", "\\")
                        .replace("\\\\\\\\\\\\", "\\")
                        .replace("\\\\\\\\", "\\")
                        .replace("£\\\\t£", "\\\\t")
                        .replace('""', '"')
                        .replace("  ", " ")
                        .replace("[.]", ".")
                        .replace("[:]", ":")
                        .replace("&#42;", "*")
                        .replace("&lbrace;", "{")
                        .replace("&rbrace;", "}")
                        .replace("&lt;", "<")
                        .replace("&gt;", ">")
                        .replace("[username]", "%username%")
                        .replace("\\]\\", "]\\")
                        .replace('""', '"')
                        .replace('""', '"')
                        .strip("\\")
                        .strip()
                    )
                    if len(identifier) > 1:
                        cmd_identifiers.append(identifier)
                    else:
                        pass
                else:
                    pass
        cmd_identifiers = list(set(cmd_identifiers))
        return cmd_identifiers

    """def extract_cve_indicators(description):
        pass"""

    """def extract_software_indicators(description):
        pass"""

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
            identifiers = finding_to_stdout(
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
            identifiers = finding_to_stdout(
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
            identifiers = finding_to_stdout(
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
            identifiers = finding_to_stdout(
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
    """if "CVE" in description.upper():
        cve_identifiers = extract_cve_indicators(description)
    else:
        cve_identifiers = []"""
    """if "/software/" in description.lower():
        software_identifiers = extract_software_indicators(description)
    else:
        software_identifiers = []"""
    return evidence_found, previous_findings
