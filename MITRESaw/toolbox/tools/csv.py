import re
import os
from MITRESaw.toolbox.tools.logs import generic_mapping
from MITRESaw.toolbox.mapping import bespoke_mapping


def map_log_sources(detectable_threat_actor_technique):
    log_sources = []
    group = detectable_threat_actor_technique.split("||")[0]
    technique_id = detectable_threat_actor_technique.split("||")[2]
    technique_name = detectable_threat_actor_technique.split("||")[6].split(",")[0]
    technique_desc = detectable_threat_actor_technique.split("||")[7]
    platform = detectable_threat_actor_technique.split("||")[8]
    evidence_type = detectable_threat_actor_technique.split("||")[10]
    evidence = (
        detectable_threat_actor_technique.split("||")[11]
        .replace("', 'G", "")
        .replace("\\'", "'")
        .replace("\\\\\\\\", "\\\\")
    )
    # mapping to identifiable evidence according to https://attack.mitre.org/datasources/
    logsources = generic_mapping(
        technique_id,
        platform,
        detectable_threat_actor_technique.split("||")[9],
        evidence_type,
    )
    for logsource in logsources[1:-1].split(", "):
        log_sources.append(logsource)
    # mapping to specific log sources available within Company X
    log_sources = bespoke_mapping(
        technique_id,
        platform,
        sorted(
            list(
                set(
                    str(list(set(log_sources)))[2:-2]
                    .replace("; ", "', '")
                    .split("', '")
                )
            )
        ),
        evidence_type,
    )
    return (
        group,
        technique_id,
        technique_name,
        technique_desc,
        platform,
        log_sources,
        evidence_type,
        evidence,
    )


def write_csv_log_source_mapping(
    detectable_threat_actor_technique,
):
    (
        group,
        technique_id,
        technique_name,
        technique_desc,
        platform,
        log_sources,
        evidence_type,
        evidence,
    ) = map_log_sources(detectable_threat_actor_technique)
    import subprocess, time

    subprocess.Popen(["clear"])
    time.sleep(2)
    print("\n\n\n\n")
    print(group)
    print(technique_id)
    print(technique_name)
    print(platform)
    print(log_sources)
    print(evidence_type)
    print(evidence)
    print("\n\n\n\n")
    time.sleep(3000)


def write_csv_summary(
    consolidated_techniques,
    mitresaw_output_directory,
    mitre_files,
    queries,
    query_pairings,
    log_sources,
):
    for dataset in consolidated_techniques:
        """print(dataset)
        import time

        time.sleep(3000)"""
        with open(
            os.path.join(mitresaw_output_directory, "ThreatActors_Techniques.csv"),
            "a",
        ) as opmitre_csv:
            csv_line = "{}\n".format(
                re.sub(
                    r'( \d{4})\\\\n(,")',
                    r"\1\2",
                    re.sub(
                        r"\('', ('\d+')\)",
                        r"\1",
                        dataset.replace(",||,", ",")
                        .replace("||", ",")
                        .replace(" \\\\n\\', \\'", "")
                        .replace("\\\\\\'", "'")
                        .replace("\\\\n\\', \\'", "\\n")
                        .replace("\\\\n\", \\'", "\\n")
                        .replace("..  ", ". "),
                    ),
                )
            )
            # replacing commas in field values (group_desc) with URL encoded syntax of %2C
            counter = 0
            while counter < 50:
                csv_line = re.sub(
                    r"^((?:[^,]+,){6}.*,relationship--[^,]+,\d{2} [A-Za-z]{3,20} \d{4},\d{2} [A-Za-z]{3,20} \d{4}[^\[]+[^\(]+\([^\)]+\)[^,]+), ",
                    r"\1%2C ",
                    csv_line,
                )
                counter += 1
            csv_line = re.sub(
                r"^((?:[^,]+,){6}.*,relationship--[^,]+,\d{2} [A-Za-z]{3,20} \d{4},\d{2} [A-Za-z]{3,20} \d{4},[^,]+,)\.\[\]'?,",
                r"\1",
                csv_line,
            )
            # replacing commas in field values (technique_desc) with URL encoded syntax of %2C
            counter = 0
            while counter < 50:
                csv_line = re.sub(
                    r"^((?:[^,]+,){6}.*,relationship--[^,]+,\d{2} [A-Za-z]{3,20} \d{4},\d{2} [A-Za-z]{3,20} \d{4},[^,]+,[^,]+,[^,]+), ",
                    r"\1%2C ",
                    csv_line,
                )
                counter += 1
            csv_line = (
                csv_line.replace("uses,", "")
                .replace("\\\\\\\\", "\\\\")
                .replace("\\\\'s", "'s")
            )
            if csv_line.endswith("'"):
                csv_line = "{}]".format(csv_line)
            # resolving issue where multiple lines become merged
            if ".[]': '-'" in csv_line:
                csv_line = re.sub(
                    r"(,\.\[\][\"']: '-', \")", r",-,-,-,-,-,-,-\n", csv_line
                )
                csv_line = csv_line.replace(",-,-,-,-,-,-,-", ",-,-,-,-,-,-").replace(
                    ',.[]",', ","
                )
                # replacing commas in field values (technique_desc) with URL encoded syntax of %2C
                counter = 0
                while counter < 50:
                    csv_line = re.sub(
                        r"((?:[^,]+,){5}.*,relationship--[^,]+,\d{2} [A-Za-z]{3,20} \d{4},\d{2} [A-Za-z]{3,20} \d{4}[^\[]+[^\(]+\([^\)]+\)[^,]+,[^,]+,[^,]+), ",
                        r"\1%2C ",
                        csv_line,
                    )
                    counter += 1
                csv_line = re.sub(r"\(Citation:[^\)]+\)", r"", csv_line)
                csv_lines = csv_line.replace(".. ", ". ").replace(",,", ",")
                for csv_line in csv_lines.split("\n"):
                    if ",-,-,-,-,-" in csv_line:
                        for csvtechnique in os.listdir(mitre_files):
                            if csvtechnique.endswith("techniques-techniques.csv"):
                                with open(
                                    "{}".format(
                                        os.path.join(mitre_files, csvtechnique)
                                    ),
                                    encoding="utf-8",
                                ) as techniquecsv:
                                    techniques_file_content = techniquecsv.readlines()
                                    for line in techniques_file_content:
                                        if line.startswith(
                                            "{},".format(csv_line.split(",")[2])
                                        ):
                                            missing_fields = re.findall(
                                                r"^T[\d\.\/]+,attack-pattern--[^,]+,([^,]+),(.*?),https:\/\/attack\.mitre\.org\/techniques\/T[\d\.\/]+,[^,]+,[^,]+,[^,]+,\d+\.\d+,\"?((?:Reconnaissance|Resource Development|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact)(?:, (?:Reconnaissance|Resource Development|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact)){0,6})\"?,(\"?.*\"?),(\"?(?:Azure AD|Containers|Google Workspace|IaaS|Linux|Network|Office 365|PRE|SaaS|Windows|macOS)(?:(?:, (?:Azure AD|Containers|Google Workspace|IaaS|Linux|Network|Office 365|PRE|SaaS|Windows|macOS))?){0,10}\"?),(\"?[^\"]+\"?),",
                                                line,
                                            )[0]
                                            technique_name = missing_fields[0]
                                            technique_description = missing_fields[
                                                1
                                            ].replace(",", "%2C")
                                            technique_tactics = missing_fields[2]
                                            technique_detection = missing_fields[
                                                3
                                            ].replace(",", "%2C")
                                            technique_platforms = missing_fields[4]
                                            technique_datasources = missing_fields[5]
                                            csv_line = (
                                                "{},{},{},{},{},{},{},N/A,[]\n".format(
                                                    csv_line.replace(",-,-,-,-,-", ""),
                                                    technique_name,
                                                    technique_tactics,
                                                    technique_description,
                                                    technique_detection,
                                                    technique_platforms,
                                                    technique_datasources,
                                                )
                                            )
                                            opmitre_csv.write(
                                                csv_line.replace(", ", "%2C ")
                                                .replace("£\\\\t£", "")
                                                .replace(",technique,", ",")
                                            )
            else:
                for csvtechnique in os.listdir(mitre_files):
                    if csvtechnique.endswith("techniques-techniques.csv"):
                        with open(
                            "{}".format(os.path.join(mitre_files, csvtechnique)),
                            encoding="utf-8",
                        ) as techniquecsv:
                            techniques_file_content = techniquecsv.readlines()
                            for line in techniques_file_content:
                                if line.startswith(
                                    "{},".format(csv_line.split(",")[2])
                                ):
                                    missing_fields = re.findall(
                                        r"^T[\d\.\/]+,attack-pattern--[^,]+,([^,]+),.*?,https:\/\/attack\.mitre\.org\/techniques\/T[\d\.\/]+,[^,]+,[^,]+,[^,]+,\d+\.\d+,\"?((?:Reconnaissance|Resource Development|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact)(?:, (?:Reconnaissance|Resource Development|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact)){0,6})\"?,\"?.*\"?,\"?((?:Azure AD|Containers|Google Workspace|IaaS|Linux|Network|Office 365|PRE|SaaS|Windows|macOS)(?:(?:, (?:Azure AD|Containers|Google Workspace|IaaS|Linux|Network|Office 365|PRE|SaaS|Windows|macOS))?){0,10})\"?,\"?[^\"]+\"?,",
                                        line,
                                    )[0]
                                    technique_name = missing_fields[0]
                                    technique_tactics = missing_fields[1]
                                    technique_platforms = missing_fields[2]
                                    # splitting on technique name to insert the respective tactic
                                    extracted_parts = csv_line.split(
                                        ",{},".format((technique_name))
                                    )
                                    csv_line = "{},{},{},{}".format(
                                        extracted_parts[0],
                                        technique_name,
                                        technique_tactics,
                                        extracted_parts[1],
                                    )
                                    opmitre_csv.write(
                                        csv_line.replace(", ", "%2C ")
                                        .replace("£\\\\t£", "")
                                        .replace(",technique,", ",")
                                    )
            if queries:
                technique_id = dataset.split("||")[2]
                technique_name = dataset.split("||")[3]
                parameters = dataset.split("||")[-1].replace("\\\\\\\\", "\\\\").lower()
                query_pairings.append(
                    "{}||{}||{}".format(technique_id, technique_name, parameters)
                )
        logsource = generic_mapping(
            dataset.split("||")[3],
            technique_platforms,
            dataset.split("||")[-3],
            dataset.split("||")[-2],
        )
        log_sources.append(logsource.replace(", , ", ", "))
