#!/usr/bin/env python3 -tt
import os
import re


def collect_files(
    mitresaw_mitre_files,
    groups,
    group_procedures,
    group_descriptions,
    terms,
    additional_terms,
    softwares,
    group_descriptions_software,
):
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
                    for group_procedure_csv_row in groups_procedure.split("\\n',<##>'"):
                        if str(groups) == "['.']":
                            row_elements = re.findall(
                                r"^([^,]+),([^,]+),[^,]+,[^,]+,([^,]+),([^,]+),[^,]+,(.*)",
                                group_procedure_csv_row.strip(),
                            )
                            if len(row_elements) > 0:
                                if row_elements[0][0] != "source ID":
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
                            for group in groups:
                                if (
                                    group in group_procedure_csv_row
                                    and group_procedure_csv_row.startswith("G")
                                ):
                                    row_elements = re.findall(
                                        r"^([^,]+),([^,]+),[^,]+,[^,]+,([^,]+),([^,]+),[^,]+,(.*)",
                                        group_procedure_csv_row.strip(),
                                    )
                                    if len(row_elements) > 0:
                                        if row_elements[0][0] != "source ID":
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
        else:
            pass
    # obtaining group description
    for groupsfile in os.listdir(mitresaw_mitre_files):
        if groupsfile.endswith("-groups-groups.csv"):
            with open(
                "{}".format(os.path.join(mitresaw_mitre_files, groupsfile)),
                encoding="utf-8",
            ) as groupscsv:
                for group_rows in groupscsv:
                    group_rows = re.sub(
                        r"\\n[\"'], [\"'](G\d{4},)",
                        r"\\n',<##>'\1",
                        group_rows,
                    )
                    for group_row in group_rows.split("\\n',<##>'"):
                        group_description_row = re.findall(
                            r"^([^,]+),([^,]+),([^\n]+),https:\/\/attack\.mitre\.org\/groups\/\1,\d{1,2} ",
                            group_row,
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
                                        group_descriptions[
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
                                                group_procedure.split("||")[0]
                                                == group_id
                                                and group_procedure.split("||")[1]
                                                == group_name
                                                and group_id_name
                                                in str(group_procedure)
                                            ):
                                                group_descriptions[
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
    if softwares:
        # obtaining group software
        for groupfile in os.listdir(mitresaw_mitre_files):
            if groupfile.endswith("-groups-associated_software.csv"):
                with open(
                    "{}".format(os.path.join(mitresaw_mitre_files, groupfile)),
                    encoding="utf-8",
                ) as group_software_csv:
                    for group_software_csv_row in group_software_csv:
                        for group_description in group_descriptions:
                            if (
                                group_description.split("||")[0]
                                in group_software_csv_row
                            ):
                                group_id = group_software_csv_row.split(",")[0]
                                group_name = group_software_csv_row.split(",")[1]
                                software_id = group_software_csv_row.split(",")[4]
                                software_name = group_software_csv_row.split(",")[5]
                                group_softwares.append(
                                    "{},{},{},{}".format(
                                        group_id, group_name, software_id, software_name
                                    )
                                )
                            else:
                                pass
            else:
                pass
        group_softwares = list(set(group_softwares))
        # obtaining software techniques
        for softwarefile in os.listdir(mitresaw_mitre_files):
            if softwarefile.endswith("-software-techniques_used.csv"):
                with open(
                    "{}".format(os.path.join(mitresaw_mitre_files, softwarefile)),
                    encoding="utf-8",
                ) as software_techniques_csv:
                    for software_rows in software_techniques_csv:
                        software_rows = re.sub(
                            r"\\n[\"'], [\"'](S\d{4},)",
                            r"\\n',<##>'\1",
                            software_rows,
                        )
                        for software_row in software_rows.split("\\n',<##>'")[1:]:
                            for group_procedure in group_procedures.keys():
                                if (
                                    "{}||{}".format(
                                        software_row.split(",")[4],
                                        software_row.split(",")[5],
                                    )
                                    in group_procedure
                                ):
                                    for group_software in group_softwares:
                                        if (
                                            "{}||{}".format(
                                                group_software.split(",")[0],
                                                group_software.split(",")[1],
                                            )
                                            in group_procedure
                                        ) and (
                                            "{},{}".format(
                                                group_software.split(",")[2],
                                                group_software.split(",")[3],
                                            )
                                            in software_row
                                        ):
                                            software_id = software_row.split(",")[0]
                                            software_name = software_row.split(",")[1]
                                            software_procedure = software_row.split(
                                                ",technique,"
                                            )[1]
                                            group_descriptions_software[
                                                "{}||{}||{}||{}".format(
                                                    group_procedure,
                                                    software_id,
                                                    software_name,
                                                    software_procedure.strip('"'),
                                                )
                                            ] = "-"
                                        else:
                                            pass
            else:
                pass
    else:
        pass
    contextual_information = group_descriptions  # | group_descriptions_software
    return contextual_information
