#!/usr/bin/env python3 -tt
import os
import pandas
import re
from collections import Counter


def chunker(seq, size):
    return (seq[pos:pos + size] for pos in range(0, len(seq), size))


def build_matrix(
    mitresaw_output_directory, mitresaw_mitre_files, consolidated_techniques, techniques_subtechniques_counts
):
    (
        threat_actors_xaxis,
        techniques_yaxis,
        threat_actor_techniques,
        markers,
        rows_techniques,
        query_pairings,
        threat_actors_count,
    ) = ([] for _ in range(7))
    previous_technique_parent = ""
    previous_tactics = ""
    with open(
        os.path.join(mitresaw_output_directory, "ThreatActors_Techniques.csv"), "w"
    ) as opmitre_csv:
        opmitre_csv.write(
            "group_software_id,group_software_name,group_software_description,group_software_link,group_software_searchterms,technique_id,technique_name,groupgroup_software,technique_description,technique_detection,technique_platforms,technique_datasources,evidence_type,evidence_indicators\n"
        )
    # compile intersect
    for dataset in consolidated_techniques:
        threat_actors_xaxis.append(dataset.split("||")[1])
        techniques_yaxis.append(dataset.split("||")[3])
        threat_actor_techniques.append(
            "{}||{}".format(dataset.split("||")[1], dataset.split("||")[3])
        )
    uniq_threat_actors_xaxis = sorted(list(set(threat_actors_xaxis)))
    uniq_techniques_yaxis = sorted(list(set(techniques_yaxis)))
    uniq_threat_actor_techniques = sorted(list(set(threat_actor_techniques)))
    for csvtechnique in os.listdir(mitresaw_mitre_files):
        if csvtechnique.endswith("-techniques-techniques.csv"):
            with open(
                "{}".format(os.path.join(mitresaw_mitre_files, csvtechnique)),
                encoding="utf-8",
            ) as techniquecsv:
                techniques_file_content = techniquecsv.readlines()
    threat_actors = Counter(threat_actors_xaxis)
    threat_actors = sorted(threat_actors.items(), key=lambda x: x[1], reverse=True)
    for threat_actors_pair in threat_actors:
        threat_actors_count.append(list(threat_actors_pair))
    # collect potential sub-technique and tactics
    for uniq_technique in uniq_techniques_yaxis:
        this_technique_parent = list(
            filter(
                None,
                re.findall(
                    r"(?:([^,]+): |,)$",
                    str(techniques_file_content)
                    .split("{},".format(uniq_technique))[0]
                    .split("\\n', '")[-1],
                ),
            )
        )
        technique_tactics = re.findall(
            r",.*?,https:\/\/attack\.mitre\.org\/techniques\/T[\d\.\/]+,[^,]+,[^,]+,\d+\.\d+,\"?((?:Initial\ Access|Execution|Persistence|Privilege\ Escalation|Defense\ Evasion|Credential\ Access|Dicovery|Lateral\ Movement|Collection|Command\ and\ Control|Exfiltration|Impact)(?:(?:, (?:Initial\ Access|Execution|Persistence|Privilege\ Escalation|Defense\ Evasion|Credential\ Access|Dicovery|Lateral\ Movement|Collection|Command\ and\ Control|Exfiltration|Impact))?){0,13})",
            str(techniques_file_content)
            .split("{},".format(uniq_technique))[1]
            .split("\\n', '")[0],
        )
        if len(this_technique_parent) > 0 and len(technique_tactics) > 0:
            sub_technique = uniq_technique
            if (this_technique_parent[0] != previous_technique_parent) and (
                technique_tactics[0] != previous_tactics
            ):
                if technique_tactics[0] != "":
                    parent_technique = this_technique_parent[0]
                    sub_technique = uniq_technique
                else:
                    pass
            else:
                pass
        else:
            parent_technique = uniq_technique
            sub_technique = "-"
        for threat_actor in uniq_threat_actors_xaxis:
            # compiling techniques which have searchable identifiers
            if "{}||{}".format(threat_actor, parent_technique) in str(
                uniq_threat_actor_techniques
            ) or "{}||{}".format(threat_actor, sub_technique) in str(
                uniq_threat_actor_techniques
            ):
                markers.append("x")
            else:
                markers.append("N/A")
            if (len(technique_tactics) > 0) and (
                len(markers) == len(uniq_threat_actors_xaxis)
            ):
                formatted_technique_row = []
                row_technique = [
                    technique_tactics[0].replace(",", ";"),
                    parent_technique,
                    sub_technique,
                    str(markers)[2:-2],
                    str(markers)[2:-2].count("x"),
                ]
                row_technique = re.sub(
                    r"(£, )(\d+)\]$",
                    r"\1£\2£",
                    str(row_technique).replace("'", "£").replace('"', "£"),
                )[2:-1].split("£, £")
                for element in row_technique[0:-1]:
                    formatted_technique_row.append(element)
                formatted_technique_row.append(int(row_technique[-1]))
                rows_techniques.append(formatted_technique_row)
            else:
                pass
        this_technique_parent.clear()
        technique_tactics.clear()
        markers.clear()
    # output intersect
    column_threat_actors_count = ["Threat Actor", "Count"]
    threat_actor_count_data_frame = pandas.DataFrame(
        threat_actors_count, columns=column_threat_actors_count
    )
    column_techniques_subtechniques_counts = ["Technique", "Sub-technique", "Count"]
    techniques_subtechniques_count_data_frame = pandas.DataFrame(
        techniques_subtechniques_counts, columns=column_techniques_subtechniques_counts
    )
    column_threat_actors = (
        ["tactics", "technique", "sub_technique"]
        + uniq_threat_actors_xaxis
        + ["Technique Total"]
    )
    intersect_data_frame = pandas.DataFrame(
        rows_techniques, columns=column_threat_actors
    )
    with pandas.ExcelWriter(
        os.path.join(
            mitresaw_output_directory, "ThreatActors_Techniques_Intersect.xlsx"
        )
    ) as intersect_writer:
        threat_actor_count_data_frame.to_excel(
            intersect_writer, sheet_name="ThreatActorCount"
        )
        techniques_subtechniques_count_data_frame.to_excel(
            intersect_writer, sheet_name="TechniqueCount"
        )
        intersect_data_frame.to_excel(intersect_writer, sheet_name="DetectableMatrix")
    return query_pairings
