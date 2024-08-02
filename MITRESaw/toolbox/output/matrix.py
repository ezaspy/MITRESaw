#!/usr/bin/env python3 -tt
import os
import pandas
import re
from collections import Counter
from MITRESaw.toolbox.tools.map_general_logs import generic_mapping
from MITRESaw.toolbox.tools.map_bespoke_logs import bespoke_mapping


def find_parent_sub_technique(technique, sorted_threat_actors_techniques_in_scope):
    if (
        "||{}||".format(technique)
        in str(sorted_threat_actors_techniques_in_scope)[2:-2]
    ):
        parent_technique = technique
        sub_technique = "-"
    elif (
        "||{}: ".format(technique)
        in str(sorted_threat_actors_techniques_in_scope)[2:-2]
    ):
        parent_technique = technique
        sub_technique = (
            str(sorted_threat_actors_techniques_in_scope)[2:-2]
            .split("{}: ".format(technique))[1]
            .split("', '")[0]
        )
    elif (
        ": {}||".format(technique)
        in str(sorted_threat_actors_techniques_in_scope)[2:-2]
    ):
        parent_technique = (
            str(sorted_threat_actors_techniques_in_scope)[2:-2]
            .split(": {}".format(technique))[0]
            .split("||")[-1]
        )
        sub_technique = technique
    return parent_technique, sub_technique


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
    return f"{group},{technique_id},{technique_name},{technique_desc.replace(",", "%2C")},{platform},{str(log_sources)[2:-2].replace("', '", "; ")},{evidence_type},{str(evidence)[2:-2].replace("', '", "; ")}"


def build_matrix(
    mitresaw_output_directory,
    consolidated_techniques,
    sorted_threat_actors_techniques_in_scope,
    threat_actor_technique_id_name_findings,
):
    (
        threat_actors_xaxis,
        techniques_yaxis,
        threat_actor_techniques,
        markers,
        rows_techniques,
        query_pairings,
        threat_actors_count,
        techniques_count,
        parent_sub_techniques_yaxis,
        parent_sub_counts,
    ) = ([] for _ in range(10))
    with open(
        os.path.join(mitresaw_output_directory, "ThreatActors_Techniques.csv"), "w"
    ) as mitresaw_csv:
        mitresaw_csv.write(
            "group_software_id,group_software_name,technique_id,item_identifier,group_software,relation_identifier,created,last_modified,group_software_description,technique_name,technique_tactics,technique_description,technique_detection,technique_platforms,technique_datasources,evidence_type,evidence_indicators\n"
        )
    mapped_log_sources = []

    # compile intersect
    for dataset in consolidated_techniques:
        threat_actors_xaxis.append(dataset.split("||")[1])
        techniques_yaxis.append(dataset.split("||")[3])
        threat_actor_techniques.append(
            "{}||{}".format(dataset.split("||")[1], dataset.split("||")[3])
        )
    threat_actors = Counter(threat_actors_xaxis)
    threat_actors = sorted(threat_actors.items(), key=lambda x: x[1], reverse=True)
    for threat_actors_pair in threat_actors:
        threat_actors_count.append(list(threat_actors_pair))
    uniq_threat_actors_xaxis = sorted(list(set(threat_actors_xaxis)))
    uniq_techniques_yaxis = sorted(list(set(techniques_yaxis)))
    # uniq_threat_actor_techniques = sorted(list(set(threat_actor_techniques)))
    for each_technique in techniques_yaxis:
        parent_technique, sub_technique = find_parent_sub_technique(
            each_technique, sorted_threat_actors_techniques_in_scope
        )
        parent_sub_techniques_yaxis.append(
            "{}||{}".format(parent_technique, sub_technique)
        )
    techniques_count = Counter(parent_sub_techniques_yaxis)
    techniques_count = sorted(
        techniques_count.items(), key=lambda x: x[1], reverse=True
    )

    # collect potential sub-technique and tactics
    for uniq_technique in uniq_techniques_yaxis:
        parent_technique, sub_technique = find_parent_sub_technique(
            uniq_technique, sorted_threat_actors_techniques_in_scope
        )
        technique_tactics = (
            str(sorted_threat_actors_techniques_in_scope)
            .split("{}||".format(uniq_technique))[1]
            .split("', '")[0]
        )

        # need to identify criteria for what is detectable, non-detectable and out-of-scope
        for threat_actor in uniq_threat_actors_xaxis:
            threat_actor_technique_regex = (
                re.escape(threat_actor)
                + r"\|\|uses\|\|"
                + re.escape(uniq_technique)
                + r"(?:[\.\d]+)?(?:\|\|[^\|]+){7}\|\|(ports|evt|reg|cmd|software|cve|N/A)\|\|([^\|]+)', 'G"
            )
            detectable_threat_actor_technique = re.search(
                threat_actor_technique_regex,
                str(consolidated_techniques),
            )
            if detectable_threat_actor_technique != None:
                if detectable_threat_actor_technique[0].split("||")[-2] == "N/A":
                    marker = "O"
                else:
                    marker = "X"
                    mapping = map_log_sources(detectable_threat_actor_technique[0])
                    mapped_log_sources.append(mapping)
            else:
                marker = "-"
            markers.append(marker)
            if len(markers) == len(uniq_threat_actors_xaxis):
                formatted_technique_row = []
                row_technique = [
                    technique_tactics.replace(",", ";"),
                    parent_technique,
                    sub_technique,
                    str(markers)[2:-2],
                    "{}".format(str(markers)[2:-2].count("X")),
                    "{}".format(str(markers)[2:-2].count("O")),
                    str(len(markers)),
                ]

                # readjusting the count from int->str->int
                if str(row_technique[-2]) != "0" and str(row_technique[-3]) != "0":
                    row_technique = (
                        str(row_technique).replace('"', "'")[2:-2].split("', '")
                    )
                    for element in row_technique[0:-3]:
                        formatted_technique_row.append(element)
                    formatted_technique_row.append(int(row_technique[-3]))
                    formatted_technique_row.append(int(row_technique[-2]))
                    formatted_technique_row.append(int(row_technique[-1]))
                    rows_techniques.append(formatted_technique_row)
        markers.clear()

    # output intersect
    for technique_count in techniques_count:
        parent_sub_count = [
            str(technique_count)[2:-1].split("||")[0],
            str(technique_count)[2:-1].split("||")[1].split("', ")[0],
            int(str(technique_count)[2:-1].split("||")[1].split("', ")[1]),
        ]
        parent_sub_counts.append(list(parent_sub_count))
    column_threat_actors_count = ["Threat Actor", "Count"]
    threat_actor_count_data_frame = pandas.DataFrame(
        threat_actors_count, columns=column_threat_actors_count
    )
    column_techniques_count = ["Technique", "Sub-technique", "Count"]
    techniques_subtechniques_count_data_frame = pandas.DataFrame(
        parent_sub_counts, columns=column_techniques_count
    )
    column_threat_actors = (  # sort count columns by Total, Identifable, Uidentifiable
        ["Tactic", "Parent Technique", "Sub-technique"]
        + uniq_threat_actors_xaxis
        + ["Identifiable"]
        + ["Unidentifiable"]
        + ["Total"]
    )
    intersect_data_frame = pandas.DataFrame(
        rows_techniques, columns=column_threat_actors
    )
    sorted_intersect_data_frame = intersect_data_frame.sort_values(
        [
            "Total",
            "Identifiable",
            "Unidentifiable",
            "Parent Technique",
            "Sub-technique",
        ],
        ascending=[False, False, False, True, True],
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
        sorted_intersect_data_frame.to_excel(
            intersect_writer, sheet_name="DetectableMatrix"
        )
    return query_pairings, mapped_log_sources
