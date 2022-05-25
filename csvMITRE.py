#!/usr/bin/env python3 -tt
import argparse
import urllib.request
import json
import re
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument(
    "-v",
    "--verbose",
    help="Show progress",
    action="store_const",
    const=True,
    default=False,
)
args = parser.parse_args()
verbose = args.verbose


def main():
    subprocess.Popen(["clear"])
    json_framework = urllib.request.urlopen(
        "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
    ).read()
    attack_list = []
    attack_dict = {}
    with open("./enterprise-attack.json", "wb") as attack_json:
        attack_json.write(json_framework)
    with open("./enterprise-attack.json") as attack_json:
        json_data = json.load(attack_json)
    with open("./enterprise-attack.csv", "w") as attack_csv:
        attack_csv.write(
            "mitre_id,parent_id,sub_id,name,mitre_description,platform,tactic,created,modified,detection,data_sources,defences_bypassed,threat_actor,software\n"
        )
    for key, value in json_data.items():
        if key == "objects":
            for technique in value:
                for element_key, element_value in technique.items():
                    if element_key == "type" and element_value == "attack-pattern":
                        attack_list.append(technique)
                    else:
                        pass
        else:
            pass
    time.sleep(0.5)
    print()
    for each_attack in attack_list:
        csv_row = ""
        previous = ""
        for each_key, each_value in each_attack.items():
            each_key = each_key.split("x_")[-1]
            if (
                each_key == "name"
                or each_key == "description"
                or each_key == "mitre_platforms"
                or each_key == "kill_chain_phases"
                or each_key == "mitre_is_subtechnique"
                or each_key == "mitre_detection"
                or each_key == "mitre_data_sources"
                or each_key == "mitre_defense_bypassed"
                or each_key == "created"
                or each_key == "modified"
                or each_key == "external_references"
            ):
                attack_dict[each_key] = each_value
        for technique_key, technique_value in attack_dict.items():
            technique_key = technique_key.split("x_")[-1]
            if technique_key == "mitre_platforms":
                for each_platform in technique_value:
                    for technique_key, technique_value in attack_dict.items():
                        technique_key = technique_key.split("x_")[-1]
                        if technique_key == "kill_chain_phases":
                            for each_technique in technique_value:
                                each_technique = (
                                    str(each_technique)[2:-2]
                                    .split(", ")[1]
                                    .split("': '")[1]
                                    .replace("-", " ")
                                    .title()
                                )
                                for (
                                    technique_key,
                                    technique_value,
                                ) in attack_dict.items():
                                    technique_key = technique_key.split("x_")[-1]
                                    if technique_key == "name":
                                        csv_row = technique_value + ","
                                    else:
                                        pass
                                for (
                                    technique_key,
                                    technique_value,
                                ) in attack_dict.items():
                                    technique_key = technique_key.split("x_")[-1]
                                    if technique_key == "description":
                                        csv_row = (
                                            csv_row
                                            + technique_value.replace(
                                                "\\n", ""
                                            ).replace(",", "")
                                            + ","
                                        )
                                    else:
                                        pass
                                csv_row = (
                                    csv_row + each_platform + "," + each_technique + ","
                                )
                                for (
                                    technique_key,
                                    technique_value,
                                ) in attack_dict.items():
                                    technique_key = technique_key.split("x_")[-1]
                                    if technique_key == "created":
                                        csv_row = csv_row + str(technique_value) + ","
                                    else:
                                        pass
                                for (
                                    technique_key,
                                    technique_value,
                                ) in attack_dict.items():
                                    technique_key = technique_key.split("x_")[-1]
                                    if technique_key == "modified":
                                        csv_row = csv_row + str(technique_value) + ","
                                    else:
                                        pass
                                for (
                                    technique_key,
                                    technique_value,
                                ) in attack_dict.items():
                                    technique_key = technique_key.split("x_")[-1]
                                    if "mitre_detection" in str(attack_dict):
                                        if technique_key == "mitre_detection":
                                            technique_value = re.sub(
                                                r"\(Citation: [^\)]+\)",
                                                r"",
                                                technique_value.replace("\\n\\n", ". "),
                                            )
                                            technique_value = (
                                                technique_value.replace("\\n\\n", ". ")
                                                .replace("\\n", "")
                                                .replace(", ", "; ")
                                                .replace(",", ";")
                                                .replace(" * ", " ")
                                                .replace("* ", "; ")
                                                .replace(". . ", ". ")
                                                .replace(".. ", ". ")
                                                .replace(".  ", ". ")
                                                .replace("\\", "\\\\")
                                            )
                                            csv_row = (
                                                csv_row + str(technique_value) + ","
                                            )
                                        else:
                                            pass
                                    else:
                                        csv_row = csv_row + "-,"
                                for (
                                    technique_key,
                                    technique_value,
                                ) in attack_dict.items():
                                    technique_key = technique_key.split("x_")[-1]
                                    if "mitre_data_sources" in str(attack_dict):
                                        if technique_key == "mitre_data_sources":
                                            if len(technique_value) > 0:
                                                technique_value = str(technique_value)[
                                                    2:-2
                                                ].replace("', '", "; ")
                                                csv_row = (
                                                    csv_row
                                                    + str(technique_value).replace(
                                                        ",", ";"
                                                    )
                                                    + ","
                                                )
                                            else:
                                                csv_row = csv_row + "-,"
                                        else:
                                            pass
                                    else:
                                        csv_row = csv_row + "-,"
                                for (
                                    technique_key,
                                    technique_value,
                                ) in attack_dict.items():
                                    technique_key = technique_key.split("x_")[-1]
                                    if "mitre_defense_bypassed" in str(attack_dict):
                                        if technique_key == "mitre_defense_bypassed":
                                            if len(technique_value) > 0:
                                                technique_value = str(technique_value)[
                                                    2:-2
                                                ].replace("', '", "; ")
                                                csv_row = (
                                                    csv_row + str(technique_value) + ","
                                                )
                                            else:
                                                csv_row = csv_row + "-,"
                                        else:
                                            pass
                                    else:
                                        csv_row = csv_row + "-,"
                                for (
                                    technique_key,
                                    technique_value,
                                ) in attack_dict.items():
                                    technique_key = technique_key.split("x_")[-1]
                                    if technique_key == "external_references":
                                        if len(technique_value) > 0:
                                            for every_ref in technique_value:
                                                for (
                                                    ref_key,
                                                    ref_value,
                                                ) in every_ref.items():
                                                    if (
                                                        ref_key == "external_id"
                                                        and ref_value.startswith("T")
                                                    ):
                                                        if "." in ref_value:
                                                            csv_row = (
                                                                ref_value
                                                                + ","
                                                                + ref_value.split(".")[
                                                                    0
                                                                ]
                                                                + ","
                                                                + ref_value.split(".")[
                                                                    1
                                                                ]
                                                                + ","
                                                                + csv_row
                                                                + ","
                                                            )
                                                        else:
                                                            csv_row = (
                                                                ref_value
                                                                + ","
                                                                + ref_value
                                                                + ",-,"
                                                                + csv_row
                                                                + ","
                                                            )
                                                    else:
                                                        pass
                                        else:
                                            csv_row = csv_row + "-,"
                                    else:
                                        pass
                                if (
                                    "**This technique has been deprecated"
                                    not in csv_row
                                ):
                                    technique_page = str(
                                        urllib.request.urlopen(
                                            "https://attack.mitre.org/techniques/{}/".format(
                                                csv_row.split(",")[0].replace(".", "/")
                                            )
                                        ).read()
                                    )[2:-1]
                                    if "Procedure Examples" in technique_page:
                                        software = []
                                        groups = []
                                        examples = re.findall(
                                            r"Procedure Examples.*?(<)(table)(.*?)\1\/\2",
                                            technique_page,
                                        )[0][2]
                                        for each_example in examples.split("\\n"):
                                            if (
                                                "/software/S" in each_example
                                                or "/group/G" in each_example
                                                or "/groups/G" in each_example
                                            ) and each_example.strip().startswith(
                                                "<p>"
                                            ):
                                                details = re.findall(
                                                    r"<p>(.*<a href=\"\/(\w+)\/(\w+)\">([^<]+).*)",
                                                    each_example.strip(),
                                                )[0]
                                                sw_group = details[1]
                                                if sw_group == "software":
                                                    software.append(details[3])
                                                elif (
                                                    sw_group == "group"
                                                    or sw_group == "groups"
                                                ):
                                                    groups.append(details[3])
                                                else:
                                                    pass
                                            else:
                                                pass
                                    else:
                                        csv_row = csv_row + "-,-"
                                    if len(groups) > 0 or len(software) > 0:
                                        if len(groups) > 0:
                                            csv_row = (
                                                csv_row
                                                + str(groups)[2:-2].replace(
                                                    "', '", "; "
                                                )
                                                + ","
                                            )
                                        else:
                                            csv_row = csv_row + "-,"
                                        if len(software) > 0:
                                            csv_row = csv_row + str(software)[
                                                2:-2
                                            ].replace("', '", "; ")
                                        else:
                                            csv_row = csv_row + "-"
                                    else:
                                        pass
                                    if verbose:
                                        id_name = (
                                            csv_row.split(",")[0]
                                            + " - "
                                            + csv_row.split(",")[3]
                                        )
                                        if previous != id_name:
                                            print(
                                                " [+] Collected technique '{}'\n".format(
                                                    id_name
                                                )
                                            )
                                        else:
                                            pass
                                        previous = id_name
                                    else:
                                        pass
                                    final_csv_row = (
                                        csv_row.replace("--", "-")
                                        .replace(",,-", ",-")
                                        .replace(",,", ",")
                                        .strip(",")
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)\-([^,]+,[^,]+)$",
                                        r"\1\2",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+)$",
                                        r"\1,-,-",
                                        final_csv_row,
                                    )
                                    final_csv_row = re.sub(
                                        r"^([^,]+,[^,]+),\-",
                                        r"\1,000",
                                        final_csv_row,
                                    )
                                    final_csv_row = final_csv_row.replace(",; ", ",")
                                    with open(
                                        "./enterprise-attack.csv", "a"
                                    ) as attack_csv:
                                        attack_csv.write(
                                            final_csv_row.replace("\n", " ") + "\n"
                                        )
                                else:
                                    pass
                        else:
                            pass
            else:
                pass
        attack_dict.clear()


if __name__ == "__main__":
    main()
