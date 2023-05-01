#!/usr/bin/env python3 -tt
# offer arg for string searching in ta descriptions - produce attack-nav.json
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument(
    "-j",
    "--json",
    help="Keep MITRE ATT&CK json file",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-n",
    "--makeNav",
    nargs=1,
    help="Make ATT&CK Navigator json file based on provided string list e.g. finance,europe,SWIFT",
)
parser.add_argument(
    "-s",
    "--silent",
    help="Show no output",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-t",
    "--splitbyTA",
    help="Split by Threat Actor; expand each row by each associated Threat Actor.",
    action="store_const",
    const=True,
    default=False,
)

args = parser.parse_args()
json_file = args.json
makeNav = args.makeNav
silent = args.silent
splitbyTA = args.splitbyTA


def write_to_csv(csv_file, temp_csv_row):
    with open(
        csv_file, "a"
    ) as attack_csv:
        attack_csv.write(temp_csv_row)


def main():
    attack_list = []
    attack_dict = {}
    csv_row = ""
    previous = ""
    subprocess.Popen(["clear"])
    time.sleep(0.2)
    print("\n       Retrieving enterprise-attack.json...")
    try:
        json_framework = urllib.request.urlopen(
            "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        ).read()
    except:
        print("\n        Unable to retrieve MITRE Enterprise ATT&CK json.\n         Are you connected to the Internet?\n\n")
        sys.exit()
    subprocess.Popen(["clear"])
    time.sleep(0.2)
    if not silent:
        print(
            """
                        ______  __________________________________
    ________________   ____   |/  /___  _/__  __/__  __ \__  ____/
    _  ___/_  ___/_ | / /_  /|_/ / __  / __  /  __  /_/ /_  __/   
    / /__ _(__  )__ |/ /_  /  / / __/ /  _  /   _  _, _/_  /___   
    \___/ /____/ _____/ /_/  /_/  /___/  /_/    /_/ |_| /_____/ *ATT&CK v13
    """
        )
    else:
        print("\n\t🤫 *sssshhhhhh running in silent mode...*\n")
    if os.path.exists("./.enterprise-attack.json"):
        os.remove("./.enterprise-attack.json")
    else:
        pass
    with open("./.enterprise-attack.json", "wb") as attack_json:
        attack_json.write(json_framework)
    with open("./.enterprise-attack.json","rb") as json_blob:
        chunk = 0
        while chunk != b"":
            chunk = json_blob.read(1024)
            hashlib.sha256().update(chunk)
        json_hash = hashlib.sha256().hexdigest()
    if not json_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        print("\n        MITRE Enterprise ATT&CK json file has failed validation checks.\n         The file is likely incomplete and/or corrupted.\n         Please try again.\n\n")
        sys.exit()
    else:
        pass
    with open("./.enterprise-attack.json") as attack_json:
        json_data = json.load(attack_json)
    with open("./.enterprise-attack.csv", "w") as attack_csv:
        if not splitbyTA:
            headers = "mitre_id,parent_id,sub_id,name,mitre_description,platform,tactic,created,modified,detection,data_sources,defences_bypassed,threat_actor,software\n"
        else:
            headers = "mitre_id,parent_id,sub_id,name,mitre_description,platform,tactic,created,modified,detection,data_sources,defences_bypassed,threat_actor,threat_actor_associated,threat_actor_description,software\n"
            threat_groups = []
            groups_page = str(
                urllib.request.urlopen(
                    "https://attack.mitre.org/groups/".format(
                        csv_row.split(",")[0].replace(".", "/")
                    )
                ).read()
            )[2:-1].replace("\\n","§")
            raw_groups = re.findall("<a href=\"/groups/G\d+\">([^<]+)</a>§[^§]+§[^§]+§\s+([^§]+)§[^§]+§[^§]+§\s+<p><a href=\"/groups/G\d+\">([^<]+)</a>([^§]+)</p>§", groups_page)
            for each_ta_set in str(raw_groups)[3:-3].split("'), ('"):
                ta_set = re.sub(r"^([^']+', '[^']+', '[^']+', '[^']+)$", r"\1", re.sub(r"/(?:software|groups|campaigns)/(?:S|G|C)\d{4}\">", r"", re.sub(r"<a href=\"https://attack\.mitre\.org", r"", each_ta_set.replace("</a>", "").replace("</p><p>", " ").replace("\\\\\\'", "'").replace("<a href=\"", ""))))
                threat_actor_set = "{}||{}||{}{}".format(ta_set.split("', '")[2], re.sub(r"^ $", r"-", ta_set.split("', '")[1].replace(";"," - ").replace(",",";")), ta_set.split("', '")[2], ta_set.split("', '")[3].replace(";"," - ").replace(",",";"))
                threat_groups.append(threat_actor_set)
            threat_groups = list(set(threat_groups))
        attack_csv.write(headers)
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
    time.sleep(0.2)
    print()
    for each_attack in attack_list:
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
                                    try:
                                        technique_page = str( # check here for legacy IDs against technique name e.g. Spearphishing Link - T1566 (new); T1192 (old)
                                            urllib.request.urlopen(
                                                "https://attack.mitre.org/techniques/{}/".format(
                                                    csv_row.split(",")[0].replace(".", "/")
                                                )
                                            ).read()
                                        )[2:-1]
                                        if "<!DOCTYPE html>" in technique_page and csv_row.split(",")[0].replace(".", "/") in technique_page:
                                            error = 0
                                        else:
                                            error = 1
                                    except urllib.error.HTTPError as e:
                                        if "404" in e:
                                            error = "404"
                                        else:
                                            error = "0"
                                    if error == 0:
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
                                                groups = list(set(groups))
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
                                                software = list(set(software))
                                                csv_row = csv_row + str(software)[
                                                    2:-2
                                                ].replace("', '", "; ")
                                            else:
                                                csv_row = csv_row + "-"
                                        else:
                                            pass
                                        if not silent:
                                            id_name = (
                                                csv_row.split(",")[0]
                                                + " - "
                                                + csv_row.split(",")[3]
                                            )
                                            if previous != id_name:
                                                print(
                                                    "      -> Collected technique '{}'\n".format(
                                                        id_name
                                                    )
                                                )
                                            else:
                                                pass
                                            previous = id_name
                                        else:
                                            pass
                                        if True:
                                            temp_csv_row = (
                                                csv_row.replace("--", "-")
                                                .replace(",,-", ",-")
                                                .replace(",,", ",")
                                                .strip(",")
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[temp_csv_row[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)\-([^,]+,[^,]+)$",
                                                r"\1\2",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+)$",
                                                r"\1,-,-",
                                                temp_csv_row,
                                            )
                                            temp_csv_row = re.sub(
                                                r"^([^,]+,[^,]+),\-",
                                                r"\1,000",
                                                temp_csv_row,
                                            )
                                        temp_csv_row = temp_csv_row.replace(",; ", ",").replace(". ,", ".,").replace("’", "'").replace("    ", " ").replace("   ", " ").replace("  ", " ")
                                        temp_csv_row = re.sub(r"\s\.\s", r"\. ", re.sub(r"\s{2,}", r" ", temp_csv_row.replace("\n", " ")) + "\n")
                                        temp_csv_row = temp_csv_row.replace("\", '","; ").replace("', \"","; ")
                                        if splitbyTA:
                                            row_with_TAs = re.findall(r"^(T\d{4}(?:[\.\d]+)?,?(?:[^,]+,){11})([^,]+),([^,]+\n)$", temp_csv_row)
                                            if len(row_with_TAs) > 0: # if more than one TA associated with the technique
                                                final_row_start = re.findall(r"^((?:[^,]+,){12})", temp_csv_row)[0]
                                                ta_insert = "-,-,-" # default insert
                                                final_row_end = re.findall(r"(?:,[^,]+)$", temp_csv_row)[0]
                                                for eachTA_from_csvrow in sorted(row_with_TAs[0][1].split("; ")): # cycle through TAs
                                                    if eachTA_from_csvrow != "-":
                                                        eachTA_from_csvrow = eachTA_from_csvrow.strip("-")
                                                        for each_group in threat_groups:
                                                            if each_group.split("||")[0] == eachTA_from_csvrow:
                                                                ta_insert = each_group.replace("|| ||",",-,").replace("||",",")
                                                                temp_csv_row = "{}{}{}".format(final_row_start, ta_insert, final_row_end)
                                                                write_to_csv("./.enterprise-attack.csv", temp_csv_row)
                                                            else:
                                                                pass
                                                    else:
                                                        temp_csv_row = "{}{}{}".format(final_row_start, ta_insert, final_row_end)
                                                        write_to_csv("./.enterprise-attack.csv", temp_csv_row)
                                            else:
                                                temp_csv_row = "{}{}{}".format(temp_csv_row, ta_insert, ",-")
                                                write_to_csv("./.enterprise-attack.csv", temp_csv_row)
                                        else:
                                            write_to_csv("./.enterprise-attack.csv", temp_csv_row)
                                    else:
                                        pass
                                else:
                                    pass
                        else:
                            pass
            else:
                pass
        attack_dict.clear()
    time.sleep(0.5)
    with open("./.enterprise-attack.csv") as hidden_csv: # tidying rows up
        with open("./enterprise-attack.csv", "w") as final_csv:
            final_csv.write(headers)
        for eachrow in hidden_csv:
            if "mitre_id,parent_id,sub_id,name" not in eachrow:
                if splitbyTA and "threat_actor_associated" in hidden_csv.readline(): # with additional threat actor information
                    if "mitre_id,parent_id,sub_id,name" not in eachrow:
                        malformed_row = re.findall(r"^(?:[^,]+,){16,}", eachrow)
                        if len(malformed_row) > 0:
                            final_csv_row = "{}\n".format(re.sub(r"^=-(T\d{4})", r"\1", ",".join(malformed_row[0].split(",")[4::])))
                        else:
                            final_csv_row = eachrow
                        write_to_csv("./enterprise-attack.csv", final_csv_row)
                    else:
                        pass
                else: # without additional threat actor information
                    malformed_row = re.findall(r"(,-,=?-[A-Za-z0-9][^,]+,[^,]+)$", eachrow)
                    if len(malformed_row) > 0:
                        final_csv_row = "{}\n".format(re.sub(r"(,)-,=?-([A-Za-z0-9][^,]+,[^,]+)$", r"\1\2", eachrow))
                    else:
                        final_csv_row = eachrow
                    write_to_csv("./enterprise-attack.csv", final_csv_row)
            else:
                pass
    if makeNav:
        print()
    else:
        pass
    if os.path.exists("./.enterprise-attack.json"):
        if not json_file:
            os.remove("./.enterprise-attack.json")
        else:
            os.rename("./.enterprise-attack.json", "./enterprise-attack.json")
    else:
        pass
    if os.path.exists("./..enterprise-attack.csv"):
        os.remove("./..enterprise-attack.csv")
    if os.path.exists("./.enterprise-attack.csv"):
        os.remove("./.enterprise-attack.csv")


if __name__ == "__main__":
    main()
