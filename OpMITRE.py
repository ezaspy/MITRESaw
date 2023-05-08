#!/usr/bin/env python3 -tt
import argparse
import hashlib
import json
import os
import re
import requests
import shutil
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
    "--make_nav",
    nargs=1,
    help="Make ATT&CK Navigator json file based on provided string list e.g. mining,technology,defense,law",
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
nav_terms = args.make_nav
silent = args.silent
splitbyTA = args.splitbyTA


def write_to_csv(csv_file, csv_row):
    with open(
        csv_file, "a"
    ) as attack_csv:
        attack_csv.write(csv_row)


def clean_csv_rows():
    with open("./.malformed_ea0.csv") as attack_csv:
        with open("./.malformed_ea1.csv", "a") as malformed_ea1:
            for csv_row in attack_csv:
                malformed_ea0_0 = re.findall(r"^(?:-+,){3}-(T\d{4}(?:[\.\d]+)?,?(?:[^,]+,){11}-,-,)[^,]+\n$", csv_row)
                if len(malformed_ea0_0) > 0:
                    malformed_ea1.write("{}-,-\n".format(malformed_ea0_0[0]))
                malformed_ea0_1 = re.findall(r"^(?:[^,]+,){3}-(T\d{4}(?:[\.\d]+)?,?(?:[^,]+,){11}(?:[^,]+,){3}[^,]+,[^,]+)", csv_row)
                if len(malformed_ea0_1) > 0:
                    malformed_ea1.write(malformed_ea0_1[0])
                malformed_ea0_2 = re.findall(r"^(?:[^,]+,){3}-(T\d{4}(?:[\.\d]+)?,?(?:[^,]+,){11}(?:[^,]+,){3}[^,-]+\n)$", csv_row)
                if len(malformed_ea0_2) > 0:
                    malformed_ea0_3 = re.findall(r"^(T\d{4}(?:[\.\d]+)?,?(?:[^,]+,){11}-,-)(?:[^,]+,)[^,]+\n$", malformed_ea0_2[0])
                    if len(malformed_ea0_3) > 0:
                        malformed_ea1.write("{},-,-\n".format(malformed_ea0_3[0]))
                    else:
                        malformed_ea1.write(malformed_ea0_2[0])
                malformed_ea0_4 = re.findall(r"^(T\d{4}(?:[\.\d]+)?,?(?:[^,]+,){9}[^,]+,[^,]+,)-,-([^,]+,[^,]+)", csv_row)
                if len(malformed_ea0_4) > 0:
                    malformed_ea1.write("{}-,-,-,-\n".format(malformed_ea0_4[0][0]))
                malformed_ea0_5 = re.findall(r"^(T\d{4}(?:[\.\d]+)?,?(?:[^,]+,){12})-([^,]+,[^,]+)", csv_row)
                if len(malformed_ea0_5) > 0:
                    malformed_ea1.write("{}-,-,-\n".format(malformed_ea0_5[0][0]))
                malformed_ea0_6 = re.findall(r"^(?:[^,]+,){3}-(T\d{4}(?:[\.\d]+)?,?(?:[^,]+,){11}[^,]+,)-[^,]+,[^,]+\n$", csv_row)
                if len(malformed_ea0_6) > 0:
                    malformed_ea1.write("{}-,-,-\n".format(malformed_ea0_6[0]))
                malformed_ea0_7 = re.findall(r"^(?:[^,]+,){3}-(T\d{4}(?:[\.\d]+)?,?(?:[^,]+,){11}(?:[^,]+,){3}-\n)$", csv_row)
                if len(malformed_ea0_7) > 0:
                    malformed_ea1.write(malformed_ea0_7[0])
                malformed_ea0_8 = re.findall(r"^(?:[^,]+,){3}-(T\d{4}(?:[\.\d]+)?,?(?:[^,]+,){11}-,-)[^,]+,[^,]+\n$", csv_row)
                if len(malformed_ea0_8) > 0:
                    malformed_ea1.write("{},-,-\n".format(malformed_ea0_8[0]))
                else:
                    malformed_ea1.write(csv_row)
    with open("./.malformed_ea1.csv") as malformed_ea1:
        with open("./.malformed_ea2.csv", "a") as malformed_ea2:
            for csv_row in malformed_ea1:
                malformed_ea1_0 = re.findall(r"^(?:[^,]+,){3}-(T\d{4}(?:[\.\d]+)?,?(?:[^,]+,){11}(?:[^,]+,){3}[^,]+\n)$", csv_row)
                if len(malformed_ea1_0) > 0:
                    malformed_ea2.write("{}".format(malformed_ea1_0[0]))
                else:
                    malformed_ea2.write(csv_row)
    with open("./.malformed_ea2.csv") as malformed_ea2:
        with open("./.malformed_ea3.csv", "a") as malformed_ea3:
            for csv_row in malformed_ea2:
                malformed_ea2_0 = re.findall(r"^(?:-+,){3}-(T\d{4}(?:[\.\d]+)?,?(?:[^,]+,){11}-,-,)[^,]+\n$", csv_row)
                if len(malformed_ea2_0) > 0:
                    malformed_ea3.write("{}-,-\n".format(malformed_ea2_0[0]))
                else:
                    malformed_ea3.write(csv_row)
    with open("./.malformed_ea3.csv") as malformed_ea3:
        with open("./.final_review.csv", "a") as malformed_ea4:
            for csv_row in malformed_ea3:
                malformed_ea3_0 = re.findall(r"^(T\d{4}(?:[\.\d]+)?,?(?:[^,]+,){11}-,-)(?:[^,]+,)[^,]+\n$", csv_row)
                if len(malformed_ea3_0) > 0:
                    malformed_ea4.write("{},-,-\n".format(malformed_ea3_0[0]))
                else:
                    malformed_ea4.write(csv_row)
    for eachcsv in os.listdir("./"):
        if eachcsv.startswith(".malformed"):
            os.remove(eachcsv)
    os.rename("./.final_review.csv", "./enterprise-attack.csv")


def find_group_id(threat_actor, groups_page):
    group_regex = r"\/(G\d{4})\/\">§\s+" + re.escape(threat_actor) + r"§"
    group_id = re.findall(group_regex, str(groups_page))[0]
    return group_id


def search_for_terms(nav_terms, groups_page):
    matches = {}
    organised_matches = []
    if os.path.exists("nav_layers"):
        shutil.rmtree("nav_layers")
    else:
        pass
    os.makedirs("nav_layers")
    for eachterm in nav_terms:
        with open("./enterprise-attack.csv") as mitre_csv:
            for eachrow in mitre_csv:
                name = re.findall(r"^(?:[^,]+,){12}([^,]+),[^,]+,[^,]+,[^,]+", eachrow)
                if len(name) > 0:
                    if name[0] != "-":
                        ta_name = name[0]
                        ta_description = re.findall(r"^(?:[^,]+,){12}[^,]+,[^,]+,([^,]+),[^,]+", eachrow)[0]
                        if eachterm.lower() in ta_description.lower():
                            if ta_name in matches:
                                if eachterm not in str(matches[ta_name]):
                                    matches[ta_name] = "{};{}".format(matches[ta_name], eachterm)
                                else:
                                    pass
                            else:
                                matches[ta_name] = eachterm
                        else:
                            pass
                    else:
                        pass
                else:
                    pass
    multiple_terms = re.findall(r"([^']+': '[^']+;[^']+)", str(matches))
    for multiple_term in multiple_terms:
        threat_actor = multiple_term.split("': '")[0]
        group_id = find_group_id(threat_actor, groups_page)
        occurances = len(re.findall(r";", multiple_term.split("': '")[1]))
        if occurances < 10:
            occurances = "0" + str(occurances + 1)
        else:
            pass
        organised_matches.append("{}:{}:{}:{}".format(str(occurances), threat_actor, group_id, multiple_term.split("': '")[1]))
    multiple_matches = sorted(organised_matches)
    organised_matches.clear()
    single_terms = re.findall(r"([^']+': '[^';]+)'", str(matches))
    for single_term in single_terms:
        threat_actor = single_term.split("': '")[0]
        group_id = find_group_id(threat_actor, groups_page)
        organised_matches.append("01:{}:{}:{}".format(threat_actor, group_id, single_term.split("': '")[1]))
    single_matches = sorted(organised_matches)
    matches_organised = multiple_matches + single_matches
    if len(matches_organised) > 0:
        for eachentry in matches_organised:
            response = requests.get("https://attack.mitre.org/groups/{}/{}-enterprise-layer.json".format(eachentry.split(":")[2], eachentry.split(":")[2]))
            if response.status_code == 200:
                with open("./nav_layers/{}-{}-enterprise-layer.json".format(eachentry.split(":")[0], eachentry.split(":")[1]), "w") as group_layer_json:
                    group_layer_json.write(response.content.decode("utf-8"))
                with open("./nav_layers/{}-{}-enterprise-layer.txt".format(eachentry.split(":")[0], eachentry.split(":")[1]), "w") as group_layer_json:
                    group_layer_json.write("{}: {}\n".format(eachentry.split(":")[1], eachentry.split(":")[3]))
            else:
                pass


def main():
    if len(nav_terms) > 20:
        print(" --makeNav can only accept a maximum of 20 strings.\n  Please try again.\n")
        sys.exit()
    elif nav_terms and not splitbyTA:
        print(" --makeNav can only be used in conjuction with --splitbyTA as the search terms are matched based on the content of the Threat Actor description field.\n  Please try again.\n")
        sys.exit()
    else:
        pass
    attack_list = []
    attack_dict = {}
    csv_row = ""
    previous = ""
    counter = 0 # 607 techniques
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
    with open("./.malformed_ea0.csv", "w") as attack_csv:
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
                                        technique_page = str(
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
                                                if len(id_name.split(" - ")[0]) == 5:
                                                    spacer = "    "
                                                else:
                                                    spacer = ""
                                                print(
                                                    "      -> Collected  {}{} : {}".format(
                                                        id_name.split(" - ")[0], spacer, id_name.split(" - ")[1]
                                                    )
                                                )
                                                counter += 1
                                            else:
                                                pass
                                            previous = id_name
                                        else:
                                            pass
                                        if True:
                                            csv_row = (
                                                csv_row.replace("--", "-")
                                                .replace(",,-", ",-")
                                                .replace(",,", ",")
                                                .strip(",")
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)[^,]+,[^,]+,[^,]+,[^,]+,([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[csv_row[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,)\-([^,]+,[^,]+)$",
                                                r"\1\2",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+)$",
                                                r"\1,-,-",
                                                csv_row,
                                            )
                                            csv_row = re.sub(
                                                r"^([^,]+,[^,]+),\-",
                                                r"\1,000",
                                                csv_row,
                                            )
                                        csv_row = csv_row.replace(",; ", ",").replace(". ,", ".,").replace("’", "'").replace("    ", " ").replace("   ", " ").replace("  ", " ")
                                        csv_row = re.sub(r"\s\.\s", r"\. ", re.sub(r"\s{2,}", r" ", csv_row.replace("\n", " ")) + "\n")
                                        csv_row = csv_row.replace("\", '","; ").replace("', \"","; ")
                                        if splitbyTA:
                                            row_with_TAs = re.findall(r"^(T\d{4}(?:[\.\d]+)?,?(?:[^,]+,){11})([^,]+),([^,]+\n)$", csv_row)
                                            if len(row_with_TAs) > 0: # if more than one TA associated with the technique
                                                row_start = re.findall(r"^((?:[^,]+,){12})", csv_row)[0]
                                                ta_insert = "-,-,-" # default insert
                                                row_end = re.findall(r"(?:,[^,]+)$", csv_row)[0]
                                                for eachTA_from_csvrow in sorted(row_with_TAs[0][1].split("; ")): # cycle through TAs
                                                    if eachTA_from_csvrow != "-":
                                                        eachTA_from_csvrow = eachTA_from_csvrow.strip("-")
                                                        for each_group in threat_groups:
                                                            if each_group.split("||")[0] == eachTA_from_csvrow:
                                                                ta_insert = each_group.replace("|| ||",",-,").replace("||",",")
                                                                csv_row = "{}{}{}".format(row_start, ta_insert, row_end)
                                                                write_to_csv("./.malformed_ea0.csv", csv_row)
                                                            else:
                                                                pass
                                                    else:
                                                        csv_row = "{}{}{}".format(row_start, ta_insert, row_end)
                                                        write_to_csv("./.malformed_ea0.csv", csv_row)
                                            else:
                                                csv_row = "{}{}{}".format(csv_row, ta_insert, ",-")
                                                write_to_csv("./.malformed_ea0.csv", csv_row)
                                        else:
                                            write_to_csv("./.malformed_ea0.csv", csv_row)
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
    if splitbyTA:
        clean_csv_rows()
    if nav_terms:
        """groups_page = str(
            urllib.request.urlopen(
                "https://attack.mitre.org/groups/".format(
                    csv_row.split(",")[0].replace(".", "/")
                )
            ).read()
        )[2:-1].replace("\\n","§") # testing"""
        print("\n      -> Obtaining Threat Actor navigation layers...")
        search_for_terms(str(nav_terms)[2:-2].split(","), groups_page)
        print("          Navigation layers obtained\n")
    else:
        pass
    if not json_file:
        os.remove("./.enterprise-attack.json")
    else:
        os.rename("./.enterprise-attack.json", "./enterprise-attack.json")
    print("\n")


if __name__ == "__main__":
    main()
