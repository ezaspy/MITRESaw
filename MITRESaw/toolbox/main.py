#!/usr/bin/env python3 -tt
import os
import pandas
import random
import re
import requests
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime

from MITRESaw.toolbox.extract import extract_indicators
from MITRESaw.toolbox.tools.csv import write_csv_summary
from MITRESaw.toolbox.output.matrix import build_matrix
from MITRESaw.toolbox.output.query import build_queries
from MITRESaw.toolbox.tools.files import collect_files
from MITRESaw.toolbox.tools.saw import print_saw


def replace_commas_in_group_desc(csv_line):
    return re.sub(
        r"^((?:[^,]+,){6}.*,relationship--[^,]+,\d{2} [A-Za-z]{3,20} \d{4},\d{2} [A-Za-z]{3,20} \d{4}[^\[]+[^\(]+\([^\)]+\)[^,]+), ",
        r"\1%2C ",
        csv_line,
    )


def mainsaw(
    operating_platforms,
    search_terms,
    provided_groups,
    show_others,
    art,
    navigationlayers,
    queries,
    truncate,
    attack_framework,
    attack_version,
    sheet_tabs,
):

    # checking latest version
    try:
        version_history = requests.get("https://attack.mitre.org/resources/versions/")
    except requests.exceptions.ConnectionError:
        print("\n\n\tUnable to connect to the Internet. Please try again.\n\n\n")
        sys.exit()
    latest_version = re.findall(
        r"<span><strong>([^<]+)",
        str(version_history.content)
        .split("<h5><strong>Current Version</strong></h5>")[1]
        .split("<h5><strong>Most Recent Versions</strong></h5>")[0],
    )[0].split("ATT&amp;CK v")[1]
    if latest_version != attack_version:
        print(
            "\n\n\tThe version of ATT&CK in \033[1;36mMITRESaw.py\033[1;m (\033[1;31m{}\033[1;m) does \n\tnot match the latest published version (\033[1;31m{}\033[1;m). \n\n\tPlease adjust the \033[1;33mattack_version\033[1;m variable \n\tin \033[1;36mMITRESaw.py\033[1;m and try again.\n\n".format(
                attack_version, latest_version
            )
        )
        sys.exit()

    mitresaw_root_date = os.path.join(".", str(datetime.now())[0:10])
    if not os.path.exists(mitresaw_root_date):
        os.makedirs(mitresaw_root_date)
    mitre_files = os.path.join(
        mitresaw_root_date, "{}-{}".format(attack_framework.lower(), attack_version)
    )
    if not os.path.exists(mitre_files):
        os.makedirs(mitre_files)
        time.sleep(0.1)
        print()
        print("    -> Obtaining MITRE ATT&CK files...")

        # obtaining framework
        for sheet_tab in sheet_tabs:
            sheet, tab = sheet_tab.split("-")
            filename = os.path.join(mitre_files, sheet)
            spreadsheet = "{}.xlsx".format(filename)
            if not os.path.exists(os.path.join(mitre_files, spreadsheet)):
                mitre_spreadsheet = requests.get(
                    "https://attack.mitre.org/docs/{}-attack-v{}/{}-attack-v{}-{}".format(
                        attack_framework.lower(),
                        attack_version,
                        attack_framework.lower(),
                        attack_version,
                        spreadsheet.split("/")[-1],
                    )
                )
                with open(spreadsheet, "wb") as spreadsheet_file:
                    spreadsheet_file.write(mitre_spreadsheet.content)
            temp_csv = "{}temp.csv".format(filename)
            xlsx_file = pandas.read_excel(spreadsheet, tab, engine="openpyxl")
            xlsx_file.to_csv(temp_csv, index=None, header=True)
            with open(temp_csv) as csv_with_new_lines:
                malformed_csv = str(csv_with_new_lines.readlines())[2:-2]
                malformed_csv = re.sub(r"\\t", r"£\\t£", malformed_csv)
                if "-groups" not in filename:
                    malformed_csv = re.sub(r"\\n', '(T\d{4})", r"\n\1", malformed_csv)
                    malformed_csv = re.sub(
                        r"\\n['\"], ['\"]\\n['\"], ['\"]", r".  ", malformed_csv
                    )
                    malformed_csv = re.sub(
                        r"([\)\"])\n([^T])", r"\1.  \2", malformed_csv
                    )
                    formated_csv = malformed_csv
                else:
                    malformed_csv = re.sub(r"\\n', '", r"\n", malformed_csv)
                    malformed_csv = re.sub(r"\n\"\\n', \"", r"\"\n", malformed_csv)
                    malformed_csv = re.sub(r"\n\"\n", r"\"\n", malformed_csv)
                    if "-groups" in filename:
                        malformed_csv = re.sub(r"\n( ?[^G])", r"\1", malformed_csv)
                        malformed_csv = re.sub(r"\\n', \"", r"\"\n", malformed_csv)
                        malformed_csv = re.sub(r"\\n\", '", r"\"\n", malformed_csv)
                        malformed_csv = re.sub(
                            r"([\)\"])\n([^G])", r"\1.  \2", malformed_csv
                        )
                    else:
                        malformed_csv = re.sub(r"\n( ?[^S])", r"\1", malformed_csv)
                        malformed_csv = re.sub(r"\\n', \"", r"\"\n", malformed_csv)
                        malformed_csv = re.sub(r"\\n\", '", r"\"\n", malformed_csv)
                        malformed_csv = re.sub(
                            r"([\)\"])\n([^S])", r"\1.  \2", malformed_csv
                        )
                    formated_csv = malformed_csv.replace('\\"', '"')
            with open(
                "{}-{}.csv".format(filename, tab.replace(" ", "_")), "w"
            ) as final_csv:
                final_csv.write(formated_csv)
            os.remove(temp_csv)

    time.sleep(0.1)
    saw = """
@                                                         ,
@                 ╓╗╗,                          ,╓▄▄▄Φ▓▓██▌╫D
@                ║▌ `▓L            ,,, ╓▄▄▄Φ▓▓▀▀▀╫╫╫╫╫╫╫▀▀╫▓▓▄
@                 ▓▄▓▓▓        ,▄▄B░▀╫Ñ╬░░╫╫▓▓▓▓╫╫╫╫▓▓▓╫╫╫╫╣▓▓▓▄
@                 ║████L   ,╓#▀▀▀╨╫ÑÑ╦▄▒▀╣▓▄▄▀╣▌╫▀    ██╫╫╫╫▓▓╫▓▓φ
@                  ▓╫╫╫▀]Ñ░░░░ÑÑÑÑ░░░░░╠▀W▄╠▀▓▒░╫Ñ╖   ╙└"╜▀▓▓▓▓▓█▓▓
@                  ║░░░╦╬╫╫╫╫╫╫╫╫╫╫╫╫╫ÑÑ░░░╠Ñ░╨╫Ñ░╫╫╫╫N     ▀▓▓▓╫██▓╕
@                ,]░╦╬╫╫╫╫╫╫╫▓▓▓▓▓▓╫╫╫╫╫╫╫Ñ░░╠░░╫M░╠╫╫╫╫╦,    ▀▓▓▓▓▓▓⌐
@       ╗▄╦     ]░░╬╫╫╫╫╫▓▓██████████▓▓▒╫╫╫╫Ñ░░╟▒╟▓▒ñ▓▓▓▓░N    ╙▓▓▓▓▓▓
@   ║███╫█╫    ]░░╫╫╫╫╫▓███▓▓▓▓▓▓▓▓▓▓███▓╫╫╫╫╫░░╟▒╟▓Ü╟▓▓▓▓░H    ╟▓▓▓▓▓L
@   ║███╫█╫   ]░░╫╫╫╫▓██▓╫▓▓▓▀▀╠╠╬▀▓▓▓╫▓██▓╫╫╫╫░░ÑÑ╠▄░╠▓▓▓▄▄▄▄▄▓▓▓╫╫╫╫
@    ╓▄▄╫█╫╖╖╖╦░╫╫╫╫╫██▓▓▓▓▀░╬Ñ╣╬╫Ñ░╟▓▓▓▓██╫╫╫╫Ñ░╦]░░░║████▀▀╫╫╫▓╩╨╟╫
@    ╟▓▓╫█╫▀▀▀╩╬╩╫╫▓██▓▓▓▓▌░╫░╟▓▓K╫Ñ░▓▓▓▓╫██▓▒╩╩╩╩ ╙╩╨▀▓M╨╩╨╙╝╣N╦╗Φ╝
@       ╫█╫     ▀███▀╣▓▓▓▓▓░╫Ñ░╠▀░╫Ü░▓▓▓▓▓▀▀███╕      ▐▓▌╖
@   ▄▄▄▄▓█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄╛
@                ▀╩╫╫╫╠╣▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▀░╫╫╫╫▌
@                 ╗▄╫╫Ñ░╠▀▓▓▓▓▓▓▓▓▓▓▓▓▀░╦╬╫╫∩
@                   `⌠╫╫╫Ñ░░Å╣▀▀▀▀▀▒░╦╬╫╫╫`█
@                    ╙╙""╫╫╫½╫╫╫╬╫╫╫╫╫M"▓╛
@                       └╙└ ▄▓╩`║▓╩ Å▀\n\n
    """
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
    tagline = "{}        *ATT&CK for {} v{}\n".format(
        chosen_title, attack_framework.title(), attack_version
    )
    time.sleep(1)
    subprocess.Popen(["clear"]).communicate()
    if not art:
        if saw:
            print_saw(saw, tagline, "                                        ")
            print_saw(saw, tagline, "                                      ")
            print_saw(saw, tagline, "                                    ")
            print_saw(saw, tagline, "                                  ")
            print_saw(saw, tagline, "                                ")
            print_saw(saw, tagline, "                              ")
            print_saw(saw, tagline, "                            ")
    platforms = str(operating_platforms)[2:-2].split(",")
    platforms = list(filter(None, platforms))
    if not art:
        print_saw(saw, tagline, "                          ")
    terms = str(search_terms)[2:-2].split(",")
    terms = list(filter(None, terms))
    if not art:
        print_saw(saw, tagline, "                        ")
    groups = str(provided_groups)[2:-2].split(",")
    groups = list(filter(None, groups))
    if not art:
        print_saw(saw, tagline, "                      ")
    else:
        print(tagline)
    if True:  # creating MITRESaw output file names
        if str(platforms) == "['.']":
            platforms_filename_insert = ""
        else:
            platforms_filename_insert = "{}".format(
                str(platforms)[2:-2].replace("', '", "-")
            )
        if str(terms) == "['.']":
            terms_filename_insert = ""
        else:
            terms_filename_insert = "{}".format(str(terms)[2:-2].replace("', '", "-"))
        if str(groups) == "['.']":
            groups_filename_insert = ""
            groups_insert = "Threat Actors"
            all_insert = "all "
        else:
            groups_filename_insert = "{}".format(str(groups)[2:-2].replace("', '", "-"))
            groups_insert = "{}".format(str(groups)[2:-2])
            all_insert = ""
        mitresaw_output_directory = os.path.join(
            mitresaw_root_date,
            "{}_{}_{}".format(
                platforms_filename_insert.replace("_", ""),
                terms_filename_insert.replace("_", ""),
                groups_filename_insert.replace("_", ""),
            ),
        )
        if not os.path.exists(os.path.join(mitresaw_output_directory)):
            os.makedirs(os.path.join(mitresaw_output_directory))
    (
        additional_terms,
        evidence_found,
        valid_procedures,
        all_evidence,
        log_sources,
        logsources,
        groups_in_scope,
        techniques_in_scope,
        groups_techniques_in_scope,
    ) = ([] for _ in range(9))
    (
        group_procedures,
        group_descriptions,
        contextual_information,
        previous_findings,
    ) = ({} for _ in range(4))
    if os.path.exists(
        os.path.join(mitresaw_output_directory, "ThreatActors_Techniques.csv")
    ):
        os.remove(
            os.path.join(mitresaw_output_directory, "ThreatActors_Techniques.csv")
        )
    if not art:
        if saw:
            print_saw(saw, tagline, "                    ")
            print_saw(saw, tagline, "                  ")
            print_saw(saw, tagline, "                ")
            print_saw(saw, tagline, "              ")
            print_saw(saw, tagline, "            ")
            print_saw(saw, tagline, "          ")
            print_saw(saw, tagline, "        ")
            print_saw(saw, tagline, "      ")
            print_saw(saw, tagline, "    ")
            print_saw(saw, tagline, "  ")
            print_saw(saw, tagline, "partial")
            print_saw(saw, tagline, "-")  # remove saw
            print()
    if str(terms) != "['.']":
        terms_insert = " associated with '\033[1;36m{}\033[1;m'".format(
            str(terms)[2:-2].replace("_", " ").replace("', '", "\033[1;m', '\033[1;36m")
        )
    else:
        terms_insert = ""
    (
        contextual_information,
        group_procedures,
    ) = collect_files(
        mitre_files,
        groups,
        group_procedures,
        group_descriptions,
        terms,
        additional_terms,
    )
    print()
    print(
        "    -> Extracting \033[1;31mIdentifiers\033[1;m from \033[1;32mTechniques\033[1;m based on {}\033[1;33m{}\033[1;m{}".format(
            all_insert,
            groups_insert.replace("', '", "\033[1;m, \033[1;33m"),
            terms_insert,
        )
    )
    # obtaining relevant techniques based on parameters provided
    for csvtechnique in os.listdir(mitre_files):
        if csvtechnique.endswith("techniques-techniques.csv"):
            with open(
                "{}".format(os.path.join(mitre_files, csvtechnique)),
                encoding="utf-8",
            ) as techniquecsv:
                techniques_file_content = techniquecsv.readlines()
                for context in str(contextual_information)[2:-7].split(": '-', '"):
                    group_id = context.split("||")[0]
                    group_name = context.split("||")[1]
                    context_id = context.split("||")[3][1:]
                    if "T{},".format(context_id) in str(techniques_file_content):
                        replaced_row_technique = re.sub(
                            r"(,https://attack.mitre.org/techniques/T\d{4}(?:\/\d{3})?)(,)",
                            r"\1±§§±\2",
                            str(techniques_file_content),
                        )
                        associated_technique = replaced_row_technique.split(
                            "T{},".format(context_id)
                        )[1].split("\"\\n', 'T")[0]
                        technique_name = associated_technique.split(",")[0]
                        technique_information = re.findall(
                            r",(.*),https:\/\/attack\.mitre\.org\/techniques\/T[\d\.\/]+±§§±,[^,]+,[^,]+,[^,]+,\d+\.\d+,\"?((?:Reconnaissance|Resource Development|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact)(?:, (?:Reconnaissance|Resource Development|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact)){0,6})\"?,(\"?.*\"?),(\"?(?:Azure AD|Containers|Google Workspace|IaaS|Linux|Network|Office 365|PRE|SaaS|Windows|macOS)(?:(?:, (?:Azure AD|Containers|Google Workspace|IaaS|Linux|Network|Office 365|PRE|SaaS|Windows|macOS))?){0,10}\"?),(\"[^\"]+\"),",
                            associated_technique,
                        )
                        if len(technique_information) > 0:
                            technique_description = technique_information[0][0]
                            technique_tactics = technique_information[0][1]
                            technique_detection = technique_information[0][2]
                            technique_platforms = technique_information[0][3]
                            technique_data_sources = technique_information[0][4]

                            # obtaining navigation layers for all identified threat groups
                            if navigationlayers:
                                navlayer_output_directory = os.path.join(
                                    mitresaw_root_date,
                                    "{}_navigationlayers".format(
                                        str(datetime.now())[0:10]
                                    ),
                                )
                                navlayer_json = os.path.join(
                                    navlayer_output_directory,
                                    "{}_{}-enterprise-layer.json".format(
                                        group_id, group_name
                                    ),
                                )
                                if not os.path.exists(navlayer_json):
                                    if not os.path.exists(navlayer_output_directory):
                                        os.makedirs(navlayer_output_directory)
                                        print(
                                            "     -> Obtaining ATT&CK Navigator Layers for \033[1;33mThreat Actors\033[1;m related to identified \033[1;32mTechniques\033[1;m...".format(
                                                group_name
                                            )
                                        )
                                    group_navlayer = requests.get(
                                        "https://attack.mitre.org/groups/{}/{}-enterprise-layer.json".format(
                                            group_id,
                                            group_id,
                                        )
                                    )
                                    if not os.path.exists(navlayer_json):
                                        with open(navlayer_json, "wb") as navlayer_file:
                                            navlayer_file.write(group_navlayer.content)
                            if str(platforms) == "['.']":
                                valid_procedure = "{}||{}||{}||{}||{}".format(
                                    context,
                                    technique_description,
                                    technique_detection,
                                    technique_platforms,
                                    technique_data_sources,
                                )
                                valid_procedures.append(valid_procedure)
                            else:
                                for platform in platforms:
                                    if platform in technique_platforms:
                                        valid_procedure = "{}||{}||{}||{}||{}".format(
                                            context,
                                            technique_description,
                                            technique_detection,
                                            technique_platforms,
                                            technique_data_sources,
                                        )
                                        valid_procedures.append(valid_procedure)
                            techniques_in_scope.append(
                                "T{}||{}".format(
                                    context_id, technique_name, technique_tactics
                                )
                            )
                            groups_techniques_in_scope.append(
                                "{}||T{}||{}||{}".format(
                                    group_name,
                                    context_id,
                                    technique_name,
                                    technique_tactics,
                                )
                            )
                    groups_in_scope.append(group_name)
    print()
    consolidated_procedures = sorted(list(set(valid_procedures)))
    counted_techniques = Counter(techniques_in_scope)
    sorted_techniques = sorted(
        counted_techniques.items(), key=lambda x: x[1], reverse=True
    )
    sorted_threat_actors_techniques_in_scope = list(set(groups_techniques_in_scope))
    technique_combos = []
    for technique in counted_techniques.most_common():
        technique_count = technique[1]
        if ": " in technique[0]:
            parent_technique = technique[0].split(": ")[0]
            sub_technique = technique[0].split(": ")[1]
        else:
            parent_technique = technique[0]
            sub_technique = "-"
        technique_combo = [parent_technique, sub_technique, technique_count]
        technique_combos.append(technique_combo)
    for each_procedure in consolidated_procedures:
        (
            technique_findings,
            previous_findings,
        ) = extract_indicators(
            each_procedure,
            terms,
            evidence_found,
            "",
            previous_findings,
            truncate,
        )
        threat_actor_technique_id_name_findings = []

        # constructing sub-technique pairing due to format of sub-techniques in mitre output files e.g. T1566.001||Spearphishing Attachment
        for technique_found in technique_findings:
            threat_actor_found = technique_found.split("||")[1]
            technique_id_found = technique_found.split("||")[2]
            technique_name_found = technique_found.split("||")[3]
            if "." in technique_id_found:
                parent_technique_found = "{}||{}".format(
                    technique_id_found,
                    str(sorted_techniques)
                    .split("{}||".format(technique_id_found))[1]
                    .split("{}".format(technique_name_found))[0][0:-2],
                )
                technique_id_name_found = "{}: {}".format(
                    parent_technique_found, technique_name_found
                )
            else:
                technique_id_name_found = "{}||{}".format(
                    technique_id_found, technique_name_found
                )
            threat_actor_technique_id_name_found = "{}||{}".format(
                threat_actor_found, technique_id_name_found
            )
            threat_actor_technique_id_name_findings.append(
                threat_actor_technique_id_name_found
            )
    threat_actor_technique_id_name_findings = list(
        set(threat_actor_technique_id_name_findings)
    )
    all_evidence.append(technique_findings)
    consolidated_techniques = all_evidence[0]
    if len(consolidated_techniques) > 0:
        print("\n     Correlating results and creating intersecting matrix...")

        # outputting relevant queries
        query_pairings = build_matrix(
            mitresaw_output_directory,
            consolidated_techniques,
            sorted_threat_actors_techniques_in_scope,
            threat_actor_technique_id_name_findings,
        )
        """if queries:
            print()
            print(
                "    -> Compiling queries based on \033[1;31midentifiers\033[1;m based on {}".format(
                    terms_insert
                )
            )"""

        # outputting csv file for ingestion into other tools
        write_csv_summary(
            consolidated_techniques,
            mitresaw_output_directory,
            mitre_files,
            queries,
            query_pairings,
            log_sources,
        )
        mitresaw_techniques = re.findall(
            r"\|\|(T\d{3}[\d\.]+)\|\|", str(consolidated_techniques)
        )
        mitresaw_techniques = list(set(mitresaw_techniques))
        mitresaw_techniques_insert = str(mitresaw_techniques)[2:-2].replace(
            "', '",
            '", "comment": "", "score": 1, "color": "#66b1ff", "showSubtechniques": false}}, {{"techniqueID": "',
        )
        print("      Done.")

        # enterprise-attack navigation layer only currently
        mitresaw_navlayer = '{{"description": "Enterprise techniques used by various Threat Actors, produced by MITRESaw", "name": "{}", "domain": "enterprise-attack", "versions": {{"layer": "4.4", "attack": "15", "navigator": "4.8.1"}}, "techniques": [{{"techniqueID": "{}", "comment": "", "score": 1, "color": "#66b1ff", "showSubtechniques": false}}], "gradient": {{"colors": ["#ffffff", "#66b1ff"], "minValue": 0, "maxValue": 1}}, "legendItems": [{{"label": "identified from MITRESaw analysis", "color": "#66b1ff"}}]}}\n'.format(
            mitresaw_output_directory.split("/")[2][11:], mitresaw_techniques_insert
        )
        with open(
            os.path.join(mitresaw_output_directory, "enterprise-layer.json"), "w"
        ) as mitresaw_navlayer_json:
            mitresaw_navlayer_json.write(
                mitresaw_navlayer.replace("{{", "{").replace("}}", "}")
            )
        build_queries(queries, mitresaw_output_directory, query_pairings)
        log_sources = sorted(
            str(log_sources)[3:-3]
            .replace(", ", "; ")
            .replace("'; '", "; ")
            .replace('"; "', "; ")
            .replace("; ", ", ")
            .split(", ")
        )
        # removing specific event IDs as they are not needed for reporting stats in stdout
        for log_source in log_sources:
            if ": " in log_source:
                logsources.append(log_source.split(": ")[0])
            elif log_source.startswith("*nix /var/log/"):
                logsources.append(f"{log_source.split("/log/")[0]}/log")
            else:
                logsources.append(log_source)
        # counting the occurance of each log source
        counted_log_sources = Counter(list(filter(None, logsources)))
        log_coverage = list(
            filter(
                None,
                sorted(counted_log_sources.items(), key=lambda x: x[1], reverse=True),
            )
        )
        print(
            "\n     The following log sources are recommended to \033[4;37maid with detecting\033[1;m the aforementioned ATT&CK techniques:"
        )
        print()
        time.sleep(0.5)
        total = 0
        for log_count in log_coverage:
            log = log_count[0].split(": ")[0]
            count = log_count[1]
            percentage = str(int(count / len(log_sources) * 100))
            if percentage == "0" and show_others:
                percentage = "<1"
                print(
                    "       - {}: \033[1;37m{}%\033[1;m".format(
                        log.strip().strip('"'), percentage
                    )
                )
            elif percentage != "0":
                print(
                    "       - {}: \033[1;37m{}%\033[1;m".format(
                        log.strip().strip('"'), percentage
                    )
                )
                total += int(percentage)
        if not show_others:
            others = 100 - total
            print("       - Others: \033[1;37m{}%\033[1;m".format(others))
    else:
        print("\n    -> No evidence could be found which match the provided criteria.")
    print("\n\n")
