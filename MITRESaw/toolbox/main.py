#!/usr/bin/env python3 -tt
import os
import pandas
import random
import re
import requests
import subprocess
import time
from collections import Counter
from datetime import datetime

from MITRESaw.toolbox.extract import extract_indicators
from MITRESaw.toolbox.files import collect_files
from MITRESaw.toolbox.logs import tidy_log_sources
from MITRESaw.toolbox.matrix import build_matrix
from MITRESaw.toolbox.query import build_queries
from MITRESaw.toolbox.saw import print_saw


def mainsaw(
    operating_platforms,
    search_terms,
    provided_groups,
    art,
    navigationlayers,
    queries,
    softwares,
    truncate,
    attack_framework,
    attack_version,
    sheet_tabs,
):
    mitresaw_root_date = os.path.join(".", str(datetime.now())[0:10])
    if not os.path.exists(mitresaw_root_date):
        os.makedirs(mitresaw_root_date)
    else:
        pass
    mitre_files = os.path.join(mitresaw_root_date, "mitre-attack-files")
    if not os.path.exists(mitre_files):
        os.makedirs(mitre_files)
        time.sleep(0.1)
        print()
        print("    -> Obtaining MITRE ATT&CK files...")
        # obtaining framework
        for sheet_tab in sheet_tabs:
            sheet, tab = sheet_tab.split("-")
            filename = os.path.join(
                mitre_files,
                "{}-attack-v{}-{}".format(attack_framework.lower(), attack_version, sheet),
            )
            spreadsheet = "{}.xlsx".format(filename)
            if not os.path.exists(
                os.path.join(
                    mitre_files,
                    "{}-attack-v{}/{}".format(attack_framework.lower(), attack_version, spreadsheet),
                )
            ):
                mitre_spreadsheet = requests.get(
                    "https://attack.mitre.org/docs/enterprise-attack-v{}/{}".format(
                        attack_version, spreadsheet.split("/")[-1]
                    )
                )
                with open(spreadsheet, "wb") as spreadsheet_file:
                    spreadsheet_file.write(mitre_spreadsheet.content)
            else:
                pass
            temp_csv = "{}temp.csv".format(filename)
            xlsx_file = pandas.read_excel(spreadsheet, tab, engine="openpyxl")
            xlsx_file.to_csv(temp_csv, index=None, header=True)
            with open(temp_csv) as csv_with_new_lines:
                malformed_csv = str(csv_with_new_lines.readlines())[2:-2]
                malformed_csv = re.sub(r"\\t", r"£\\t£", malformed_csv)
                if "-groups" not in filename and "-software" not in filename:
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
    else:
        pass
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
    tagline = "{}        *ATT&CK for Enterprise v{}\n".format(
        chosen_title, attack_version
    )
    time.sleep(2)
    subprocess.Popen(["clear"]).communicate()
    if not art:
        if saw:
            print_saw(
                saw, tagline, "                                                        "
            )
            print_saw(
                saw, tagline, "                                                      "
            )
            print_saw(
                saw, tagline, "                                                    "
            )
            print_saw(
                saw, tagline, "                                                  "
            )
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
            print_saw(saw, tagline, "                            ")
        else:
            pass
    else:
        pass
    platforms = str(operating_platforms)[2:-2].split(",")
    platforms = list(filter(None, platforms))
    if not art:
        print_saw(saw, tagline, "                          ")
    else:
        pass
    terms = str(search_terms)[2:-2].split(",")
    terms = list(filter(None, terms))
    if not art:
        print_saw(saw, tagline, "                        ")
    else:
        pass
    groups = str(provided_groups)[2:-2].split(",")
    groups = list(filter(None, groups))
    if not art:
        print_saw(saw, tagline, "                      ")
    else:
        print(tagline)
    if saw:  # creating MITRESaw output file names
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
        else:
            groups_filename_insert = "{}".format(str(groups)[2:-2].replace("', '", "-"))
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
        else:
            pass
    else:
        pass
    (
        additional_terms,
        group_softwares,
        evidence_found,
        valid_procedures,
        all_evidence,
        log_sources,
    ) = ([] for _ in range(6))
    (
        group_procedures,
        group_descriptions,
        group_descriptions_software,
        contextual_information,
        previous_findings,
    ) = ({} for _ in range(5))
    identifiers = ""
    if os.path.exists(
        os.path.join(mitresaw_output_directory, "ThreatActors_Techniques.csv")
    ):
        os.remove(
            os.path.join(mitresaw_output_directory, "ThreatActors_Techniques.csv")
        )
    else:
        pass
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
        else:
            pass
    else:
        pass
    if str(terms) != "['.']":
        terms_insert = " associated with '\033[1;36m{}\033[1;m'".format(
            str(terms)[2:-2].replace("_", " ").replace("', '", "\033[1;m', '\033[1;36m")
        )
    else:
        terms_insert = ""
    contextual_information = collect_files(
        mitre_files,
        groups,
        group_procedures,
        group_descriptions,
        terms,
        additional_terms,
        softwares,
        group_descriptions_software,
    )
    print()
    print(
        "    -> Extracting \033[1;31mIdentifiers\033[1;m from \033[1;32mTechniques\033[1;m based on \033[1;33mThreat Actors\033[1;m{}".format(
            terms_insert
        )
    )
    for csvtechnique in os.listdir(mitre_files):
        if csvtechnique.endswith("-techniques-techniques.csv"):
            with open(
                "{}".format(os.path.join(mitre_files, csvtechnique)),
                encoding="utf-8",
            ) as techniquecsv:
                techniques_file_content = techniquecsv.readlines()
                for context in str(contextual_information)[2:-7].split(": '-', '"):
                    group_id = context.split("||")[0]
                    group_name = context.split("||")[1]
                    context_id = context.split("||")[2][1:]
                    if "T{},".format(context_id) in str(techniques_file_content):
                        replaced_row_technique = re.sub(
                            r"(,https://attack.mitre.org/techniques/T\d{4}(?:\/\d{3})?)(,)",
                            r"\1||\2",
                            str(techniques_file_content),
                        )
                        associated_technique = replaced_row_technique.split(
                            "T{},".format(context_id)
                        )[1].split("\"\\n', 'T")[0]
                        technique_name = associated_technique.split(",")[0]
                        technique_information = re.findall(
                            r",(.*),https:\/\/attack\.mitre\.org\/techniques\/T[\d\.\/]+\|\|,[^,]+,[^,]+,\d+\.\d+,\"?(?:Initial\ Access|Execution|Persistence|Privilege\ Escalation|Defense\ Evasion|Credential\ Access|Dicovery|Lateral\ Movement|Collection|Command\ and\ Control|Exfiltration|Impact)(?:(, (?:Initial\ Access|Execution|Persistence|Privilege\ Escalation|Defense\ Evasion|Credential\ Access|Dicovery|Lateral\ Movement|Collection|Command\ and\ Control|Exfiltration|Impact))?){0,13},(\"?.*\"?),(\"?(?:Azure AD|Containers|Google Workspace|IaaS|Linux|Network|Office 365|PRE|SaaS|Windows|macOS)(?:(?:, (?:Azure AD|Containers|Google Workspace|IaaS|Linux|Network|Office 365|PRE|SaaS|Windows|macOS))?){0,10}\"?),(\"[^\"]+\"),",
                            associated_technique,
                        )
                        if len(technique_information) > 0:
                            technique_description = technique_information[0][0]
                            technique_detection = technique_information[0][2]
                            technique_platforms = technique_information[0][3]
                            technique_data_sources = technique_information[0][4]
                            # obtaining navigation layers for all identified threat groups and software
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
                                            "     -> Obtaining ATT&CK Navigator Layers for \033[1;33mThreat Actors/Software\033[1;m related to identified \033[1;32mTechniques\033[1;m...".format(
                                                group_name
                                            )
                                        )
                                    else:
                                        pass
                                    group_navlayer = requests.get(
                                        "https://attack.mitre.org/groups/{}/{}-enterprise-layer.json".format(
                                            group_id,
                                            group_id,
                                        )
                                    )
                                    if not os.path.exists(navlayer_json):
                                        with open(navlayer_json, "wb") as navlayer_file:
                                            navlayer_file.write(
                                                group_navlayer.content
                                            )
                                    else:
                                        pass
                                else:
                                    pass
                            else:
                                pass
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
                                    else:
                                        pass
                        else:
                            pass
                    else:
                        pass
        else:
            pass
    print()
    consolidated_procedures = sorted(list(set(valid_procedures)))
    for each_procedure in consolidated_procedures:
        (
            technique_findings,
            identifiers,
            previous_findings,
        ) = extract_indicators(
            each_procedure,
            terms,
            evidence_found,
            identifiers,
            previous_findings,
            truncate,
        )
    all_evidence.append(technique_findings)
    consolidated_techniques = all_evidence[0]
    if len(consolidated_techniques) > 0:
        query_pairings = build_matrix(
            mitresaw_output_directory, mitre_files, consolidated_techniques
        )
        for dataset in consolidated_techniques:
            with open(
                os.path.join(mitresaw_output_directory, "ThreatActors_Techniques.csv"),
                "a",
            ) as opmitre_csv:
                opmitre_csv.write(
                    "{}\n".format(dataset.replace(",||,", ",").replace("||", ","))
                )
                if queries:
                    technique_id = dataset.split("||")[2]
                    technique_name = dataset.split("||")[3]
                    parameters = (
                        dataset.split("||")[-1].replace("\\\\\\\\", "\\\\").lower()
                    )
                    query_pairings.append(
                        "{}||{}||{}".format(technique_id, technique_name, parameters)
                    )
                else:
                    pass
            logsource = tidy_log_sources(dataset.split("||")[-3])
            log_sources.append(logsource.replace(", , ",", "))
        mitresaw_techniques = re.findall(
            r"\|\|(T\d{3}[\d\.]+)\|\|", str(consolidated_techniques)
        )
        mitresaw_techniques = list(set(mitresaw_techniques))
        if navigationlayers:
            mitresaw_techniques_insert = str(mitresaw_techniques)[2:-2].replace(
                "', '",
                '", "comment": "", "score": 1, "color": "#66b1ff", "showSubtechniques": false}}, {{"techniqueID": "',
            )
            # enterprise-attack navigation layer only currently
            mitresaw_navlayer = '{{"description": "Enterprise techniques used by various Threat Actors/Software, produced by MITRESaw", "name": "{}", "domain": "enterprise-attack", "versions": {{"layer": "4.4", "attack": "13", "navigator": "4.8.1"}}, "techniques": [{{"techniqueID": "{}", "comment": "", "score": 1, "color": "#66b1ff", "showSubtechniques": false}}], "gradient": {{"colors": ["#ffffff", "#66b1ff"], "minValue": 0, "maxValue": 1}}, "legendItems": [{{"label": "identified from MITRESaw analysis", "color": "#66b1ff"}}]}}\n'.format(
                mitresaw_output_directory.split("/")[2][11:], mitresaw_techniques_insert
            )
            with open(
                os.path.join(mitresaw_output_directory, "enterprise-layer.json"), "w"
            ) as mitresaw_navlayer_json:
                mitresaw_navlayer_json.write(
                    mitresaw_navlayer.replace("{{", "{").replace("}}", "}")
                )
        else:
            pass
        build_queries(queries, mitresaw_output_directory, query_pairings)
        log_sources = sorted(
            str(log_sources)[3:-3]
            .replace(", ", "; ")
            .replace("'; '", "; ")
            .replace('"; "', "; ")
            .replace("; ", ", ")
            .split(", ")
        )
        counted_log_sources = Counter(log_sources)
        log_coverage = sorted(
            counted_log_sources.items(), key=lambda x: x[1], reverse=True
        )
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
            print(
                "       - {}: \033[1;37m{}%\033[1;m".format(
                    log.strip().strip('"'), percentage
                )
            )
    else:
        print("\n    -> No evidence could be found which match the provided criteria.")
    print("\n\n")
