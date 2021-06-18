#!/usr/bin/env python3 -tt
import urllib.request, ssl, argparse, subprocess, re, time, sys
from bs4 import BeautifulSoup

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help="Show progress", action='store_const', const=True, default=False)
parser.add_argument("-e", "--elrond", help="include scope for elrond context compatibility", action='store_const', const=True, default=False)
args = parser.parse_args()
verbose, elrond = args.verbose, args.elrond

def main():
    def doCollect(eachid):
        urlrequest = str(BeautifulSoup(urllib.request.urlopen("https://attack.mitre.org/techniques/{}/".format(eachid)).read(),"html.parser").find_all())
        regex = re.compile(r"href=\"\/techniques\/"+str(eachid.replace(".","/"))+r"\/\">[\S\s]\s+[A-Za-z\.\/][\w\-\ \.\/\(\)]+[A-Za-z\(\)]")
        name = re.sub(r"[\S\s]+\s{2,}", r"<span class=\"h5 card-title\">Technique: ", str(re.findall(regex, urlrequest)[0]))
        description = str("<span class=\"h5 card-title\">Description: "+str(re.sub(r"</p><p>", r" ", str(re.sub(r"\<span\s.*\<\/span>", r"", str(re.findall(r"<div class=\"description-body\">[\S\s]{4}(.*)</p>", urlrequest)[1]))).replace(". .",".").replace(".\".",".").replace("<code>","").replace("</code>",""))))+".."
        techniquecard, cards = str(name+description+str(urlrequest.replace("\\n","\n").replace("\n","\\n").split("<div class=\"col-md-4\">\\n<div class=\"card\">\\n<div class=\"card-body\">\\n<div class=\"row card-data\" id=\"card-id\">")[1]).split("</div>\\n</div>\\n</div>\\n<div class=\"text-center pt-2 version-button live\">\\n<div class=\"live\">")[0]).replace("\\\"","\""), []
        if ">Detection</h2>" in urlrequest:
            techniquecard = "{}<span Detection: {},".format(techniquecard, re.sub(r">\w+</h3>", r"", str(str(re.sub(r"<a href=\"https://attack.mitre.org/tactics/TA\d{4}\">", r"", str(re.sub(r"([A-Za-z]\.)([A-Z])", r"\1 \2", str(re.sub(r"<a href=\"/software/S\d{4}\">", r"", str(re.sub(r"\[\d+\]", r"", str(re.sub(r"\<sup>[^\>]+\>", r"", str(re.sub(r"\<span[^\>]+\>", r"", str(re.sub(r"<a href=\"/techniques/T\d{4}\">", r"", str(re.sub(r"<a href=\"/techniques/T\d{4}/\d{3}\">", r"", str(str(urlrequest.split(">Detection</h2>")[1].split("<h2 class")[0]).replace("\n","\\n")[12:-14].replace("<code>","").replace("</code>","").replace(",",";").replace(" / ","/").replace("&gt;",">").replace("&lt;","<").replace("&amp;","&").replace("<p>","").replace("</p>","").replace("<ul><li>","(*)").replace("</li><li>","(*)").replace("</li></ul>","(*)").replace("</a>","").replace("\\s ","'s").replace("(*)"," (*)").replace("  "," ").replace("Äô","").replace("Äî","").replace("<em>","").replace("</em>","").replace("</username>","").replace("<labelname> ","").replace("</labelname>","").replace("</sup>","").replace("</span>","")))))))))))))))))).replace(" ; ","; ").replace("\\\\","\\").split("<div class")[0]).replace("  ","").replace("</pid>","").strip("\"")))
        else:
            pass
        if "mitigations/M" in urlrequest:
            techniquecard = techniquecard+"<span Mitigations: "
            try:
                for line in str(str(BeautifulSoup(urllib.request.urlopen("https://attack.mitre.org/techniques/{}/".format(eachid)).read(),"html.parser").find_all("table"))[1:-1]).split("\n"):
                    if line.startswith("<a href=\"/mitigations/M"):
                        techniquecard = "{}{}".format(techniquecard, str(re.sub(r"<a href=\"/mitigations/M\d{4}\"> ", r"", line[0:-5]))+",")
                    else:
                        pass
            except:
                pass
        else:
            pass
        if "software/S" in urlrequest:
            techniquecard = techniquecard+"<span Software: "
            try:
                for line in str(str(BeautifulSoup(urllib.request.urlopen("https://attack.mitre.org/techniques/{}/".format(eachid)).read(),"html.parser").find_all("table"))[1:-1]).split("\n"):
                    if line.startswith("<a href=\"/software/S"):
                        techniquecard = "{}{}".format(techniquecard, str(re.sub(r"<a href=\"/software/S\d{4}\"> ", r"", line[0:-5]))+",")
                    else:
                        pass
            except:
                pass
        else:
            pass
        try:
            for line in str(str(str(BeautifulSoup(urllib.request.urlopen("https://attack.mitre.org/techniques/{}/".format(eachid)).read(),"html.parser").find_all("table"))[1:-1]).split("</tbody>")[1]).split("\n"):
                if line.startswith("<a href=\"/groups/G"):
                    threat_actor_list.append(re.sub(r"<a href=\"/groups/G\d{4}\"> ", r"", line[0:-5]))
                else:
                    pass
        except:
            pass
        for eachcard in techniquecard.replace("Tactics","Tactic").replace("  ","").replace("class=\"h5 card-title\">","").replace("</span>","").replace("\\n<div class=\"card-","").replace("\\n<!--start-indexing-for-search-->","").replace("\\n<!--stop-indexing-for-search-->","").replace("</div>data\" id=\"card-","").replace("</div>data\">","").replace("id\">","").replace("</a>\\ntactics\">","").replace("platforms\">","").replace("</div>","").replace("\\n"," ").replace(", ",",").split("<span ")[1:]:
            cards.append(eachcard.strip(","))
        collectedtechniques.append(str(str(re.sub(r"T\d{4}\">(T\d{4}\')", r"\1", str(cards).replace("\\xa0"," ").replace(" <a href=\"/techniques/","")[1:-1])))+"||||"+str(threat_actor_list))
    subprocess.Popen(["clear"])
    time.sleep(2)
    if verbose:
        print("\n\n   -> Collecting MITRE ATT&CK techniques...\n")
    else:
        pass
    ssl._create_default_https_context = ssl._create_unverified_context
    nooftechniques, counter, techniquestable, entries, previousprogress = re.findall(r"<h6>Sub-techniques: (\d+)</h6>", str(BeautifulSoup(urllib.request.urlopen("https://attack.mitre.org/techniques/enterprise/").read(),"html.parser")))[0], 1, str(BeautifulSoup(urllib.request.urlopen("https://attack.mitre.org/techniques/enterprise/").read(),"html.parser").find_all("table"))[1:-1], {}, "00.00%"
    for techniques in techniquestable.split("<tr class=\"technique\">")[1:]:
        name = str(str(re.sub(r"(/techniques/T|/software/S|/mitigations/M)\d+\">( )", r"\1", str(re.sub(r"<code>([^\<]+)</code>", r"\1", (techniques.replace("<td>\n</td>","<td></td>").replace("<td></td>","").replace("\n<td>","").replace("</td>","").replace("</tr>","").replace("                            ","").replace("                        ","").replace("                    ","").replace(". . ",". ").replace(" </a>","<a href=\"").replace("\n<td colspan=\"2\">","").replace("\n","").replace("<a href=\"<a href=\"","<a href=\"")))).split("<a href=\"")[2]))).strip()
        mitreid = str(str(re.sub(r"/techniques/T\d+\">( )", r"\1", str(re.sub(r"<code>([^\<]+)</code>", r"\1", (techniques.replace("<td>\n</td>","<td></td>").replace("<td></td>","").replace("\n<td>","").replace("</td>","").replace("</tr>","").replace("                            ","").replace("                        ","").replace("                    ","").replace(". . ",". ").replace(" </a>","<a href=\"").replace("\n<td colspan=\"2\">","").replace("\n","").replace("<a href=\"<a href=\"","<a href=\"")))).split("<a href=\"")[1]))).strip()
        subtechniques = str(re.sub(r"<code>([^\<]+)</code>", r"\1", (techniques.replace("<td>\n</td>","<td></td>").replace("<td></td>","").replace("\n<td>","").replace("</td>","").replace("</tr>","").replace("                            ","").replace("                        ","").replace("                    ","").replace(". . ",". ").replace(" </a>","<a href=\"").replace("\n<td colspan=\"2\">","").replace("\n","").replace("<a href=\"<a href=\"","<a href=\""))))
        collectedtechniques, threat_actor_list = [], []
        doCollect("T"+mitreid.split("T")[-1])
        progress = str(round(round(int(counter)/int(nooftechniques)*100, 2)*2, 2))
        if verbose:
            if progress[0:3] != previousprogress[0:3]:
                if progress.startswith("10.") or progress.startswith("20.") or progress.startswith("30.") or progress.startswith("40.") or progress.startswith("50.") or progress.startswith("60.") or progress.startswith("70.") or progress.startswith("80.") or progress.startswith("90."):
                    print("     -> Progress: {}% complete...".format(progress))
                else:
                    pass
            else:
                pass
            counter += 1
            previousprogress = progress
        else:
            pass
        for eachsub in subtechniques.split("<a href=\"")[4:]:
            subid = str(re.sub(r"/techniques/T\d+/\d+\">( )", r"\1", str(eachsub.replace("<tr class=\"sub technique\">","").strip()))).strip()
            if subid.startswith(".0"):
                doCollect(str(mitreid)+"/"+str(subid.strip(".")))
            else:
                pass
        for eachtechnique in collectedtechniques:
            for eachtactic in str(eachtechnique.split("'Tactic: ")[1]).split("'")[0].split(","):
                for eachplatform in str(eachtechnique.split("'Platforms: ")[1]).split("'")[0].split(","):
                    key, value = str(re.sub(r"(CAPEC ID: )<a href=\"https://capec.mitre.org/data/definitions/\d+.html\" target=\"_blank\">(CAPEC-\d+)</a> ,", r"\1\2", str(eachtechnique.split(", 'Tactic: ")[0]+", 'Tactic: "+eachtactic+"', 'Platform: "+eachplatform+", "+str(str(eachtechnique.split("'Platforms: ")[1]).split("'")[1:]).replace("', ', ', '",", ").replace("', ', ","").replace("', '","")[1:-3]).replace("'",""))).split("||||")
                    entries[key] = value
    if verbose:
        print("\n   -> Collection of MITRE ATT&CK Techniques completed.\n   ->  Writing to CSV...\n")
    else:
        pass
    with open("collectedMITRE.csv", "a") as mitrecsv:
        mitrecsv.write("name,description,subid,id,tactic,platform,scope,system_requirements,permissions_required,effective_permissions,data_sources,defense_bypassed,version,created,last_modified,detection,mitigations,software,threat_actor,\n")
        previoustechnique = ""
        for k, v in entries.items():
            details = str(str(re.sub(r"T\d{4}/\d{3}\">T\d{4}\.\d{3}</a>", r"", re.sub(r"T\d{4}\.\d{3}</a>,<a href=\"/techniques/T\d{4}/\d{3}\">", r"", k))).replace(" tactics\">","").replace(", Sub-techniques: , ",", ").replace(", Sub-techniques:  No sub-techniques, ",", ").replace(", ","<>").replace(",",";").replace("<>",",").replace("\\\\u202f"," "))
            details = details.replace(". <div class=\"col-md-1 px-0 text-center\"> <div class=\"col-md-11 pl-0\"> ",".").replace("   <div class=\"row card-data\"> <div class=\"col-md-1 px-0 text-center\"> ","").replace("<div class=\"col-md-11 pl-0\"> ,Sub-techniques: ",",").replace(" <div class=\"row card-data\" id=\"card-tactics\"> <div class=\"col-md-1 px-0 text-center\"> ,data-original-title=\"The tactic objectives that the (sub-)technique can be used to accomplish\" data-placement=\"left\" data-test-ignore=\"true\" data-toggle=\"tooltip\" title=\"\">ⓘ  <div class=\"col-md-11 pl-0\"> ","").replace(",data-original-title=\"The lowest level of permissions the adversary is required to be operating within to perform the (sub-)technique on a system\" data-placement=\"left\" data-test-ignore=\"true\" data-toggle=\"tooltip\" title=\"\">ⓘ  <div class=\"col-md-11 pl-0\"> ,",",").replace("   <div class=\"row card-data\"> <div class=\"col-md-1 px-0 text-center\"> ,data-original-title=\"Source of information collected by a sensor or logging system that may be used to collect information relevant to identifying the action being performed;sequence of actions;or the results of those actions by an adversary\" data-placement=\"left\" data-test-ignore=\"true\" data-toggle=\"tooltip\" title=\"\">ⓘ  <div class=\"col-md-11 pl-0\"> ,",",").replace("   <div class=\"row card-data\"> <div class=\"col-md-1 px-0 text-center\"> <div class=\"col-md-11 pl-0\"> ,",",").replace("  \"Detection: ",",Detection: ").replace(".\",Mitigations: ",".,Mitigations: ").replace(",  ,",",")
            details = re.sub(r"<a href=\"[^\>]+>[^\<]+</a>: ([^\;\,];?)", r"\1", details)
            for eachvalue in str(str(v).replace("\\'","'").replace("[","").replace("]","").strip()).split(", "):
                name = re.findall(r"^Technique: ([^\,]+)\,", details)[0]
                description = str(re.findall(r"Description: ([\S\s]+\.)\.\,", details.replace(". ..","..").replace("...","..").replace(". ,",".,").replace(".\",",".,").replace("&gt;",">").replace("&lt;","<").replace("<p>","").replace("</p>","").replace("<ul><li>","(*)").replace("</li><li>","(*)").replace("</li></ul>","(*)").replace("</a>","").replace("\\s ","'s").replace("(*)"," (*)").replace("  "," ").replace("Äô","").replace("Äî","").replace("<em>","").replace("</em>","").replace("</username>","").replace("<labelname> ","").replace("</labelname>",""))[0]).replace(",","").replace(";"," ").replace("  "," ")
                techniqueid = re.findall(r"ID: (T[^\,]+)\,", details)[0]
                if "." in techniqueid:
                    row = "{},{},{}".format(name, description, techniqueid)
                else:
                    row = "{},{},{}.000".format(name, description, techniqueid)
                if "Sub-technique of:" in details:
                    row = "{},{}".format(row, str(re.findall(r"Sub-technique of: (T[^\,]+)\,", details)[0]))
                else:
                    row = "{},{}".format(row, re.findall(r"ID: (T[^\,]+)\,", details)[0])
                row = "{},{}".format(row, re.findall(r"Tactic: ([^\,]+)\,", details)[0])
                row = "{},{}".format(row, re.findall(r"Platform: ([^\,]+)\,", details)[0])
                if elrond:
                    if row.endswith("Windows") or row.endswith("macOS") or row.endswith("Linux"):
                        row = "{},{}".format(row, "in")
                    else:
                        row = "{},{}".format(row, "out")
                else:
                    row = "{},{}".format(row, "-")
                if "System Requirements:" in details:
                    row = "{},{}".format(row, str(re.findall(r"System Requirements: ([^\,]+)\,", details)[0]).replace("<code>","").replace("</code>",""))
                else:
                    row = "{},-".format(row)
                if "Permissions Required:" in details:
                    row = "{},{}".format(row, str(re.findall(r"Permissions Required: ([^\,]+)\,", details)[0]))
                else:
                    row = "{},-".format(row)
                if "Effective Permissions:" in details:
                    row = "{},{}".format(row, str(re.findall(r"Effective Permissions: ([^\,]+)\,", details)[0]))
                else:
                    row = "{},-".format(row)
                if "Data Sources:" in details:
                    row = "{},{}".format(row, str(re.findall(r"Data Sources: ([^\,]+)\,", details)[0]))
                else:
                    row = "{},-".format(row)
                if "Defense Bypassed:" in details:
                    row = "{},{}".format(row, str(re.findall(r"Defense Bypassed: ([^\,]+)\,", details)[0]))
                else:
                    row = "{},-".format(row)
                row = "{},{}".format(row, re.findall(r"Version: ([^\,]+)\,", details)[0])
                row = "{},{}".format(row, re.findall(r"Created: ([^\,]+)\,", details)[0])
                row = "{},{}".format(row, re.findall(r"Last Modified: (\d{1,2} [^\ ]+ \d{4})", details)[0])
                if "Detection:" in details:
                    if len(re.findall(r"Detection: ([^\,]*)", details)) > 0:
                        row = "{},{}".format(row, str(re.findall(r"Detection: ([^\,]*)", details)[0]).replace(". ",".").replace(".",". ").strip("\""))
                    else:
                        row = "{},-".format(row)
                else:
                    row = "{},-".format(row)
                if "Mitigations:" in details:
                    if len(re.findall(r"Mitigations: ([^\,]*)", details)) > 0:
                        if len(re.findall(r"Mitigations: ([^\,]*)", details)[0]) > 1:
                            row = "{},{}".format(row, re.findall(r"Mitigations: ([^\,]*)", re.sub(r"M\d+", r"", details))[0])
                        else:
                            row = "{},-".format(row)
                    else:
                        row = "{},-".format(row)
                else:
                    row = "{},-".format(row)
                if "Software:" in details:
                    if len(re.findall(r"Software: ([^\,]*)", details)) > 0:
                        if len(re.findall(r"Software: ([^\,]*)", details)[0]) > 1:
                            row = "{},{}".format(row, re.findall(r"Software: ([^\,]*)", re.sub(r"(S|G)\d+,?", r"", details))[0])
                        else:
                            row = "{},-".format(row)
                    else:
                        row = "{},-".format(row)
                else:
                    row = "{},-".format(row)
                if len(eachvalue.strip()) > 0:
                    row = "{},{},\n".format(row, eachvalue.strip())
                else:
                    row = "{},-,\n".format(row)
                if ",G0" not in row:
                    def convert_to_lower(capital_letter):
                        if capital_letter.group() is not None:
                            return capital_letter.group().lower()
                        else:
                            pass
                    row = re.sub(r"(\S)\. ([A-Za-z]{3} )", r"\1 \.\2", re.sub(r"([a-z]\-[A-Z])", convert_to_lower, re.sub(r"([a-z] \d\.) (\d\.? )", r"\1\2", re.sub(r"([a-z]\.)([A-Z])", r"\1 \2", re.sub(r"(\. )\. ([A-Z])", r"\1\2", re.sub(r"([a-z] ), ([a-z])", r"\1\2", re.sub(r"([a-z]\. )\. ([A-Z])", r"\1\2", re.sub(r"(\. )<h\d([A-Z])", r"\1\2", re.sub(r"([a-z] )\. (-)", r"\1\2", re.sub(r"([a-z]) (\. [A-Z])", r"\1\2", re.sub(r"([a-z]{2,})([A-Z]{2,})", r"\1 \2", re.sub(r"<h\d>[^\<]+</h\d>", r"", re.sub(r"<a.*\" target=\"_blank\">", r"", re.sub(r"<a href=\"https://attack\.mitre\.org/tactics/TA\d{4}\">", r"", re.sub(r"<a href=\"/techniques/", r"", re.sub(r"<a href=\"/software/S\d{4}\">", r"", re.sub(r"<a href=\"/techniques/T\d{4}/\d{3}\">", r"", re.sub(r"T\d{4}(/\d{3})?\">", r"", row.replace("\\\\","\\").replace("<div class=\"col-md-11 pl-0\"> ","").replace("  <div class=\"row card-data\"> ","").replace("<div class=\"col-md-1 px-0 text-center\"> ","").replace("</a>  ,",",").replace(".,;",".,").replace(";;",";").replace(". ,;",".,").replace(",;",",").replace("ä","a")))))))))))))))))))
                    row = row.replace(". exe",".exe").replace("'s","'s ").replace("'s  ","'s ").replace("\\\\s . ","'s .").replace("\\s . ","'s .").replace("\\\\s ","'s ").replace("\\s ","'s ").replace("\\\\ve ","'ve ").replace("\\ve","'ve ").replace("s's","s'").replace("; "," ").replace(" </li><,","").replace("</li><","").replace("\\ "," ").replace("<strong>","").replace("</strong>","").replace(" .,",".,").replace(" \" "," \"").replace("\\","\\\\").replace("\\\\\\\\","\\\\").replace("\\\\\\","\\\\").replace("  "," ").replace("(e. g. ","(e.g. ").replace("  , ",", ").replace(". ,",".,").replace(" . "," .").replace(";."," .").replace(";and"," and").replace(", .",",.").replace(" ,",".,")
                    row = row.replace("evil.txt ","evil.txt").replace("evil.txt","evil.txt  ").replace(" . NET"," .NET").replace(". Some specifics from in-the-wild use include:.,",".,").replace("re-os","re-OS").replace("setsuid","setuid").replace("SendNotifyMessageto ", "SendNotifyMessage to ").replace("GetWindowLongand ", "GetWindowLong and ").replace("Sectionbefore ", "Section before ").replace("OftenValid ","Often Valid ").replace("UnlikeCode ","Unlike Code ").replace("WindowsDynamic ","Windows Dynamic ").replace("orComponent ","or Component ").replace("ofComponent ","of Component ").replace("throughComponent ","through Component ").replace("UnlikeKeylogging ","Unlike Keylogging ").replace("UnlikeUpload ","Unlike Upload ").replace("UserUnix ","User Unix ").replace("inCloud ","in Cloud ").replace(". in AWS ","; in AWS ").replace(". in GCP ","; in GCP ").replace(". in Azure ","; in Azure ").replace("monitor for: google. logging. v2. ConfigServiceV2. UpdateSink","monitor for: google.logging.v2.ConfigServiceV2.UpdateSink")
                    row = re.sub(r"([a-z]\.)([A-Z])", r"\1 \2", re.sub(r" \\+(\.[A-Z])", r"\1", re.sub(r"( [a-z]+)([A-Z][a-z]+) ", r"\1 \2", re.sub(r"( [a-z]+)([A-Z][a-z]+) ", r"\1 \2", row))))
                    row = row.replace("\\\\","\\").replace(" \\\\.",".").replace(" \\.",".")
                    row = row.replace(" Through "," through ").replace(" Over "," over ").replace(" In "," in ").replace(" Or "," or ").replace(" From "," from ").replace(" To "," to ").replace(" For "," for ").replace(" The "," the ").replace(" And "," and ") # adjust MITRE techniques names in elrond to reflect these changes...
                    mitrecsv.write(row)
                else:
                    pass
        print("\n   -> Done - if you notice any errors anywhere in the output please log an issue on GitHub (https://github.com/ezaspy/collectMITRE/issues)\n\n")
if __name__ == '__main__':
	main()
