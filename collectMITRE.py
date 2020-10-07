#!/usr/bin/env python3 -tt
import urllib.request, ssl, re, time, sys
from bs4 import BeautifulSoup

def main():
    def doCollect(eachid):
        techniquecard, cards = str(str((BeautifulSoup(urllib.request.urlopen("https://attack.mitre.org/techniques/{}/".format(eachid)).read(),"html.parser").find_all())).replace("\\n","\n").replace("\n","\\n").split("<div class=\"col-md-4\">\\n<div class=\"card\">\\n<div class=\"card-body\">\\n<div class=\"card-data\" id=\"card-id\">")[1]).split("</div>\\n</div>\\n</div>\\n<div class=\"text-center pt-2 version-button live\">\\n<div class=\"live\">")[0], []
        try:
            for line in str(str(str(BeautifulSoup(urllib.request.urlopen("https://attack.mitre.org/techniques/{}/".format(eachid)).read(),"html.parser").find_all("table"))[1:-1]).split("</tbody>")[1]).split("\n"):
                if line.startswith("<a href=\"/groups/G"):
                    tas.append(re.sub(r"<a href=\"/groups/G\d{4}\"> ", r"", line[0:-5]))
                else:
                    pass
        except:
            pass
        for eachcard in techniquecard.replace("Tactics","Tactic").replace("  ","").replace("class=\"h5 card-title\">","").replace("</span>","").replace("\\n<div class=\"card-","").replace("\\n<!--start-indexing-for-search-->","").replace("\\n<!--stop-indexing-for-search-->","").replace("</div>data\" id=\"card-","").replace("</div>data\">","").replace("id\">","").replace("</a>\\ntactics\">","").replace("platforms\">","").replace("</div>","").replace("\\n"," ").replace(", ",",").split("<span ")[1:]:
            cards.append(eachcard)
        collectedtechniques.append(str(str(re.sub(r"T\d{4}\">(T\d{4}\')", r"\1", str(cards).replace("\\xa0"," ").replace(" <a href=\"/techniques/","")[1:-1])))+"||||"+str(tas))
    ssl._create_default_https_context = ssl._create_unverified_context
    techniquestable, entries = str(BeautifulSoup(urllib.request.urlopen("https://attack.mitre.org/techniques/enterprise/").read(),"html.parser").find_all("table"))[1:-1], {}
    for techniques in techniquestable.split("<tr class=\"technique\">")[1:]:
        mitreid, subtechniques, collectedtechniques, tas = str(str(re.sub(r"/techniques/T\d+\">( )", r"\1", str(re.sub(r"<code>([^\<]+)</code>", r"\1", (techniques.replace("<td>\n</td>","<td></td>").replace("<td></td>","").replace("\n<td>","").replace("</td>","").replace("</tr>","").replace("                            ","").replace("                        ","").replace("                    ","").replace(". . ",". ").replace(" </a>","<a href=\"").replace("\n<td colspan=\"2\">","").replace("\n","").replace("<a href=\"<a href=\"","<a href=\"")))).split("<a href=\"")[1]))).strip(), str(re.sub(r"<code>([^\<]+)</code>", r"\1", (techniques.replace("<td>\n</td>","<td></td>").replace("<td></td>","").replace("\n<td>","").replace("</td>","").replace("</tr>","").replace("                            ","").replace("                        ","").replace("                    ","").replace(". . ",". ").replace(" </a>","<a href=\"").replace("\n<td colspan=\"2\">","").replace("\n","").replace("<a href=\"<a href=\"","<a href=\"")))), [], []
        doCollect(mitreid)
        for eachsub in subtechniques.split("<a href=\"")[4:]:
            subid = str(re.sub(r"/techniques/T\d+/\d+\">( )", r"\1", str(eachsub.replace("<tr class=\"sub technique\">","").strip()))).strip()
            if subid.startswith(".0"):
                doCollect(str(mitreid)+"/"+str(subid.strip(".")))
            else:
                pass
            for eachtechnique in collectedtechniques:
                for eachtactic in str(eachtechnique.split("'Tactic: ")[1]).split("'")[0].split(","):
                    for eachplatform in str(eachtechnique.split("'Platforms: ")[1]).split("'")[0].split(","):
                        key, value = str(re.sub(r"(CAPEC ID: )<a href=\"https://capec.mitre.org/data/definitions/\d+.html\" target=\"_blank\">(CAPEC-\d+)</a> ,", r"\1\2", str(eachtechnique.split(", 'Tactic: ")[0]+", 'Tactic: "+eachtactic+"', 'Platforms: "+eachplatform+", "+str(str(eachtechnique.split("'Platforms: ")[1]).split("'")[1:]).replace("', ', ', '",", ").replace("', ', ","").replace("', '","")[1:-3]).replace("'",""))).split("||||")
                        entries[key] = value
    with open("mitre.csv", "a") as mitrecsv:
        mitrecsv.write("subid,id,tactic,platform,permissions_required,effective_permissions,data_sources,defense_bypassed,version,created,last_modified,threat_actor\n")
        for k, v in entries.items():
            details = str(str(re.sub(r"T\d{4}/\d{3}\">T\d{4}\.\d{3}</a>", r"", re.sub(r"T\d{4}\.\d{3}</a>,<a href=\"/techniques/T\d{4}/\d{3}\">", r"", k))).replace(" tactics\">","").replace(", Sub-techniques: , ",", ").replace(", Sub-techniques:  No sub-techniques, ",", ").replace(", ","<>").replace(",",";").replace("<>",","))
            for eachvalue in v.replace("'","").replace("[","").replace("]","").strip().split(", "):
                print(details)
                time.sleep(4)
                row = re.findall(r"^ID: (T[^\,]+)\,", details)[0]
                if "Sub-technique of:" in details:
                    row = "{},{}".format(row, str(re.findall(r"Sub-technique of: (T[^\,]+)\,", details)[0]))
                else:
                    row = "{},-".format(row)
                row = "{},{}".format(row, re.findall(r"Tactic: ([^\,]+)\,", details)[0])
                row = "{},{}".format(row, re.findall(r"Platforms: ([^\,]+)\,", details)[0])
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
                if len(eachvalue.strip()) > 0:
                    row = "{},{}\n".format(row, eachvalue.strip())
                else:
                    row = "{},-\n".format(row)
                print(row)
                mitrecsv.write(row)

if __name__ == '__main__':
	main()
