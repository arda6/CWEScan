import subprocess
import xml.etree.ElementTree as xml
import requests
from bs4 import BeautifulSoup as bs
import os 

print("""
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| |0|x|4|7| |0|x|4|F| |0|x|4|B| |0|x|4|3| |0|x|4|5| |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

""")

site = input("[+] Target ")
port = str(input("[+] Target Port "))
print("[+] Selected Target " +site)

subprocess.check_output(["nmap","-sV","-Pn",site,"-p"+port,"-oX","sonuc.xml"])
def xmlparse():
    data = xml.parse("sonuc.xml")
    for ver in data.iter("cpe"):
        print("[+] Target Using "+ver.text)
        cwe = ver.text
        wr = open("gkc.txt","w")
        wr.write(cwe)
    print("\n")
    op = open("gkc.txt","r")
    op = op.read()
    sp = len(op)
    sp = sp + 37
    sc = requests.get("https://www.nist.gov/fusion-search?s="+op,headers={"User-Agent":"Chrome-Windows"})
    source = bs(sc.content,"lxml")
    source = source.find_all("div",attrs={"class","text-green"})
    for link in source:
        print(sp*"-")
        link = link.text
        print(link)
        print(sp * "-")

xmlparse()

os.remove("gkc.txt")
print("[+] Scan Finished")
