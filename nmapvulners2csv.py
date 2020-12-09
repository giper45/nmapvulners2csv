from xml.etree import ElementTree
import csv
import fire
import requests
from time import sleep
from bs4 import BeautifulSoup
from os import path




OUTPUT_DIR = "output"
CSV_HEADERS = ['host', 'port', 'protocol', 'cpe', 'id_vuln', 'cvss', 'type', 'exploit', 'url', 'description']
VULNERS_URL= "https://vulners.com/"




vulners_base = lambda t: "{}{}".format(VULNERS_URL, t)
vulners_endpoint = lambda t,id: "{}/{}".format(vulners_base(t), id)

def info(msg):
    print("[+] {}".format(msg))

def err(msg):
    print("[-] ERR:{}".format(msg))

def download_descr(type, id):
    ve = vulners_endpoint(type, id)
    ret = requests.get(ve)
    return ret.text
    # print(r.html.xpath("/html/body[@class='vulners-item-description']"))

def obtain_descr(text):
    html = "".join(text)
    soup = BeautifulSoup(html, 'html.parser')
    meta_descr = soup.select('meta[property="og:description"]')[0]
    return meta_descr['content']




def is_open(p):
    state = p.find("state")
    return state.attrib['state'] == "open"

def get_cpe(p):
    return p.find("service").find("cpe").text if p.find("service").find("cpe") is not None else ""

def get_vulns(p):
    script = p.find("script[@id='vulners']")
    if script is None:
        return []
    else: 
        t = script.find("table")
        vulns = []
        tables = t.findall('table')
        for t in tables:
            vuln = { 'id': t.find("elem[@key='id']").text,
                'cvss': t.find("elem[@key='cvss']").text,
                'exploit': t.find("elem[@key='is_exploit']").text, 
                'type': t.find("elem[@key='type']").text,
            }
            vuln['url'] = vulners_endpoint(vuln['type'], vuln['id'])
            vulns.append(vuln)
        return vulns


def get(host, descr=False):
    ports = host.findall('ports//port')
    open_ports = [p for p in ports if is_open(p)]
    evidences = []
    
    for p in open_ports:
        vulns = get_vulns(p)
        cpe = get_cpe(p)
        for v in vulns:
            # To avoid vulners block, tbd resend logic
            if descr:
                sleep(0.2)
        # CSV_HEADERS = ['host', 'port', 'cpe', 'cvss', 'id_vuln', 'type', 'exploit']
            info("get {}".format(v['id']))
            evidence = {
                'host': host.find("address").attrib['addr'],
                'port': p.attrib['portid'],
                'protocol': p.attrib['protocol'],
                'cpe': cpe,
                'id_vuln':  v['id'],
                'cvss' : v['cvss'],
                'type' : v['type'], 
                'exploit' : v['exploit'],
                'url':  v['url'],
                'description': obtain_descr(download_descr(v['type'], v['id'])) if descr else ""
            }
            evidences.append(evidence)
    return evidences


    return open_ports
def process(nmap_xml_file, output = 'output.csv', descr = False):
    """
    Convert a xml nmap output file in csv file
    Example usage:
    --get_descr

    """
    if descr:
        info("Description enabled: send requests to obtain vunerability descriptoins")
    info("Open xml")
    document = ElementTree.parse(nmap_xml_file)
    info("Obtain hosts")
    hosts = document.findall('host')
    info("Found hosts: {}".format(len(hosts)))
    evidences = []
    for sh in hosts:
        evidences.extend(get(sh, descr))
    info("Found evidences: {}".format(len(evidences)))
    with open(path.join(OUTPUT_DIR, output),  'w', encoding='utf-8', newline='') as csvfile:
        info("Store evidences")
        writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADERS)
        writer.writeheader()
        writer.writerows(evidences)
    pass

if __name__ == '__main__':
    try:
        fire.Fire(process)
    except Exception as e:
        err(str(e))