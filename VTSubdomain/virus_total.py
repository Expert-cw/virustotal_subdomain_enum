import requests 
from bs4 import BeautifulSoup
import json
from pprint import pprint
import outputformat as ouf

ouf.bigtitle("VirusTotal subdomain enum")
all_subdomains=[]
burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0", "Accept": "application/json", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Referer": "https://www.virustotal.com/", "Content-Type": "application/json", "X-Tool": "vt-ui-main", "X-App-Version": "v1x135x0", "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8", "X-Vt-Anti-Abuse-Header": "MTY1MTQwODE2NjAtWkc5dWRDQmlaU0JsZG1scy0xNjY5MTgzMzU3LjA3Mw==", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "Te": "trailers"}




domain = input("Enter domain name:  ")
if str(domain).find('http://') > 0:
    domain = str(domain).replace('http://','')
elif str(domain).find('https://') > 0:
    domain = str(domain).replace('https://','')    
burp0_url = "https://www.virustotal.com:443/ui/domains/"+str(domain)+"/subdomains?relationships=resolutions"
req=requests.get(burp0_url, headers=burp0_headers)
json_data=json.loads(req.text)
subdomain_count = json_data['meta']['count']
for i in json_data['data']:
    all_subdomains.append(str(i['relationships']['resolutions']['links']['related']).replace('https://www.virustotal.com/ui/domains/','').replace('/resolutions',''))


if 'next' in json_data['links']:
    link=str(json_data['links']['next'])
    while True:
        req=requests.get(link, headers=burp0_headers)
        json_data_all_subdomain=json.loads(req.text)
        for i in json_data_all_subdomain['data']:
            all_subdomains.append(str(i['relationships']['resolutions']['links']['related']).replace('https://www.virustotal.com/ui/domains/','').replace('/resolutions',''))
        if 'next' in json_data_all_subdomain['links']:
            link = str(json_data_all_subdomain['links']['next'])
        else:
            break    



for domain in all_subdomains:
    print(domain)       