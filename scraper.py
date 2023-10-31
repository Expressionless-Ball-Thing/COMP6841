from io import TextIOWrapper
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Set
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import re
import json
import requests
import lxml

from page._common import SecScraper, WebPage
        
def analyze(url:str, debug:bool, cve: bool) -> Dict[str, Dict[str, Any]]:
    # Create SecScraper
    print("creating the scraper")
    secscraper: SecScraper = SecScraper.compile(debug)
    print("done")
    # Create WebPage        
    with sync_playwright() as p:
        chromium = p.chromium
        browser = chromium.launch(headless=True)
        page = browser.new_page()
        page.on("request", lambda request: secscraper.handle_request(request))
        page.on("response", lambda response: secscraper.handle_response(response))
        page.goto(url, wait_until="domcontentloaded")
        
        webpage = WebPage(url,page=page)
        
        # Analyze
        secscraper.analyze(webpage)


        # printing the expected output.
        outfile = open(f"analysis_output/analysis_results.json", "w")
        outfile.write(json.dumps(secscraper.get_results(), indent=4, sort_keys=True))
        outfile.close()
        
        # printing out the things the scraper can't make sense of
        make_no_sense = open(f"analysis_output/unknown.json", "w")
        make_no_sense.write(json.dumps(secscraper.cant_make_sense, indent=4, sort_keys=True))
        make_no_sense.close()
        
        # printing out all the servers this scraper contacted with
        servers = open(f"analysis_output/servers_and_security.json", "w")
        servers.write(json.dumps(secscraper.server_security, indent=4, sort_keys=True))
        servers.close()

        if (debug):
            html = open(f"analysis_output/html_full.html", "w", encoding='utf-8')
            html.write(webpage.parsed_html.prettify())
            html.close()
            secscraper.request_file.close()
            secscraper.response_file.close()

        if (cve):
            cve_list = {}
            for tech_name, tech in secscraper.get_results().items():
                response = requests.get(url="https://nvd.nist.gov/vuln/search/results", params={
                    "form_type": "Basic",
                    "results_type": "overview",
                    "query": tech["cpe"].split("*")[0] if tech["cpe"] is not None else tech_name,
                    "search_type": "all",
                    "isCpeNameSearch": False
                }, timeout=3)
                soup = BeautifulSoup(response.text, 'lxml')
                entries = [ {
                    "name" : entry.find('a').text, 
                    "description": entry.find('p').text, 
                    "published":  entry.find('span', attrs={"data-testid" : True}).text, 
                    "Severity": entry.find(id='cvss3-link').find('a').text if entry.find(id='cvss3-link') != None else "Not Available"}
                           for entry in soup.find_all('tr', attrs={"data-testid" : True})]
                if entries != []:
                    cve_list[tech_name] = entries
                
            cves = open(f"analysis_output/potential_vulnerabilities.json", "w")
            cves.write(json.dumps(cve_list, indent=4, sort_keys=True))
            cves.close()
        
        
        ### Links stuff
        on_site = set()
        internals =  set()
        externals = set()        
        for link in webpage.parsed_html.find_all('a'):
            if bool(re.compile("^#.*").match(link.attrs.get('href'))):
                on_site.add(link.attrs.get('href'))       
            elif url in link.attrs.get('href') or bool(re.compile("^/.*").match(link.attrs.get('href'))):
                internals.add(link.attrs.get('href'))     
            else:
                externals.add(link.attrs.get('href'))   

        site_links = open(f"analysis_output/site_links.json", "w")
        site_links.write(json.dumps({
            "on-site permalink": list(on_site),
            "internal link": list(internals),
            "external link": list(externals)
        }, indent=4, sort_keys=True))
        site_links.close()
        
        try:
            page.close()
            browser.close()
        except:
            pass