from io import TextIOWrapper
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Set
from playwright.sync_api import sync_playwright, Request, Response
from bs4 import BeautifulSoup
import re
import json
import requests
import lxml
from packaging import version
from fingerprint import Fingerprint, Pattern
from page._common import WebPage, Technology
import time 
class SecScraper:
    def __init__(self, technologies: List[Mapping[str, Fingerprint]], debug: bool):
        self.technologies: Mapping[str, Fingerprint] = technologies
        self.detected_technologies: Mapping[str, Technology] = {}
        self.seen_request_url = set()
        self.seen_response_url = set()
        self.debug: bool = debug
        
        self._confidence_regexp = re.compile(r"(.+)\\;confidence:(\d+)")
        self.server_security = []
        self.cant_make_sense = []
        
        self.requests = []
        self.responses = []

    @classmethod
    def compile(cls, debug:bool) -> 'SecScraper':
        """ 
            Get the technology folder, and load all the json in it.
        """
        techObject: Mapping[str, Fingerprint] = {}
        for entry in Path('technologies/').iterdir():
            f = open(entry.as_posix(), encoding='utf-8')
            obj = json.load(f)
            for k,v in obj.items():
                techObject[k] = Fingerprint(name=k, **v)
            f.close()
        
        return cls(techObject, debug)
        
    def debug_writeout(self, webpage: WebPage):
        html = open(f"analysis_output/html_full.html", "w", encoding='utf-8')
        html.write(webpage.parsed_html.prettify())
        html.close()
        request_file: TextIOWrapper = open(f"analysis_output/request.txt", "w")
        request_file.write(json.dumps(self.requests, sort_keys=True, indent=4))
        request_file.close()
        response_file: TextIOWrapper = open(f"analysis_output/response.txt", "w")
        response_file.write(json.dumps(self.responses, sort_keys=True, indent=4))
        response_file.close()


    def handle_request(self, request: Request):
        all_headers = request.all_headers()
        self.seen_request_url
        has_tech = False
        
        if (request.url not in self.seen_request_url):
            self.seen_request_url.add(request.url)        
            
            for tech_name, technology in list(self.technologies.items()):
                for name, patterns in list(technology.headers.items()):
                    if name in all_headers:
                        content = all_headers[name]
                        for pattern in patterns:
                            if pattern.regex.search(content):
                                self._set_detected_app(technology, f'Header in {request.method} request to {request.url} has key {name} and value {content}', pattern, value=content)
                                has_tech = True
        
        debug_obj = {
            "METHOD": request.method,
            "URL": request.url,
            "HEADERS": all_headers
        }
        if not has_tech:
            self.cant_make_sense.append(debug_obj)
        if (self.debug):
            self.requests.append(debug_obj)
            # self.request_file.write(json.dumps(debug_obj, indent=4, sort_keys=True))
            # self.request_file.write("\n")

    def handle_response(self, response: Response):  
        
        all_headers = response.all_headers()
        has_tech = False
        if (response.url not in self.seen_response_url):
            self.seen_response_url.add(response.url)
            
            for tech_name, technology in list(self.technologies.items()):
                for name, patterns in list(technology.headers.items()):
                    if name in all_headers:
                        content = all_headers[name]
                        for pattern in patterns:
                            if pattern.regex.search(content):
                                self._set_detected_app(technology, f'Header in response to {response.url} has key {name} and value {content}', pattern, value=content)
                                has_tech = True
            
            server_stuff = {
                "SECURITY": {key: value for key, value in response.security_details().items() if key not in ["validFrom" , "validTo"]},
                "SERVER": response.server_addr()
            }
            if (server_stuff not in self.server_security):
                self.server_security.append(server_stuff)
            
            debug_obj = {
                    "URL" : response.url,
                    "HEADERS": response.all_headers(),
                    "SECURITY": response.security_details(),
                    "SERVER": response.server_addr()
                }
            if not has_tech:
                self.cant_make_sense.append(debug_obj)     
            if self.debug:
                self.responses.append(debug_obj)                 

    def _has_technology(self, tech_fingerprint: Fingerprint, webpage: WebPage) -> bool:
        """
        Determine whether the web page matches the technology signature.
        """
        has_tech = False
        # analyze url patterns
        for pattern in tech_fingerprint.url:
            if pattern.regex.search(webpage.url):
                self._set_detected_app(tech_fingerprint, f'website url match regex {pattern.string}', pattern, value=webpage.url)
        for pattern in tech_fingerprint.scripts:
            for script in webpage.scripts:
                if pattern.regex.search(script):
                    self._set_detected_app(tech_fingerprint, f'script tag has content that match regex {pattern.string}', pattern, value=script)
                    has_tech = True
        
        for pattern in tech_fingerprint.scriptSrc:
            for script in webpage.scriptSrc:
                if pattern.regex.search(script):
                    self._set_detected_app(tech_fingerprint, f'script tag has src attribute that match regex {pattern.string}', pattern, value=script)
                    has_tech = True
                
        # analyze meta patterns
        for name, patterns in list(tech_fingerprint.meta.items()):
            if name in webpage.meta:
                content = webpage.meta[name]
                for pattern in patterns:
                    if pattern.regex.search(content):
                        self._set_detected_app(tech_fingerprint, f'meta tag has {name} attribute and it matches regex {pattern.string}', pattern, value=content)
                        has_tech = True
        # analyze html patterns
        for pattern in tech_fingerprint.html:
            if pattern.regex.search(webpage.html):
                self._set_detected_app(tech_fingerprint, f'html content matched regex {pattern.string}', pattern, value=webpage.html)
                has_tech = True
            # analyze dom patterns
            # css selector, list of css selectors, or dict from css selector to dict with some of keys:
            #           - "exists": "": only check if the selector matches somthing, equivalent to the list form. 
            #           - "text": "regex": check if the .innerText property of the element that matches the css selector matches the regex (with version extraction).
            #           - "attributes": {dict from attr name to regex}: check if the attribute value of the element that matches the css selector matches the regex (with version extraction).
        for selector in tech_fingerprint.dom:
            for item in webpage.select(selector.selector):
                if selector.exists:
                    self._set_detected_app(tech_fingerprint, f'There exist a dom element that matches regex {selector.selector}', Pattern(string=selector.selector), value='')
                    has_tech = True
                if selector.text:
                    for pattern in selector.text:
                        if pattern.regex.search(item.inner_html):
                            self._set_detected_app(tech_fingerprint, f'There is a dom element that matches selector {selector.selector} and its inner text match {pattern.string}', pattern, value=item.inner_html)
                            has_tech = True
                if selector.attributes:
                    for attrname, patterns in list(selector.attributes.items()):
                        _content = item.attributes.get(attrname)
                        if _content:
                            for pattern in patterns:
                                for content in _content:
                                    if pattern.regex.search(content):
                                        self._set_detected_app(tech_fingerprint, f'Dom element matches selector {selector.selector}, and it has attribute {attrname} with value {_content} that matches regex {pattern.string}', pattern, value=content)
                                        has_tech = True
        return has_tech

    def _set_detected_app(self, tech_fingerprint: Fingerprint, found_in: str, pattern: Pattern, value:str) -> None:

        # Lookup Technology object in the cache
        if tech_fingerprint.name not in self.detected_technologies:
            self.detected_technologies[tech_fingerprint.name] = Technology(tech_fingerprint.cpe)
        
        detected_tech = self.detected_technologies[tech_fingerprint.name]
        detected_tech.found_in.append(found_in)

        # Dectect version number
        if pattern.version:
            allmatches = re.findall(pattern.regex, value)
            for i, matches in enumerate(allmatches):
                version = pattern.version
                # Check for a string to avoid enumerating the string
                if isinstance(matches, str):
                    matches = [(matches)]
                for index, match in enumerate(matches):
                    # Parse ternary operator
                    ternary = re.search(re.compile('\\\\' + str(index + 1) + '\\?([^:]+):(.*)$', re.I), version)
                    if ternary and len(ternary.groups()) == 2 and ternary.group(1) is not None and ternary.group(2) is not None:
                        version = version.replace(ternary.group(0), ternary.group(1) if match != '' else ternary.group(2))
                    # Replace back references
                    version = version.replace('\\' + str(index + 1), match)
                if version != '' and version not in detected_tech.versions:
                    detected_tech.versions.append(version)
            self._sort_app_version(detected_tech)

    def _sort_app_version(self, detected_tech: Technology) -> None:
        if len(detected_tech.versions) >= 1:
            return
        detected_tech.versions = sorted(detected_tech.versions, key= lambda version_num: version.parse(version_num))

    def _get_implied_technologies(self, detected_technologies:Iterable[str]) -> Iterable[str]:
        def __get_implied_technologies(technologies:Iterable[str]) -> Iterable[str] :
            _implied_technologies = set()
            for tech in technologies:
                try:
                    for imply in self.technologies[tech].implies:
                        # If we have no doubts just add technology
                        if 'confidence' not in imply:
                            _implied_technologies.add(imply)

                        # Case when we have "confidence" (some doubts)
                        else:
                            try:
                                # Use more strict regexp (cause we have already checked the entry of "confidence")
                                # Also, better way to compile regexp one time, instead of every time
                                app_name, confidence = self._confidence_regexp.search(imply).groups()
                                if int(confidence) >= 50:
                                    _implied_technologies.add(app_name)
                            except (ValueError, AttributeError):
                                pass
                except KeyError:
                    pass
            return _implied_technologies

        implied_technologies = __get_implied_technologies(detected_technologies)
        all_implied_technologies : Set[str] = set()

        # Descend recursively until we've found all implied technologies
        while not all_implied_technologies.issuperset(implied_technologies):
            all_implied_technologies.update(implied_technologies)
            implied_technologies = __get_implied_technologies(all_implied_technologies)

        return all_implied_technologies

    def analyze(self, webpage:WebPage) -> Set[str]:
        for tech_name, technology in list(self.technologies.items()):
            self._has_technology(technology, webpage)

    def get_results(self) -> Dict[str, Dict[str, Any]]:
        
        detected_tech = set(self.detected_technologies.keys())
        implied_tech = self._get_implied_technologies(detected_tech)
        versioned_tech = {}
        implied_tech_dict = {}

        for tech in detected_tech:
            versioned_tech[tech] = {
                "cpe" : self.detected_technologies[tech].cpe,
                "versions" :  self.detected_technologies[tech].versions,
                "found in": self.detected_technologies[tech].found_in if self.detected_technologies[tech] is not [] else "implied"
            }
        
        for tech in implied_tech:
            implied_tech_dict[tech] = self.technologies[tech].cpe if self.technologies[tech].cpe is not None else ""
            
        return versioned_tech | implied_tech_dict        
        
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
            secscraper.debug_writeout(webpage)

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
            # page.remove_listener("request", lambda request: secscraper.handle_request(request))
            # page.remove_listener("response", lambda response: secscraper.handle_response(response))
            page.close()
            browser.close()
        except:
            pass