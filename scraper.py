from io import TextIOWrapper
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import re
import json

from fingerprint import Fingerprint, Pattern

seen_url_requests = set()
seen_url_responses = set()

tech_object = json.load(open("technologies.json", "r"))
tech_found = {}

server_security = []

cant_make_sense = []

class Technology:
    def __init__(self, name:str) -> None:
        self.name = name
        self.confidence: Dict[str, int] = {}
        self.versions: List[str] = []
    
    @property
    def confidenceTotal(self) -> int: 
        total = 0
        for v in self.confidence.values():
            total += v
        return total


class SecScraper:

    def __init__(self, technologies:Dict[str, Any]):
        self.technologies: Mapping[str, Fingerprint] = {k:Fingerprint(name=k, **v) for k,v in technologies.items()}
        self.detected_technologies: Dict[str, Dict[str, Technology]] = {}

        self._confidence_regexp = re.compile(r"(.+)\\;confidence:(\d+)")

    @classmethod
    def compile(cls) -> 'SecScraper':

        """ 
            Get the technology folder, and load all the json in it.
        """
        techlist = []
        for entry in Path('technologies/').iterdir():
            with open( f'technologies/{str(entry)}', 'r', encoding='utf-8') as file_content:
                print(json.loads(file_content))
                # {k:Fingerprint(name=k, **v) for k,v in json.loads(file_content).items()}

        
        return cls()

    def _has_technology(self, tech_fingerprint: Fingerprint, webpage: IWebPage) -> bool:
        """
        Determine whether the web page matches the technology signature.
        """

        has_tech = False
        # Search the easiest things first and save the full-text search of the
        # HTML for last

        # analyze url patterns
        for pattern in tech_fingerprint.url:
            if pattern.regex.search(webpage.url):
                self._set_detected_app(webpage.url, tech_fingerprint, 'url', pattern, value=webpage.url)
        # analyze headers patterns
        for name, patterns in list(tech_fingerprint.headers.items()):
            if name in webpage.headers:
                content = webpage.headers[name]
                for pattern in patterns:
                    if pattern.regex.search(content):
                        self._set_detected_app(webpage.url, tech_fingerprint, 'headers', pattern, value=content, key=name)
                        has_tech = True
        # analyze scripts patterns
        for pattern in tech_fingerprint.scripts:
            for script in webpage.scripts:
                if pattern.regex.search(script):
                    self._set_detected_app(webpage.url, tech_fingerprint, 'scripts', pattern, value=script)
                    has_tech = True
        # analyze meta patterns
        for name, patterns in list(tech_fingerprint.meta.items()):
            if name in webpage.meta:
                content = webpage.meta[name]
                for pattern in patterns:
                    if pattern.regex.search(content):
                        self._set_detected_app(webpage.url, tech_fingerprint, 'meta', pattern, value=content, key=name)
                        has_tech = True
        # analyze html patterns
        for pattern in tech_fingerprint.html:
            if pattern.regex.search(webpage.html):
                self._set_detected_app(webpage.url, tech_fingerprint, 'html', pattern, value=webpage.html)
                has_tech = True
        # analyze dom patterns
        # css selector, list of css selectors, or dict from css selector to dict with some of keys:
        #           - "exists": "": only check if the selector matches somthing, equivalent to the list form. 
        #           - "text": "regex": check if the .innerText property of the element that matches the css selector matches the regex (with version extraction).
        #           - "attributes": {dict from attr name to regex}: check if the attribute value of the element that matches the css selector matches the regex (with version extraction).
        for selector in tech_fingerprint.dom:
            for item in webpage.select(selector.selector):
                if selector.exists:
                    self._set_detected_app(webpage.url, tech_fingerprint, 'dom', Pattern(string=selector.selector), value='')
                    has_tech = True
                if selector.text:
                    for pattern in selector.text:
                        if pattern.regex.search(item.inner_html):
                            self._set_detected_app(webpage.url, tech_fingerprint, 'dom', pattern, value=item.inner_html)
                            has_tech = True
                if selector.attributes:
                    for attrname, patterns in list(selector.attributes.items()):
                        _content = item.attributes.get(attrname)
                        if _content:
                            for pattern in patterns:
                                if pattern.regex.search(_content):
                                    self._set_detected_app(webpage.url, tech_fingerprint, 'dom', pattern, value=_content)
                                    has_tech = True
        return has_tech

    def _set_detected_app(self, url:str, tech_fingerprint: Fingerprint, app_type:str, pattern: Pattern, value:str, key='') -> None:
        # Lookup Technology object in the cache
        if url not in self.detected_technologies:
            self.detected_technologies[url] = {}
        if tech_fingerprint.name not in self.detected_technologies[url]:
            self.detected_technologies[url][tech_fingerprint.name] = Technology(tech_fingerprint.name)
        detected_tech = self.detected_technologies[url][tech_fingerprint.name]

        # Set confidence level
        if key != '': key += ' '
        match_name = app_type + ' ' + key + pattern.string
        
        detected_tech.confidence[match_name] = pattern.confidence

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
                        version = version.replace(ternary.group(0), ternary.group(1) if match != ''
                                                  else ternary.group(2))
                    # Replace back references
                    version = version.replace('\\' + str(index + 1), match)
                if version != '' and version not in detected_tech.versions:
                    detected_tech.versions.append(version)
            self._sort_app_version(detected_tech)

    def _sort_app_version(self, detected_tech: Technology) -> None:
        """
        Sort version number (find the longest version number that *is supposed to* contains all shorter detected version numbers).
        """
        if len(detected_tech.versions) >= 1:
            return
        detected_tech.versions = sorted(detected_tech.versions, key=self._cmp_to_key(self._sort_app_versions))

    def _get_implied_technologies(self, detected_technologies:Iterable[str]) -> Iterable[str]:
        def __get_implied_technologies(technologies:Iterable[str]) -> Iterable[str] :
            _implied_technologies = set()
            for tech in technologies:
                try:
                    for implie in self.technologies[tech].implies:
                        # If we have no doubts just add technology
                        if 'confidence' not in implie:
                            _implied_technologies.add(implie)

                        # Case when we have "confidence" (some doubts)
                        else:
                            try:
                                # Use more strict regexp (cause we have already checked the entry of "confidence")
                                # Also, better way to compile regexp one time, instead of every time
                                app_name, confidence = self._confidence_regexp.search(implie).groups() # type: ignore
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

    def get_categories(self, tech_name:str) -> List[str]:
        cat_nums = self.technologies[tech_name].cats if tech_name in self.technologies else []
        cat_names = [self.categories[str(cat_num)].name
                     for cat_num in cat_nums if str(cat_num) in self.categories]
        return cat_names

    def get_versions(self, url:str, app_name:str) -> List[str]:
        try:
            return self.detected_technologies[url][app_name].versions
        except KeyError:
            return []

    def get_confidence(self, url:str, app_name:str) -> Optional[int]:
        try:
            return self.detected_technologies[url][app_name].confidenceTotal
        except KeyError:
            return None

    def analyze(self, webpage:IWebPage) -> Set[str]:
        detected_technologies = set()

        for tech_name, technology in list(self.technologies.items()):
            if self._has_technology(technology, webpage):
                detected_technologies.add(tech_name)

        detected_technologies.update(self._get_implied_technologies(detected_technologies))

        return detected_technologies

    def analyze_with_versions(self, webpage:IWebPage) -> Dict[str, Dict[str, Any]]:
        detected_apps = self.analyze(webpage)
        versioned_apps = {}

        for app_name in detected_apps:
            versions = self.get_versions(webpage.url, app_name)
            versioned_apps[app_name] = {"versions": versions}

        return versioned_apps

    def analyze_with_versions_and_categories(self, webpage:IWebPage) -> Dict[str, Dict[str, Any]]:
        versioned_apps = self.analyze_with_versions(webpage)
        versioned_and_categorised_apps = versioned_apps

        for app_name in versioned_apps:
            cat_names = self.get_categories(app_name)
            versioned_and_categorised_apps[app_name]["categories"] = cat_names

        return versioned_and_categorised_apps

    def _sort_app_versions(self, version_a: str, version_b: str) -> int:
        return len(version_a) - len(version_b)

    def _cmp_to_key(self, mycmp: Callable[..., Any]):
        """
        Convert a cmp= function into a key= function
        """

        # https://docs.python.org/3/howto/sorting.html
        class CmpToKey:
            def __init__(self, obj, *args):
                self.obj = obj

            def __lt__(self, other):
                return mycmp(self.obj, other.obj) < 0

            def __gt__(self, other):
                return mycmp(self.obj, other.obj) > 0

            def __eq__(self, other):
                return mycmp(self.obj, other.obj) == 0

            def __le__(self, other):
                return mycmp(self.obj, other.obj) <= 0

            def __ge__(self, other):
                return mycmp(self.obj, other.obj) >= 0

            def __ne__(self, other):
                return mycmp(self.obj, other.obj) != 0

        return CmpToKey



def handle_request(request, request_file: TextIOWrapper, debug):
    
    all_headers = request.all_headers()
    hit = False
    
    if (request.url not in seen_url_requests):
        seen_url_requests.add(request.url)        
        
        for tech_name, object in tech_object.items():
            if "headers" in object.keys(): 
                headers: dict = object["headers"]
                for header_name, header_identifier in headers.items():
                    if header_name in all_headers:
                        for regex_version_pair in header_identifier:
                            if re.search(regex_version_pair["regex"], all_headers[header_name]):
                                # adding it into the tech database
                                hit = True
                                if tech_name not in tech_found:
                                    tech_found[tech_name] = {
                                        "found in": [f"Header in {request.method} request to {request.url}"]
                                    }
                                else:
                                    tech_found[tech_name]["found in"].append(f"Header in {request.method} request to {request.url}")           
                            
        
        debug_obj = {
            "METHOD": request.method,
            "URL": request.url,
            "HEADERS": request.all_headers()
        }
          
        if not hit:
            cant_make_sense.append(debug_obj)     
          
        if (debug):
            request_file.write(json.dumps(debug_obj, indent=4, sort_keys=True))
            request_file.write("\n")

        
def handle_response(response, response_file: TextIOWrapper, debug):   
    
    all_headers = response.all_headers()
    hit = False
    if (response.url not in seen_url_responses):
        seen_url_responses.add(response.url)
        
        for tech_name, object in tech_object.items():
            if "headers" in object.keys(): 
                headers: dict = object["headers"]
                for header_name, header_identifier in headers.items():
                    if header_name in all_headers:
                        for regex_version_pair in header_identifier:
                            if re.search(regex_version_pair["regex"], all_headers[header_name]):
                                # adding it into the tech database
                                hit = True
                                if tech_name not in tech_found:
                                    
                                    tech_found[tech_name] = {
                                        "found in": [f"Header in response to {response.url}"]
                                    }
                                else:
                                    tech_found[tech_name]["found in"].append(f"Header in response to {response.url}") 
        
        server_stuff = {
            "SECURITY": {key: value for key, value in response.security_details().items() if key not in ["validFrom" , "validTo"]},
            "SERVER": response.server_addr()
        }
        
        if (server_stuff not in server_security):
            server_security.append(server_stuff)
        
        
        debug_obj = {
                "URL" : response.url,
                "HEADERS": response.all_headers(),
                "SECURITY": response.security_details(),
                "SERVER": response.server_addr()
            }
          
        if not hit:
            cant_make_sense.append(debug_obj)     
        
        if debug:
            response_file.write(json.dumps(debug_obj, indent=4, sort_keys=True))
            response_file.write("\n")

def potential_cves(tech_found):
    

    
    pass

"""
    Run the tech list through the scripts, meta_tags and links and see if anything match here.
"""
def process_tags(scripts, meta_tags, link_tags):
    
    hit_set = set()
    
    for tech_name, object in tech_object.items():
        if "scriptSrc" in object:
            for regex_version_pair in object['scriptSrc']:
                for script in scripts:
                    if 'src' in script.attrs and re.search(regex_version_pair["regex"], script.attrs.get('src')):
                        hit_set.add(script)
                        if tech_name not in tech_found:
                                    
                            tech_found[tech_name] = {
                                        "found in": [f"<script> tag with src attribute {script.attrs.get('src')} matched pattern {regex_version_pair["regex"]}"]
                                    }
                        else:
                            tech_found[tech_name]["found in"].append(f"<script> tag with src attribute {script.attrs.get('src')} matched pattern {regex_version_pair["regex"]}") 
    
        if "meta" in object:
            metas: dict = object["meta"]
            for meta_name, meta_identifiers in metas.items():
                for meta in meta_tags:
                    if meta_name in meta.attrs:
                        for regex_version_pair in meta_identifiers:
                            if meta_name in meta.attrs and re.search(regex_version_pair["regex"], meta.attrs.get(meta_name)):
                                # adding it into the tech database
                                hit_set.add(meta)
                                if tech_name not in tech_found:
                                    
                                    tech_found[tech_name] = {
                                        "found in": [f"a meta tag with {meta_name} attribute and value of {meta.attrs.get(meta_name)}"]
                                    }
                                else:
                                    tech_found[tech_name]["found in"].append(f"a meta tag with {meta_name} attribute and value of {meta.attrs.get(meta_name)}") 
        
        if "link" in object:
            links: dict = object["link"]
            for link_attribute, link_identifiers in links.items():
                for link in link_tags:
                    if link_attribute in link.attrs:
                        for regex_version_pair in link_identifiers:
                            if link_attribute in link.attrs and re.search(regex_version_pair["regex"], link.attrs.get(link_attribute)):
                                # adding it into the tech database
                                hit_set.add(link)
                                if tech_name not in tech_found:
                                    
                                    tech_found[tech_name] = {
                                        "found in": [f"a link tag with {link_attribute} attribute and value of {link.attrs.get(link_attribute)}"]
                                    }
                                else:
                                    tech_found[tech_name]["found in"].append(f"a link tag with {link_attribute} attribute and value of {link.attrs.get(link_attribute)}") 

    cant_make_sense.append([script.attrs for script in (set(scripts) - hit_set)])
    cant_make_sense.append([meta.attrs for meta in (set(meta_tags) - hit_set)])
    cant_make_sense.append([link.attrs for link in (set(link_tags) - hit_set)])

                        

def scraper(url, debug):
    
    debug_outfile: TextIOWrapper = None
    request_file: TextIOWrapper = None
    response_file: TextIOWrapper = None
    
    if (debug):
        debug_outfile = open(f"analysis_output/output.txt", "w")
        request_file = open(f"analysis_output/request.txt", "w")
        request_file.write("\n-------------------------------------REQUESTS---------------------------------------\n")   
        response_file = open(f"analysis_output/response.txt", "w")
        response_file.write("\n-------------------------------------RESPONSES---------------------------------------\n") 
    
    
    try:
        print("loading in the tech database")
        print("done loading")
    except:
        print("oh no, seems like something was wrong with the tec_object")
        return
    
    with sync_playwright() as playwright:
        chromium = playwright.chromium
        browser = chromium.launch(headless=True)
        page = browser.new_page()
        
        """ 
        Getting the items
        """

        # Subscribe to "request" and "response" events.
        
        page.on("request", lambda request: handle_request(request, request_file, debug))
        page.on("response", lambda response: handle_response(response, response_file, debug))
        page.goto(url)
        
        # Use Beautiful to parse down all of the html
        html = BeautifulSoup(page.content(), 'html.parser')
        
        # Check that it actually loaded a page
        if not bool(html.find('html')):
            print("The page does not exist, it doesn't have a <html> tag")
            return
        
        # get scripts, meta, anchors, links
        scripts = list(html.find_all('script'))
        meta_tags = list(html.find_all("meta"))
        anchors = list(html.find_all("a"))  
        link_tags = list(html.find_all('link'))  

        process_tags(scripts, meta_tags, link_tags)


        if (debug):
        # Scanning the scripts for their source and id tag
            debug_outfile.write("\n-------------------------------------SCRIPT TAG----------------------------------------\n")
            for script in scripts:
                debug_outfile.write(json.dumps(script.attrs, indent=4, sort_keys=True))
                debug_outfile.write("\n")
            
            debug_outfile.write("\n-------------------------------------META----------------------------------------\n")
            for meta in meta_tags: 
                debug_outfile.write(json.dumps(meta.attrs, indent=4, sort_keys=True))
                debug_outfile.write("\n")
                
            debug_outfile.write("\n-------------------------------------LINK----------------------------------------\n")
            # Same thing, but now for meta tags
            for link in link_tags: 
                debug_outfile.write(json.dumps(link.attrs, indent=4, sort_keys=True))
                debug_outfile.write("\n")

            debug_outfile.write("\n-------------------------------------ANCHORS---------------------------------------\n")
            # Same thing, but not for anchor tags
            for link in anchors:
                link_json = {"href" : link.attrs.get('href'), "rel": link.attrs.get('rel')}
                if bool(re.compile("^#.*").match(link.attrs.get('href'))):
                    link_json["type"] = "on-site permalink"            
                elif url in link.attrs.get('href'):
                    link_json["type"] = "internal link"     
                else:
                    link_json["type"] = "external link"  
                debug_outfile.write(json.dumps(link_json, indent=4, sort_keys=True))
                debug_outfile.write("\n")

        print("Scraping done, you can now find the outputs in the analysis_output folder")

        # printing the expected output.
        outfile = open(f"analysis_output/output.json", "w")
        outfile.write(json.dumps(tech_found, indent=4, sort_keys=True))
        outfile.close()
        
        # printing out the things the scraper can't make sense of
        make_no_sense = open(f"analysis_output/unknown.json", "w")
        make_no_sense.write(json.dumps(cant_make_sense, indent=4, sort_keys=True))
        make_no_sense.close()
        
        # printing out all the servers this scraper contacted with
        servers = open(f"analysis_output/servers_and_security.json", "w")
        servers.write(json.dumps(server_security, indent=4, sort_keys=True))
        servers.close()

        try:
            page.close()
            browser.close()
            debug_outfile.close()
            request_file.close()
            response_file.close()
        except:
            pass
        
def analyze(url:str, update:bool=False, useragent:str=None, timeout:int=10, verify:bool=True) -> Dict[str, Dict[str, Any]]:
    # Create Wappalyzer
    wappalyzer=Wappalyzer.latest(update=update)
    # Create WebPage
    headers={}
    if useragent:
        headers['User-Agent'] = useragent
    webpage=WebPage.new_from_url(url, 
        headers=headers, 
        timeout=timeout, 
        verify=verify)
    # Analyze
    results = wappalyzer.analyze_with_versions_and_categories(webpage)
    return results