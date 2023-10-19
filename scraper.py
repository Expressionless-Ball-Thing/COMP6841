from io import TextIOWrapper
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import re
import json

seen_url_requests = set()
seen_url_responses = set()

tech_object = json.load(open("technologies.json", "r"))
tech_found = {}

server_security = []

cant_make_sense = []



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