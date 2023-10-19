from io import TextIOWrapper
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import re
import json


seen_url_requests = set()
seen_url_responses = set()

tech_object = {}

"""
    This functions just load the technologies.json file.
"""
def load_tech_database() -> dict:
    return json.load(open("technologies.json", "r"))

def handle_request(request, request_file, debug):
    if (request.url not in seen_url_requests):
        seen_url_requests.add(request.url)  
        if (debug):
            request_file.write(json.dumps({
                "METHOD": request.method,
                "URL": request.url,
                "HEADERS": request.all_headers()
            }, indent=4, sort_keys=True))
            request_file.write("\n")
        
def handle_response(response, response_file, debug):   
    if (response.url not in seen_url_responses):
        seen_url_responses.add(response.url)
        if debug:
            response_file.write(json.dumps({
                "URL" : response.url,
                "HEADERS": response.all_headers(),
                "SECURITY": response.security_details(),
                "SERVER": response.server_addr()
            }, indent=4, sort_keys=True))
            response_file.write("\n")

def scraper(url, debug):
    
    outfile: TextIOWrapper = None
    request_file: TextIOWrapper = None
    response_file: TextIOWrapper = None
    
    if (debug):
        outfile =  open(f"analysis_output/output.txt", "w")
        request_file = open(f"analysis_output/request.txt", "w").write("\n-------------------------------------REQUESTS---------------------------------------\n")   
        response_file = open(f"analysis_output/response.txt", "w").write("\n-------------------------------------RESPONSES---------------------------------------\n") 
    
    print("loading in the tech database")
    tech_object = load_tech_database()
    print("done loading")
    
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
        scripts = list(script.attrs for script in html.find_all('script'))
        meta_tags = list(meta.attrs for meta in html.find_all("meta"))
        anchors = list(html.find_all("a"))  
        links = list(link.attrs for link in html.find_all('link'))  
        """ 
        Listing them out
        """


        if (debug):
        # Scanning the scripts for their source and id tag
            outfile.write("\n-------------------------------------SCRIPT TAG----------------------------------------\n")
            for script in scripts:
                outfile.write(json.dumps(script, indent=4, sort_keys=True))
                outfile.write("\n")
            
            outfile.write("\n-------------------------------------META----------------------------------------\n")
            for meta in meta_tags: 
                outfile.write(json.dumps(meta, indent=4, sort_keys=True))
                outfile.write("\n")
                
            outfile.write("\n-------------------------------------LINK----------------------------------------\n")
            # Same thing, but now for meta tags
            for link in links: 
                outfile.write(json.dumps(link, indent=4, sort_keys=True))
                outfile.write("\n")

            outfile.write("\n-------------------------------------anchors---------------------------------------\n")
            # Same thing, but not for anchor tags
            for link in anchors:
                link_json = {"href" : link.attrs.get('href'), "rel": link.attrs.get('rel')}
                if bool(re.compile("^#.*").match(link.attrs.get('href'))):
                    link_json["type"] = "on-site permalink"            
                elif url in link.attrs.get('href'):
                    link_json["type"] = "internal link"     
                else:
                    link_json["type"] = "external link"  
                outfile.write(json.dumps(link_json, indent=4, sort_keys=True))
                outfile.write("\n")

        print("Scraping done, you can now find the outputs in the analysis_output folder\n\n")

        try:
            page.close()
            browser.close()
            outfile.close()
            request_file.close()
            response_file.close()
        except:
            pass