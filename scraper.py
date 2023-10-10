from json import JSONDecodeError
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import re
import json

def scraper(url):
    with sync_playwright() as playwright:
        chromium = playwright.chromium
        browser = chromium.launch(headless=True)
        page = browser.new_page()
        
        """ 
        Getting the items
        """
        
        # Subscribe to "request" and "response" events.
        
        requests = []
        responses = []
        
        page.on("request", lambda request: requests.append(request) if request not in requests else request)
        page.on("response", lambda response: responses.append(response) if response not in responses else response)
        page.goto(url)
        
        # Use Beautiful to parse down all of the html
        html = BeautifulSoup(page.content(), 'html.parser')
        
        # Check that it actually loaded a page
        if not bool(html.find('html')):
            print("The page does not exist, it doesn't have a <html> tag")
            return
        
        # get scripts, meta, link
        scripts = list(html.find_all('script'))
        meta_tags = list(html.find_all("meta"))
        links = list(html.find_all("a"))    
            
        """ 
        Listing them out
        """

        outfile = open(f"analysis_output/output.txt", "w")
        request_file = open(f"analysis_output/request.txt", "w")
        response_file = open(f"analysis_output/response.txt", "w")

        # # Scanning the scripts for their source and id tag
        outfile.write("\n-------------------------------------SCRIPT TAG----------------------------------------\n")
        for script in filter(lambda script: script.attrs.get('src') not in [None, ""] and script.attrs.get('id') not in [None, ""], scripts):
            outfile.write(json.dumps({"script-source" : script.attrs.get('src'), "id_tags": script.attrs.get('id')}, indent=4, sort_keys=True))
            outfile.write("\n")
        
        outfile.write("\n-------------------------------------META----------------------------------------\n")
        # Same thing, but now for meta tags
        for meta in filter(lambda meta: (meta.attrs.get('name') not in [None, ""] or meta.attrs.get('property') not in [None, ""]), meta_tags):
            outfile.write(json.dumps({"meta_name" : meta.attrs.get('name'), "meta_property": meta.attrs.get('property'), "meta_content": meta.attrs.get('content')}, indent=4, sort_keys=True))
            outfile.write("\n")

        outfile.write("\n-------------------------------------LINKS---------------------------------------\n")
        # Same thing, but not for anchor tags
        for link in links:
            link_json = {"href" : link.attrs.get('href'), "rel": link.attrs.get('rel')}
            if bool(re.compile("^#.*").match(link.attrs.get('href'))):
                link_json["type"] = "on-site permalink"            
            elif url in link.attrs.get('href'):
                link_json["type"] = "internal link"     
            else:
                link_json["type"] = "external link"  
                        
            outfile.write(json.dumps(link_json, indent=4, sort_keys=True))
            outfile.write("\n")

        request_file.write("\n-------------------------------------REQUESTS---------------------------------------\n")
        for request in requests:
            request_file.write(json.dumps({
                "METHOD": request.method,
                "URL": request.url,
                "HEADERS": request.headers
            }, indent=4, sort_keys=True))
            request_file.write("\n")
        
        thing = {}
        
        
        response_file.write("\n-------------------------------------RESPONESES---------------------------------------\n")
        seen = set()
        for response in [seen.add(d.url) or d for d in responses if d.url not in seen]:
            response_file.write(json.dumps({
                "URL" : response.url,
                "HEADERS": response.headers,
                "SECURITY": {key: value for key, value in response.security_details().items() if (key in ["issuer", "protocol", "subjectName"])} if response.security_details() is not None else None,
                "SERVER": response.server_addr()
            }, indent=4, sort_keys=True))
            response_file.write("\n")
            # try:
            #     print(f"TEXT: {response.json()}")
            # except:
            #     try:
            #         print(f"TEXT: {response.text()}")
            #     except:
            #         print(f"TEXT: ")

        print("Scraping done, you can now find the outputs in the analysis_output folder")

        browser.close()
        outfile.close()
        request_file.close()
        response_file.close()