from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import re
import json

outfile = open(f"analysis_output/output.txt", "w")
request_file = open(f"analysis_output/request.txt", "w")
response_file = open(f"analysis_output/response.txt", "w") 
request_file.write("\n-------------------------------------REQUESTS---------------------------------------\n")     
response_file.write("\n-------------------------------------RESPONESES---------------------------------------\n") 

seen = set()

def handle_request(request):
    try:
        request_file.write(json.dumps({
            "METHOD": request.method,
            "URL": request.url,
            "HEADERS": request.all_headers()
        }, indent=4, sort_keys=True))
        request_file.write("\n")
        
        response = request.response()
        response_file.write(json.dumps({
            "URL" : response.url,
            "HEADERS": response.all_headers(),
            "SECURITY": {key: value for key, value in response.security_details().items() if (key in ["issuer", "protocol", "subjectName"])} if response.security_details() is not None else None,
            "SERVER": response.server_addr()
        }, indent=4, sort_keys=True))
        response_file.write("\n")
    except:
        pass

def scraper(url):
    with sync_playwright() as playwright:
        chromium = playwright.chromium
        browser = chromium.launch(headless=True)
        page = browser.new_page()
        
        """ 
        Getting the items
        """

  
               
        # Subscribe to "request" and "response" events.
        
        page.on("request", handle_request)
        # page.on("response", handle_response)
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
            
        # outfile.write("\n-------------------------------------BODY---------------------------------------\n")
        # print(html.find_all('body'))      

        print("Scraping done, you can now find the outputs in the analysis_output folder")

        try:
            page.close()
            browser.close()
        except:
            pass
        outfile.close()
        request_file.close()
        response_file.close()