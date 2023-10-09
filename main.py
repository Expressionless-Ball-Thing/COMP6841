from json import JSONDecodeError
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import re

site_url = "https://www.frase.io"

def scraper():

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
        # subscribe to the loading event
        page.on("load", lambda page: print("page loaded", page.url))
        page.goto(site_url)
        
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
        print("-------------------------------------SCRIPT TAG----------------------------------------")
        for script in scripts:
            if not (script.attrs.get('src') not in [None, ""] and script.attrs.get('id') not in [None, ""]):
                print(f"script-source: {script.attrs.get('src')}\nid_tag: {script.attrs.get('id')}\n")
        
        print("-------------------------------------META----------------------------------------")
        # Same thing, but now for meta tags
        for meta in meta_tags:
            if not (meta.attrs.get('name') not in [None, ""] and meta.attrs.get('property') not in [None, ""]):
                print(f"meta_name: {meta.attrs.get('name')}\nmeta_property: {meta.attrs.get('property')}\nmeta_content: {meta.attrs.get('content')}\n")

        print("-------------------------------------LINKS---------------------------------------")
        # Same thing, but not for anchor tags
        for link in links:
            if site_url in link.attrs.get('href') or re.compile("^#.*").match(link.attrs.get('href')):
                print("type: internal link")
            else:
                print("type: external link")
            print(f"href: {link.attrs.get('href')}\nrel: {link.attrs.get('rel')}\n")

        # print("-------------------------------------REQUESTS---------------------------------------")
        # for request in requests:
        #     print(f"METHOD: {request.method}")
        #     print(f"URL: {request.url}")
        #     print(f"RESOURCE_TYPE: {request.resource_type}")
        #     print(f"POST_DATA: {request.post_data}")
        #     print(f"HEADERS: {request.headers}")
        
        # for response in responses:
        #     print(f"URL: {response.url}")
        #     print(f"HEADERS: {response.headers}")
        #     print(f"SECURITY: {response.security_details()}")
        #     try:
        #         print(f"TEXT: {response.json()}")
        #     except:
        #         try:
        #             print(f"TEXT: {response.text()}")
        #         except:
        #             print(f"TEXT: ")

        #     print(f"SERVER: {response.server_addr()}")
        
        browser.close()


if __name__ == "__main__":
    scraper()
        