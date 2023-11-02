from typing import Iterator, Mapping, Optional
from playwright.sync_api import Page
from bs4 import BeautifulSoup, Tag as bs4_Tag
from cached_property import cached_property
from functools import cached_property
from typing import List, Mapping
class Tag():
    
    def __init__(self, name: str, attributes: Mapping[str, str], soup: bs4_Tag) -> None:
        self._soup: bs4_Tag = soup
        self.name: str = name
        self.attributes: Mapping[str, str] = attributes
    
    @cached_property
    def inner_html(self) -> str:
        return self._soup.decode_contents()
class WebPage():
    def __init__(self, url:str, page: Page):
        self.page = page
        self.url: str = url
        self.scripts: List[str] = []
        self.scriptSrc: List[str] = []
        self.meta: Mapping[str, str] = {}
        
        self.html: str = self.page.content() 
        self.parsed_html = BeautifulSoup(self.page.content(), 'lxml')
        
        self._parse_html()

    def _parse_html(self):
        self.scripts.extend(script.get_text() for script in self.parsed_html.findAll('script', src=True))
        self.scriptSrc.extend(script['src'] for script in self.parsed_html.findAll('script', src=True))
        self.meta = {
            meta['name'].lower():
                meta['content'] for meta in self.parsed_html.findAll(
                    'meta', attrs=dict(name=True, content=True))
        }
   
    def select(self, selector: str) -> Iterator[Tag]:
        for item in self.parsed_html.select(selector):
            yield Tag(item.name, item.attrs, item)
            
class Technology:
    def __init__(self, cpe:str ="") -> None:
        self.found_in: List[str] = []
        self.versions: List[str] = []
        self.cpe: Optional[str] = cpe