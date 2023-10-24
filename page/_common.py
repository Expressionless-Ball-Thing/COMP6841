import abc
from typing import Iterable, List, Mapping, Any
try:
    from typing import Protocol
except ImportError:
    Protocol = object # type: ignore

import aiohttp
import requests
from requests.structures import CaseInsensitiveDict

def _raise_not_dict(obj:Any, name:str) -> None:
    try:
        list(obj.keys())
    except AttributeError: 
        raise ValueError(f"{name} must be a dictionary-like object")

class ITag(Protocol):
    name: str
    attributes: Mapping[str, str]
    inner_html: str

class BaseTag(ITag, abc.ABC):
    def __init__(self, name:str, attributes:Mapping[str, str]) -> None:
        _raise_not_dict(attributes, "attributes")
        self.name = name
        self.attributes = attributes
    @property
    def inner_html(self) -> str: # type: ignore
        """Returns the inner HTML of an element as a UTF-8 encoded bytestring"""
        raise NotImplementedError()

class IWebPage(Protocol):
    url: str
    html: str
    headers: Mapping[str, str]
    scripts: List[str]
    meta: Mapping[str, str]
    def select(self, selector:str) -> Iterable[ITag]: 
        raise NotImplementedError()

class BaseWebPage(IWebPage):
    def __init__(self, url:str, html:str, headers:Mapping[str, str]):
        _raise_not_dict(headers, "headers")
        self.url = url
        self.html = html
        self.headers = CaseInsensitiveDict(headers)
        self.scripts: List[str] = []
        self.meta: Mapping[str, str] = {}
        self._parse_html()

    def _parse_html(self):
        raise NotImplementedError()
    
    @classmethod
    def new_from_url(cls, url: str, **kwargs:Any) -> IWebPage:
        response = requests.get(url, **kwargs)
        return cls.new_from_response(response)

    @classmethod
    def new_from_response(cls, response:requests.Response) -> IWebPage:
        return cls(response.url, html=response.text, headers=response.headers)

    @classmethod
    async def new_from_url_async(cls, url: str, verify: bool = True,
                                 aiohttp_client_session: aiohttp.ClientSession = None, **kwargs:Any) -> IWebPage:

        if not aiohttp_client_session:
            connector = aiohttp.TCPConnector(ssl=verify)
            aiohttp_client_session = aiohttp.ClientSession(connector=connector)

        async with aiohttp_client_session.get(url, **kwargs) as response:
            return await cls.new_from_response_async(response)

    @classmethod
    async def new_from_response_async(cls, response:aiohttp.ClientResponse) -> IWebPage:
        html = await response.text()
        return cls(str(response.url), html=html, headers=response.headers)