import re
import sre_compile
from typing import Any, Dict, List, Mapping, Optional, Union

class DomSelector:
    def __init__(self, selector: str, exists: Optional[bool] = None, text: Optional[List['Pattern']] = None, attributes: Optional[Mapping[str, List['Pattern']]] = None) -> None:
        self.selector: str = selector
        self.exists: bool = bool(exists)
        self.text: Optional[List[Pattern]] = text
        self.attributes: Optional[Mapping[str, List['Pattern']]] = attributes

class Pattern:
    def __init__(self, string:str, regex: Optional[re.Pattern]=None, version: Optional[str]=None, confidence: Optional[str] = None) -> None:
        self.string: str = string
        self.regex: 're.Pattern' = regex or sre_compile.compile('', 0)
        self.version: Optional[str] = version
        self.confidence: int = int(confidence) if confidence else 100

class Fingerprint:
        
    def __init__(self, name:str, **attrs: Any) -> None:
        # Required infos
        self.name: str = name

        # Metadata
        self.website: str = attrs.get('website', '??')
        self.description: Optional[str] = attrs.get('description')
        self.cpe: Optional[str] = attrs.get('cpe')

        # Implies
        self.implies: List[str] = self._prepare_list(attrs['implies']) if 'implies' in attrs else []
        self.requires: List[str] = self._prepare_list(attrs['requires']) if 'requires' in attrs else []
        self.requiresCategory: List[str] = self._prepare_list(attrs['requiresCategory']) if 'requiresCategory' in attrs else []
        self.excludes: List[str] = self._prepare_list(attrs['excludes']) if 'excludes' in attrs else []

        # Patterns
        self.dom: List[DomSelector] = self._prepare_dom(attrs['dom']) if 'dom' in attrs else []
        
        self.headers: Mapping[str, List[Pattern]] = self._prepare_headers(attrs['headers']) if 'headers' in attrs else {}
        self.meta: Mapping[str, List[Pattern]] = self._prepare_meta(attrs['meta']) if 'meta' in attrs else {}

        self.html: List[Pattern] = self._prepare_pattern(attrs['html']) if 'html' in attrs else []
        self.text: List[Pattern] = self._prepare_pattern(attrs['text']) if 'text' in attrs else []
        self.url: List[Pattern] = self._prepare_pattern(attrs['url']) if 'url' in attrs else []
        self.scriptSrc: List[Pattern] = self._prepare_pattern(attrs['scriptSrc']) if 'scriptSrc' in attrs else []
        self.scripts: List[Pattern] = self._prepare_pattern(attrs['scripts']) if 'scripts' in attrs else []

        self.cookies: Mapping[str, List[Pattern]] = self._prepare_pattern_dict({k.lower():v for k,v in attrs['cookies'].items()}) if 'cookies' in attrs else {}
        self.dns: Mapping[str, List[Pattern]] = self._prepare_pattern_dict({k.lower():v for k,v in attrs['dns'].items()}) if 'dns' in attrs else {} 
        self.js: Mapping[str, List[Pattern]] = self._prepare_pattern_dict({k.lower():v for k,v in attrs['js'].items()}) if 'js' in attrs else {}
        # self.css: List[Pattern] Not supported (yet)
        # self.robots: List[Pattern] Not supported (yet)
        # self.xhr: List[Pattern] Not supported
    
    @classmethod
    def _prepare_list(cls, thing: Any) -> List[Any]:
        return [thing] if not isinstance(thing, list) else thing

    @classmethod
    def _prepare_pattern(cls, pattern: Union[str, List[str]]) -> List[Pattern]:
        """
        Parse the Regex Pattern in Wappalyzer format, since it's more condensed.
        The logic here is basically the same.
        """
        pattern_objects = []
        if isinstance(pattern, list):
            for p in pattern:
                pattern_objects.extend(cls._prepare_pattern(p))
        else:
            attrs = {}
            patterns = pattern.split('\\;')
            for index, expression in enumerate(patterns):
                if index == 0:
                    attrs['string'] = expression
                    try:
                        attrs['regex'] = re.compile(expression, re.I) # type: ignore
                    except re.error as err:
                        # Wappalyzer is a JavaScript application therefore some of the regex wont compile in Python.
                        # regex that never matches: http://stackoverflow.com/a/1845097/413622
                        attrs['regex'] = re.compile(r'(?!x)x')
                else:
                    attr = expression.split(':')
                    if len(attr) > 1:
                        key = attr.pop(0)
                        attrs[str(key)] = ':'.join(attr)
            pattern_objects.append(Pattern(**attrs))
        return pattern_objects
    
    @classmethod
    def _prepare_pattern_dict(cls, thing: Dict[str, Union[str, List[str]]]) -> Mapping[str, List[Pattern]]:
        for k in thing:
            thing[k] = cls._prepare_pattern(thing[k])
        return thing
    
    @classmethod
    def _prepare_meta(cls,  thing: Union[str, List[str], Dict[str, Union[str, List[str]]]]) -> Mapping[str, List[Pattern]]:
        # Ensure dict.
        if not isinstance(thing, dict):
            thing = {'generator': thing}
        return cls._prepare_pattern_dict({k.lower():v for k,v in thing.items()})

    @classmethod
    def _prepare_headers(cls,  thing: Dict[str, Union[str, List[str]]]) -> Mapping[str, List[Pattern]]:
        return cls._prepare_pattern_dict({k.lower():v for k,v in thing.items()})
    
    @classmethod
    def _prepare_dom(cls, thing: Union[str, List[str], Dict[str, Dict[str, Union[str, List[str]] ] ] ]) -> List[DomSelector]:
        selectors = []
        if isinstance(thing, str):
            selectors.append(DomSelector(thing, exists=True))
        elif isinstance(thing, list):
            for _o in thing: 
                selectors.append(DomSelector(_o, exists=True))
        elif isinstance(thing, dict):
            for cssselect, clause in thing.items():
                # prepare regexes
                _prep_text_patterns = None
                _prep_attr_patterns = None
                _exists = None
                if clause.get('exists') is not None:
                    _exists = True
                if clause.get('text'):
                    _prep_text_patterns = cls._prepare_pattern(clause['text'])
                if clause.get('attributes'):
                    _prep_attr_patterns ={}
                    for _key, pattern in clause['attributes'].items(): #type: ignore
                        _prep_attr_patterns[_key] = cls._prepare_pattern(pattern)
                selectors.append(DomSelector(cssselect, exists=_exists, text=_prep_text_patterns, attributes=_prep_attr_patterns))
        return selectors