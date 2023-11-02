# Something Awesome: Cybersecurity website Scraper and analyser

This is my COMP6841 Self-Selected Project (Something Awesome), it's a python web scraper and CLI tool for junior web devs and web security engineers to analyse websites and hunt for potential vulnerabilities, with the goal of helping people understand the uses of web scraping and to help understand the power of Recon and information within the realm of cybersecurity.

Regardless, do use this tool with caution, do not attempt to use this tool on a website that isn't public (e.g. behind a login), as it could land the user in potential legal troubles.

## Features

Given a website url as an input, this scraper will scrape the website's code and netowrk traffic and reference it with a database of web techonologies and integrations to determine what web technologies are used on the website, along with the versions, all neatly shown in neat JSON files.

(This web scraper uses the web technologies database used by Wappalyzer, which is more complete, but requires copying some of the logic used to parse the database into reusable technology identifiers, you can find links to it at the bottom of this document)

The web scraper can also do the following:

- Note down the IP addresses and ports of any server that the site sends requests to.
- Note down all the links on the site for site mapping purposes.
- Optionally reference found technologies with the NIST CVE database. (Be warned that there are potentially lots of false positives, because unless the tech has a known CPE, the NIST CVE database's search function just fuzzy searches).
- A debug mode that prints out every single network request and responses made along with the full HTML of the site.

### Planned Features and improvements

Features:

- Hunt for hidden input fields and links.
- Web crawling functionalities.
- Allow for the insertion of cookies and headers when scraping a website.
- Fuzzer integration to detect hidden endpoints.

Improvements:

- Increase performance overall, perhaps taking advantage of the async API within Playwright.
- Add in code to parse the body of a network response,

## Setting up

The simplified steps are as follows, see further down for the detailed steps:

1. Install python **3.11** and pip (**Currently, this scraper works best with python 3.11, 3.12 causes one of the dependencies to crash**)
2. Clone the repo.
3. Set up a virtual environment and then install the dependencies by running `pip install -r requirements.txt`
4. Run `playwright install`.
5. To start scraping simply type in `python .\main.py analyze -u <URL>` to start scraping.

### Cloning this repo, setting up a virtual environment and

After installing [python version 3.11](https://www.python.org/downloads/release/python-3110/) (Once again, python 3.12 causes one of the dependencies to crash), you can clone the repo and navigate to the project's folder with

```bash
git clone https://github.com/Expressionless-Ball-Thing/COMP6841.git
cd COMP6841
```

Next we can set up the virtual environment, if you are on Windows, run the following:

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

If you are on Mac or Linux, run the following instead:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

This project uses playwright, a browser automation tool, so you need to also run the following command:

```bash
playwright install
```

Now you can start scraping by typing in:

```bash
python .\SecScraper.py -u <URL>
```

## Usage

You can see the following help message if you type `python .\SecScraper.py --help`

```bash
Usage: SecScraper.py [OPTIONS]

  Analyze the target URL

Options:
  -u, --url TEXT  The url for the website you are going to scrape.  [required]
  -d, --debug     Prints out all requests, reponses, etc.
  -c, --cve       List out any potential CVE vulnerabilities from scraped technology.
  --help          Show this message and exit.
```

After the site is scraped and analyse, you will find the `analysis_output` folder populated with files, these include:

- `analysis_results.json`, this contains the list of detected web tech, specific versions and cpe (if there's any), and what point to its existence on the website.
- `servers_and_security.json`, this contains the SSL certificates, IP address and port numbers of every server the website makes requests to.
- `site_links.json`, this contains all the links on the web page, and whether they are internal links or external links.
- `unknown.json`, this contains all the network traffic headers that has no known technologies detected on it, for user's analysis.

And optionally, if the debug flag `-d` was used:

- `debug_request.json` and `debug_response.json`, Contains all the request and response headers from the network traffic of the website.
- `html_full.html`, contains the full html doucment of the website.

And if the cve flag `-c` was used:

- `potential_vulnerabilites.json`, contains the list of potential cves from the NIST's NVD that the website might be vulnerable of based on the detected web technologies.
(Please note that there are potentially lots of false positives)

## Relevant documentation for python packages used

- [Requests](https://docs.python-requests.org/en/latest/index.html)
- [Playwright](https://playwright.dev/python/docs/intro)
- [BeautifulSoup](https://beautiful-soup-4.readthedocs.io/en/latest/)
- [Click](https://click.palletsprojects.com/en/8.1.x/)

## Main sources of inspration and reference texts

Project Inspiration

- [Wappalyzer](https://www.wappalyzer.com/)

Sadly, Wappalyzer privated their github repo a few months ago as of writing, but there are forks of it, this is also the source of the web technology database in this project.

- [Wappalyzer Fork](https://github.com/tomnomnom/wappalyzer)

This port of Wappalyzer to Golang helped with figuring out how to parse the Wappalyzer's JSON files into a usable format.

- [WappalyzerGo](https://github.com/projectdiscovery/wappalyzergo)

This port of Wappalyzer to Python also help a great deal with figuring out how to structure the project

- [python-Wappalyzer](https://github.com/chorsley/python-Wappalyzer)

Very useful book and website to learning about web scraping and the tools for it

- [Web Scraping With Python 2nd Edition](https://www.oreilly.com/library/view/web-scraping-with/9781491985564/)
- [Web Scraping FYI](https://webscraping.fyi)
