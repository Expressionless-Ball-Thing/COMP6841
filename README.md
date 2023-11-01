# Something Awesome: Web Scraper

This is my COMP6841 Self-Selected Project (Something Awesome), it's a python web scraper and CLI tool for junior web devs and web security people to analyse websites and hunt for potential vulnerabilities, with the goal of helping people understand the uses of web scraping and to help understand the power of Recon and information within the realm of cybersecurity.

Regardless, do use this tool with caution, do not attempt to use this tool on a website that isn't public (e.g. behind a login), as it could land the user in potential legal troubles.

## Features

Given a website url as an input, this scraper will scrape the website's code and netowrk traffic and reference it with a database of web techonologies and integrations to determine what web technologies are used on the website, along with the versions, all neatly shown in neat JSON files.

The web scraper can also do the following:

- Note down the IP addresses and ports of any server that the send sites sends requests to.
- Note down all the links on the site for site mapping purposes.
- Optionally reference found technologies with the NIST CVE database.
- A debug mode that prints out every single network request and reponses made along with the full HTML of the site.

### Planned Features

- Hunt for hidden input fields and links.
- Web crawling functionalities.
- Allow for the insertion of cookies and headers when scraping a website.
- Fuzzer integration to detect hidden endpoints.

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
python .\main.py analyze -u <URL>
```

## Usage

You can see the following help message if you type `python .\main.py analyze --help`

```bash
Usage: main.py analyze [OPTIONS]
  Analyze the target URL

Options:
  -u, --url TEXT  [required]
  -d, --debug     prints out all requets, reponses, etc
  -c, --cve       List out any potential CVE vulnerabilities from detected technologies.
  --help          Show this message and exit.
```
