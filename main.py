import argparse
import asyncio
import click
import scraper
from playwright.async_api import async_playwright

def get_parser() -> argparse.ArgumentParser:
    """Get the CLI `argparse.ArgumentParser`"""
    parser = argparse.ArgumentParser(description="python-Wappalyzer CLI", prog="python -m Wappalyzer")
    parser.add_argument('url', help='URL to analyze')
    parser.add_argument('-d', '--debug', default=False, help="prints out all requets, reponses, etc", dest='debug')
    parser.add_argument('-c', '--cve', default=False, help="List out any potential CVE vulnerabilities from scraped technology.", dest='cve')
    parser.add_argument('--user-agent', help='Request user agent', dest='useragent')
    parser.add_argument('--timeout', help='Request timeout', type=int, default=10)
    parser.add_argument('--no-verify', action='store_true', help='Skip SSL cert verify', dest='noverify')
    return parser

@click.group()
def cli():
    pass

# TODO: Do a regex check here to be sure that the url passed in is actually a url
@cli.command(help='Analyze the target URL')
@click.option('-u', '--url', 'url', type=str, required=True)
@click.option('-d', '--debug', 'debug', default=False, is_flag=True, help="prints out all requets, reponses, etc")
@click.option('-c', '--cve', 'cve', default=False, is_flag=True, help="List out any potential CVE vulnerabilities from scraped technology.")
async def analyze(url, debug, cve):
    async with async_playwright() as playwright:
        await scraper.analyze(url, debug, cve, playwright)


if __name__ == "__main__":
    cli()
        