import click
import scraper

@click.group()
def cli():
    pass

# TODO: Do a regex check here to be sure that the url passed in is actually a url
@cli.command(help='Analyze the target URL')
@click.option('-u', '--url', 'url', type=str, required=True)
@click.option('-d', '--debug', 'debug', default=False, is_flag=True, help="prints out all requests, reponses, etc")
@click.option('-c', '--cve', 'cve', default=False, is_flag=True, help="List out any potential CVE vulnerabilities from scraped technology.")
def analyze(url, debug, cve):
    scraper.analyze(url, debug, cve)


if __name__ == "__main__":
    cli()
        