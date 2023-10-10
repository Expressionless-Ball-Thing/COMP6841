import re
import click
from scraper import scraper

@click.group()
def cli():
    pass

@cli.command(help='Analyze the target URL')
@click.argument('url')
def analyze(url):
    scraper(url)


if __name__ == "__main__":
    cli()
        