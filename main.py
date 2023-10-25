import click
import scraper

@click.group()
def cli():
    pass

# TODO: Do a regex check here to be sure that the url passed in is actually a url
@cli.command(help='Analyze the target URL')
@click.option('-u', '--url', 'url', type=str, required=True)
@click.option('-d', '--debug', 'debug', default=False, is_flag=True, help="prints out all requets, reponses, etc")
def analyze(url, debug):
    print(debug)
    scraper.analyze()


if __name__ == "__main__":
    cli()
        