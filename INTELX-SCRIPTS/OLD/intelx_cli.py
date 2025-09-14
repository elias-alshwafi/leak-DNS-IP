
import click
import requests
import json

INTELX_KEY = "24fcfc64-849f-4e15-b365-40419b7d6624"
INTELX_URL = "https://free.intelx.io/"

@click.group()
def cli():
    """A command-line tool for interacting with the Intelligence X API."""
    pass

def _make_request(method, endpoint, json_data=None, params=None):
    headers = {
        "x-key": INTELX_KEY,
        "User-Agent": "IntelX-CLI-Tool/1.0"
    }
    url = f"{INTELX_URL}{endpoint}"

    try:
        if method == "POST":
            response = requests.post(url, json=json_data, headers=headers)
        elif method == "GET":
            response = requests.get(url, params=params, headers=headers)
        else:
            raise ValueError("Unsupported HTTP method")

        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.HTTPError as e:
        click.echo(f"HTTP Error: {e.response.status_code} - {e.response.text}", err=True)
        return None
    except requests.exceptions.ConnectionError as e:
        click.echo(f"Connection Error: {e}", err=True)
        return None
    except requests.exceptions.Timeout as e:
        click.echo(f"Timeout Error: {e}", err=True)
        return None
    except requests.exceptions.RequestException as e:
        click.echo(f"An unexpected error occurred: {e}", err=True)
        return None

@cli.command()
@click.option('--term', required=True, help='The search term (strong selector).')
@click.option('--maxresults', default=100, type=int, help='Maximum number of results to query per bucket.')
@click.option('--sort', default=2, type=int, help='Sort order (0: No sorting, 1: X-Score ASC, 2: X-Score DESC, 3: Date ASC, 4: Date DESC).')
@click.option('--media', default=0, type=int, help='Media type filter (0: Not set).')
@click.option('--timeout', default=0, type=int, help='Timeout in seconds (0: default).')
@click.option('--datefrom', default='', help='Start date for filtering (YYYY-MM-DD).')
@click.option('--dateto', default='', help='End date for filtering (YYYY-MM-DD).')
@click.option('--buckets', multiple=True, help='Buckets to search in (can be specified multiple times).')
def search(term, maxresults, sort, media, timeout, datefrom, dateto, buckets):
    """Submits an intelligent search request."""
    click.echo(f"Submitting search for: {term}")
    json_data = {
        "term": term,
        "buckets": list(buckets),
        "lookuplevel": 0,
        "maxresults": maxresults,
        "timeout": timeout,
        "datefrom": datefrom,
        "dateto": dateto,
        "sort": sort,
        "media": media,
        "terminate": []
    }
    response = _make_request("POST", "intelligent/search", json_data=json_data)
    if response:
        click.echo(json.dumps(response, indent=4))

@cli.command()
@click.option('--search_id', required=True, help='The search ID obtained from the search command.')
@click.option('--limit', default=100, type=int, help='Maximum number of items to return.')
def get_results(search_id, limit):
    """Retrieves results for a given search ID."""
    click.echo(f"Retrieving results for search ID: {search_id}")
    params = {
        "id": search_id,
        "limit": limit
    }
    response = _make_request("GET", "intelligent/search/result", params=params)
    if response:
        click.echo(json.dumps(response, indent=4))

@cli.command()
@click.option('--search_id', required=True, help='The search ID to terminate.')
def terminate_search(search_id):
    """Terminates a running search."""
    click.echo(f"Terminating search ID: {search_id}")
    json_data = {
        "id": search_id
    }
    response = _make_request("POST", "intelligent/search/terminate", json_data=json_data)
    if response:
        click.echo(json.dumps(response, indent=4))

@cli.command()
@click.option('--selector', required=True, help='The selector for phonebook search (e.g., domain).')
@click.option('--maxresults', default=100, type=int, help='Maximum number of results.')
def phonebook_search(selector, maxresults):
    """Submits a phonebook search request."""
    click.echo(f"Submitting phonebook search for: {selector}")
    json_data = {
        "selector": selector,
        "maxresults": maxresults
    }
    response = _make_request("POST", "phonebook/search", json_data=json_data)
    if response:
        click.echo(json.dumps(response, indent=4))

@cli.command()
@click.option('--search_id', required=True, help='The search ID obtained from the phonebook search command.')
@click.option('--limit', default=100, type=int, help='Maximum number of items to return.')
def get_phonebook_results(search_id, limit):
    """Retrieves results for a given phonebook search ID."""
    click.echo(f"Retrieving phonebook results for search ID: {search_id}")
    params = {
        "id": search_id,
        "limit": limit
    }
    response = _make_request("GET", "phonebook/search/result", params=params)
    if response:
        click.echo(json.dumps(response, indent=4))

@cli.command()
@click.option('--system_id', required=True, help='The system ID of the item to read.')
@click.option('--output_file', required=True, help='Path to save the file content.')
def read_file(system_id, output_file):
    """Reads an item's data for download."""
    click.echo(f"Reading file with System ID: {system_id} to {output_file}")
    params = {
        "id": system_id
    }
    # For file reading, the response is raw data, not JSON
    headers = {
        "x-key": INTELX_KEY,
        "User-Agent": "IntelX-CLI-Tool/1.0"
    }
    url = f"{INTELX_URL}file/read"
    try:
        response = requests.get(url, params=params, headers=headers, stream=True)
        response.raise_for_status()
        with open(output_file, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        click.echo(f"File successfully saved to {output_file}")
    except requests.exceptions.HTTPError as e:
        click.echo(f"HTTP Error: {e.response.status_code} - {e.response.text}", err=True)
    except requests.exceptions.RequestException as e:
        click.echo(f"An error occurred: {e}", err=True)

@cli.command()
@click.option('--system_id', required=True, help='The system ID of the item to view.')
def view_file(system_id):
    """Views an item's data for detailed inline view."""
    click.echo(f"Viewing file with System ID: {system_id}")
    params = {
        "id": system_id
    }
    response = _make_request("GET", "file/view", params=params)
    if response:
        click.echo(response) # This will print the raw content, might be large

@cli.command()
@click.option('--system_id', required=True, help='The system ID of the item to preview.')
def preview_file(system_id):
    """Previews an item's data (max. first 1000 characters)."""
    click.echo(f"Previewing file with System ID: {system_id}")
    params = {
        "id": system_id
    }
    response = _make_request("GET", "file/preview", params=params)
    if response:
        click.echo(response) # This will print the raw content, might be large

if __name__ == '__main__':
    cli()


