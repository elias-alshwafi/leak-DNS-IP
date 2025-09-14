#!/usr/bin/env python3
"""
IntelX Interactive TUI — robust, auto-detecting API instance

This is an improved TUI script that:
- Auto-detects the correct API instance (free.intelx.io / 2.intelx.io / public.intelx.io / intelx.io / www.intelx.io)
  by probing /authenticate/info with the provided API key and selecting the instance
  that returns meaningful capabilities (buckets/redacted) or a 200 response.
- Provides clear diagnostics when DNS fails or when the API key is bound to a different
  instance (401/403) — it prints per-host status_code, errors and short response snippets.
- Keeps the polished menu-driven TUI previously built (search, preview, download, export,
  settings) and improves error handling and user guidance.

How to use:
  1) Back up your original file: cp intelx.py intelx.py.bak
  2) Save this script as intelx.py (or intelx_tui.py) and make executable: chmod +x intelx.py
  3) Install recommended libs: pip install requests rich pandas openpyxl intelx
  4) Export your API key: export INTELX_KEY='your-key'
  5) Run: python3 intelx.py

Notes:
- The script will attempt to auto-detect the correct API instance for your key. If it fails
  it will present diagnostics so you can decide to change base URL or check your account's
  Developer -> API settings.
- Do NOT paste production API keys into public chats. If your key was exposed, rotate it.

"""
from __future__ import annotations
import os
import sys
import json
import time
from typing import List, Dict, Any, Optional, Tuple

# External libs
try:
    import requests
except Exception:
    print("Missing dependency: requests. Install with: pip install requests")
    raise

# Optional UX libs
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    RICH = True
    console = Console()
except Exception:
    RICH = False
    class _ConsoleDummy:
        def print(self, *a, **k):
            print(*a)
    console = _ConsoleDummy()

try:
    import pandas as pd
    PANDAS = True
except Exception:
    PANDAS = False

# SDK detection (optional)
USE_SDK = False
intelx_sdk = None
try:
    import intelx as intelx_module
    intelx_sdk = intelx_module
    USE_SDK = True
except Exception:
    try:
        import intelxapi as intelxapi_module
        intelx_sdk = intelxapi_module
        USE_SDK = True
    except Exception:
        USE_SDK = False

# Config
HOME = os.path.expanduser('~')
CONFIG_PATH = os.path.join(HOME, '.intelx_tui_config.json')
LOG_PATH = os.path.join(HOME, '.intelx_tui.log')

DEFAULT_CANDIDATES = [
    'https://www.intelx.io',
    'https://intelx.io',
    'https://free.intelx.io',
    'https://public.intelx.io',
    'https://2.intelx.io',
    'https://api.intelx.io'
]

BASE_URL = os.environ.get('INTELX_API_BASE', 'https://www.intelx.io')
API_KEY = os.environ.get('INTELX_KEY') or None
USER_AGENT = 'IntelX-TUI/2.0'

# Logging helper
def log(msg: str) -> None:
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(f"[{ts}] {msg}")
    except Exception:
        pass

# config helpers
def load_config() -> Dict[str, Any]:
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        log(f'Failed to load config: {e}')
    return {}

def save_config(cfg: Dict[str, Any]) -> None:
    try:
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        log(f'Failed to save config: {e}')

# IntelX client wrapper
class IntelXClient:
    def __init__(self, apikey: str, base_url: str = BASE_URL, timeout: int = 30):
        if not apikey:
            raise ValueError('API key required')
        self.apikey = apikey
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT, 'x-key': self.apikey})
        self.use_sdk = USE_SDK
        self.sdk = None
        if self.use_sdk:
            try:
                if hasattr(intelx_sdk, 'intelx'):
                    self.sdk = intelx_sdk.intelx(self.apikey)
                elif hasattr(intelx_sdk, 'IntelX'):
                    self.sdk = intelx_sdk.IntelX(self.apikey)
            except Exception as e:
                log(f'SDK init failed: {e}')
                self.use_sdk = False

    def _request(self, path: str, method: str = 'GET', params: Dict[str, Any] = None, json_data: Dict[str, Any] = None, stream: bool = False):
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            if method.upper() == 'GET':
                resp = self.session.get(url, params=params, timeout=self.timeout, stream=stream)
            else:
                resp = self.session.post(url, json=json_data, params=params, timeout=self.timeout, stream=stream)
            return resp
        except Exception as e:
            log(f'HTTP request error to {url}: {e}')
            raise

    def capabilities(self) -> Dict[str, Any]:
        # prefer SDK
        if self.use_sdk and self.sdk:
            try:
                if hasattr(self.sdk, 'authenticate_info'):
                    return self.sdk.authenticate_info()
            except Exception as e:
                log(f'sdk capabilities failed: {e}')
        resp = self._request('/authenticate/info')
        try:
            return resp.json()
        except Exception:
            # return structured diagnostic so UI can present it
            return {'_http_status': resp.status_code, '_text_snippet': resp.text[:800]}

    def search(self, query: str, buckets: Optional[List[str]] = None, maxresults: int = 50) -> Dict[str, Any]:
        if self.use_sdk and self.sdk and hasattr(self.sdk, 'search'):
            try:
                return self.sdk.search(query, buckets=buckets or [], maxresults=maxresults)
            except Exception as e:
                log(f'sdk.search failed: {e}')
        payload = {'q': query, 'maxresults': maxresults}
        if buckets:
            payload['buckets'] = ','.join(buckets)
        resp = self._request('/intelligent/search', method='POST', json_data=payload)
        try:
            return resp.json()
        except Exception:
            raise RuntimeError(f'Search response parse failed: {resp.status_code} {resp.text[:500]}')

    def file_view(self, media: int, type_: int, storageid: Optional[str], bucket: str) -> str:
        if self.use_sdk and self.sdk:
            try:
                if hasattr(self.sdk, 'FILE_VIEW'):
                    return self.sdk.FILE_VIEW(media, type_, storageid, bucket)
                if hasattr(self.sdk, 'file_view'):
                    return self.sdk.file_view(media, type_, storageid, bucket)
            except Exception as e:
                log(f'sdk.FILE_VIEW failed: {e}')
        params = {'media': media, 'type': type_, 'storageid': storageid, 'bucket': bucket}
        resp = self._request('/file/view', method='GET', params=params)
        if resp.status_code == 200:
            return resp.text
        raise RuntimeError(f'file_view failed: {resp.status_code} {resp.text[:200]}')

    def file_read_stream(self, systemid: str, storageid: Optional[str], bucket: str, outpath: str) -> int:
        if self.use_sdk and self.sdk and hasattr(self.sdk, 'FILE_READ'):
            try:
                self.sdk.FILE_READ(systemid, 0, bucket, outpath)
                return os.path.getsize(outpath)
            except Exception as e:
                log(f'sdk.FILE_READ failed: {e}')
        params = {'systemid': systemid, 'bucket': bucket}
        resp = self._request('/file/read', method='GET', params=params, stream=True)
        if resp.status_code != 200:
            raise RuntimeError(f'Download failed: {resp.status_code} {resp.text[:200]}')
        total = int(resp.headers.get('Content-Length') or 0)
        os.makedirs(os.path.dirname(outpath) or '.', exist_ok=True)
        written = 0
        if total > 0 and RICH:
            with Progress(SpinnerColumn(), TextColumn('{task.description}'), BarColumn(), "{task.completed}/{task.total} bytes", TimeElapsedColumn()) as progress:
                task = progress.add_task('Downloading', total=total)
                with open(outpath, 'wb') as fh:
                    for chunk in resp.iter_content(chunk_size=8192):
                        if chunk:
                            fh.write(chunk)
                            written += len(chunk)
                            progress.update(task, advance=len(chunk))
        else:
            if RICH:
                with Progress(SpinnerColumn(), TextColumn('{task.description}'), TimeElapsedColumn()) as progress:
                    task = progress.add_task('Downloading (unknown size)', total=None)
                    with open(outpath, 'wb') as fh:
                        for chunk in resp.iter_content(chunk_size=8192):
                            if chunk:
                                fh.write(chunk)
                                written += len(chunk)
            else:
                with open(outpath, 'wb') as fh:
                    for chunk in resp.iter_content(chunk_size=8192):
                        if chunk:
                            fh.write(chunk)
                            written += len(chunk)
        return written

# --- Auto-detect the correct base URL for the provided API key ---
def detect_best_instance(api_key: str, candidates: List[str] = DEFAULT_CANDIDATES, timeout: int = 8) -> Tuple[Optional[str], Dict[str, Any]]:
    """Probe candidate base URLs and return the first one that returns useful capabilities.
    Returns: (best_url_or_None, diagnostics)
    diagnostics is a mapping host -> dict(status / error / snippet)
    """
    diagnostics: Dict[str, Any] = {}
    headers = {'User-Agent': USER_AGENT, 'x-key': api_key}
    for base in candidates:
        url = base.rstrip('/') + '/authenticate/info'
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            status = resp.status_code
            text_snip = (resp.text or '')[:800]
            # Try json
            try:
                j = resp.json()
            except Exception:
                j = None
            diagnostics[base] = {'status': status, 'json': j if j is not None else None, 'text_snippet': text_snip}
            # Choose base if status==200 and json contains 'buckets' or 'redacted' or non-empty dict
            if status == 200 and isinstance(j, dict) and (j.get('buckets') or j.get('redacted') or len(j) > 0):
                return base, diagnostics
            # If status 200 and j=={} (empty) treat as semi-valid — prefer but continue probing to find richer instance
            if status == 200 and isinstance(j, dict) and len(j) == 0:
                # keep note but prefer other instances; tentatively accept if no better found
                tentative = base
                # continue probing but remember tentative
                if 'tentative' not in diagnostics:
                    diagnostics['tentative'] = base
        except Exception as e:
            diagnostics[base] = {'error': str(e)}
    # fallback: if any candidate had status 200 (even empty) pick it
    for b, d in diagnostics.items():
        if isinstance(d, dict) and d.get('status') == 200:
            return b, diagnostics
    return None, diagnostics

# normalizer
def normalize(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if isinstance(raw, dict) and 'records' in raw:
        for rec in raw['records']:
            items.append({
                'systemid': rec.get('systemid') or rec.get('id'),
                'storageid': rec.get('storageid'),
                'bucket': rec.get('bucket'),
                'media': rec.get('media'),
                'type': rec.get('type'),
                'title': rec.get('title') or rec.get('selector') or rec.get('name'),
                'size': rec.get('size') or rec.get('filesize') or 0,
                'raw': rec
            })
        return items
    if isinstance(raw, dict) and 'results' in raw:
        for rec in raw['results']:
            items.append({
                'systemid': rec.get('systemid') or rec.get('id'),
                'storageid': rec.get('storageid'),
                'bucket': rec.get('bucket'),
                'media': rec.get('media'),
                'type': rec.get('type'),
                'title': rec.get('title') or rec.get('selector'),
                'size': rec.get('size', 0),
                'raw': rec
            })
        return items
    if isinstance(raw, list):
        for rec in raw:
            if isinstance(rec, dict):
                items.append({
                    'systemid': rec.get('systemid') or rec.get('id'),
                    'storageid': rec.get('storageid'),
                    'bucket': rec.get('bucket'),
                    'media': rec.get('media'),
                    'type': rec.get('type'),
                    'title': rec.get('title') or rec.get('selector'),
                    'size': rec.get('size', 0),
                    'raw': rec
                })
    return items

# TUI helpers (unchanged from earlier)
def print_table(results: List[Dict[str, Any]], page: int = 0, page_size: int = 10, redacted: set = set(), allowed: set = set()):
    start = page * page_size
    end = start + page_size
    slice_ = results[start:end]
    if RICH:
        table = Table(title=f'Results (showing {start+1}-{min(end, len(results))} of {len(results)})', show_lines=False)
        table.add_column('#', width=4)
        table.add_column('systemid', style='dim')
        table.add_column('bucket')
        table.add_column('title', overflow='fold')
        table.add_column('size', justify='right')
        table.add_column('downloadable', justify='center')
        for i, r in enumerate(slice_, start+1):
            b = r.get('bucket')
            can = False
            if b is not None:
                can = (b not in redacted)
            table.add_row(str(i), str(r.get('systemid','-')), str(b or '-'), str(r.get('title','-'))[:80], str(r.get('size','-')), 'YES' if can else 'NO')
        console.print(table)
    else:
        for i, r in enumerate(slice_, start+1):
            print(f'[{i}] {r.get("systemid")} | bucket={r.get("bucket")} | size={r.get("size")} | title={r.get("title")[:60]}')


def ask_menu(prompt_text: str, options: List[str], allow_back: bool = True) -> Optional[int]:
    while True:
        console.print(Panel(prompt_text))
        for idx, opt in enumerate(options, 1):
            console.print(f'[cyan]{idx}[/] - {opt}')
        if allow_back:
            console.print('[cyan]0[/] - Back / Cancel')
        choice = Prompt.ask('Choose', default='0' if allow_back else '1') if RICH else input('Choose: ')
        try:
            val = int(choice)
            if allow_back and val == 0:
                return None
            if 1 <= val <= len(options):
                return val - 1
        except Exception:
            console.print('[red]Invalid selection, try again.[/]')

# Main flow
def run_tui():
    global API_KEY, BASE_URL
    cfg = load_config()
    if not API_KEY and cfg.get('api_key'):
        API_KEY = cfg.get('api_key')
    console.print(Panel('IntelX — Interactive TUI (auto-detecting API instance)', style='bold green'))
    if not API_KEY:
        console.print('[yellow]No API key detected. You can set INTELX_KEY env var or paste it now.[/]')
        key = Prompt.ask('Paste API key (leave empty to exit)') if RICH else input('Paste API key (leave empty to exit): ')
        if not key:
            console.print('No API key provided. Exiting.')
            sys.exit(1)
        API_KEY = key.strip()
        if Confirm.ask('Save API key to config file (~/.intelx_tui_config.json)?', default=False):
            cfg['api_key'] = API_KEY
            save_config(cfg)
            console.print('[green]API key saved to config.[/]')

    # Auto-detect best instance unless user already set a custom base
    if cfg.get('base_url'):
        BASE_URL = cfg.get('base_url')
    else:
        console.print('[blue]Auto-detecting best API instance for your API key...[/]')
        best, diag = detect_best_instance(API_KEY)
        if best:
            BASE_URL = best
            console.print(f'[green]Detected API instance: {BASE_URL}[/]')
            log(f'Auto-detected instance: {BASE_URL}')
        else:
            console.print('[yellow]Auto-detection failed. Diagnostics follow. You may set base URL manually in Settings.[/]')
            # pretty print diagnostics
            if RICH:
                for k, v in diag.items():
                    console.print(Panel(f"Host: {k}Info: {json.dumps(v, indent=2)[:2000]}"))
            else:
                print(diag)

    client = IntelXClient(API_KEY, base_url=BASE_URL)

    try:
        caps = client.capabilities()
    except Exception as e:
        console.print(f'[red]Failed to fetch capabilities: {e}[/]')
        caps = {}
    redacted = set(caps.get('redacted', [])) if isinstance(caps, dict) else set()
    allowed = set(caps.get('buckets', [])) if isinstance(caps, dict) else set()

    last_results: List[Dict[str, Any]] = []
    last_query = ''
    page_size = 10

    while True:
        main_opts = ['Show capabilities', 'Search', 'Browse last results', 'Export last results', 'Settings', 'Quit']
        choice = ask_menu('Main Menu', main_opts, allow_back=False)
        if choice is None:
            continue
        if choice == 0:
            if isinstance(caps, dict) and caps:
                console.print(Panel(json.dumps(caps, indent=2)[:4000]))
            else:
                console.print('[yellow]No capabilities data returned. This may indicate a wrong API instance or an API key without permissions.[/]')
                console.print('[blue]Tip: Open Settings -> Change base URL to try another instance (free.intelx.io / 2.intelx.io).[/]')
            continue
        if choice == 1:
            q = Prompt.ask('Enter search term / selector (email/domain/phone)') if RICH else input('Search term: ')
            if not q.strip():
                console.print('[yellow]Empty query. Back.[/]')
                continue
            buckets_in = Prompt.ask('Buckets (comma-separated) [empty = all]') if RICH else input('Buckets (comma-separated) [empty=all]: ')
            buckets = [b.strip() for b in buckets_in.split(',')] if buckets_in.strip() else None
            limit_str = Prompt.ask('Max results', default='100') if RICH else input('Max results (default 100): ')
            try:
                limit = max(1, int(limit_str))
            except Exception:
                limit = 100
            console.print(f'[blue]Searching for:[/] {q} [dim](buckets={buckets} limit={limit})[/]')
            try:
                raw = client.search(q, buckets=buckets, maxresults=limit)
            except Exception as e:
                console.print(f'[red]Search failed: {e}[/]')
                continue
            items = normalize(raw)
            for it in items:
                b = it.get('bucket')
                it['can_download'] = (b not in redacted)
            last_results = items
            last_query = q
            page = 0
            while True:
                if not last_results:
                    console.print('[yellow]No results.[/]')
                    break
                print_table(last_results, page=page, page_size=page_size, redacted=redacted, allowed=allowed)
                action_opts = ['View preview', 'Download item', 'Next page', 'Previous page', 'Change page size', 'Back to main']
                act = ask_menu('Actions', action_opts)
                if act is None or act == 5:
                    break
                if act == 2:
                    if (page+1)*page_size < len(last_results):
                        page += 1
                    else:
                        console.print('[yellow]Already at last page.[/]')
                    continue
                if act == 3:
                    if page > 0:
                        page -= 1
                    else:
                        console.print('[yellow]Already at first page.[/]')
                    continue
                if act == 4:
                    sz = Prompt.ask('New page size', default=str(page_size)) if RICH else input('New page size: ')
                    try:
                        page_size = max(1, int(sz))
                        page = 0
                    except Exception:
                        console.print('[red]Invalid number[/]')
                    continue
                if act == 0:
                    idx = Prompt.ask('Result number to view') if RICH else input('Result number: ')
                    try:
                        idxn = int(idx) - 1
                        if idxn < 0 or idxn >= len(last_results):
                            console.print('[red]Index out of range[/]')
                            continue
                    except Exception:
                        console.print('[red]Invalid index[/]')
                        continue
                    item = last_results[idxn]
                    raw_item = item.get('raw', {})
                    storageid = raw_item.get('storageid') or item.get('storageid')
                    media = raw_item.get('media') or item.get('media') or 0
                    type_ = raw_item.get('type') or item.get('type') or 0
                    bucket = item.get('bucket') or ''
                    try:
                        content = client.file_view(media, type_, storageid, bucket)
                        if not content:
                            console.print('[yellow]Empty preview (possibly binary or access restricted).[/]')
                        else:
                            if RICH:
                                console.pager(content)
                            else:
                                print(content[:4000])
                    except Exception as e:
                        console.print(f'[red]Failed to preview: {e}[/]')
                    continue
                if act == 1:
                    idx = Prompt.ask('Result number to download') if RICH else input('Result number: ')
                    try:
                        idxn = int(idx) - 1
                        if idxn < 0 or idxn >= len(last_results):
                            console.print('[red]Index out of range[/]')
                            continue
                    except Exception:
                        console.print('[red]Invalid index[/]')
                        continue
                    item = last_results[idxn]
                    if not item.get('can_download', False):
                        console.print('[yellow]This item is NOT downloadable with your current API key (redacted/restricted bucket).[/]')
                        continue
                    default_name = f"{item.get('systemid') or item.get('storageid')}.bin"
                    outname = Prompt.ask('Destination filename', default=default_name) if RICH else input(f"Destination filename (default {default_name}): ")
                    outname = outname.strip() or default_name
                    console.print(f'[blue]Downloading to {outname}[/]')
                    try:
                        written = client.file_read_stream(item.get('systemid') or item.get('storageid'), item.get('storageid'), item.get('bucket'), outname)
                        if written > 0:
                            console.print(f'[green]Download OK: {written} bytes -> {outname}[/]')
                        else:
                            console.print('[yellow]Download completed but file size is 0 bytes. Likely restricted or no content for your API key.[/]')
                    except Exception as e:
                        console.print(f'[red]Download failed: {e}[/]')
                    continue
        if choice == 2:
            if not last_results:
                console.print('[yellow]No cached results. Run a search first.[/]')
                continue
            page = 0
            while True:
                print_table(last_results, page=page, page_size=page_size, redacted=redacted, allowed=allowed)
                opts = ['View preview', 'Download item', 'Next', 'Prev', 'Back']
                a = ask_menu('Browse actions', opts)
                if a is None or a == 4:
                    break
                if a == 2:
                    if (page+1)*page_size < len(last_results):
                        page += 1
                    else:
                        console.print('[yellow]No more pages[/]')
                    continue
                if a == 3:
                    if page > 0:
                        page -= 1
                    continue
                if a == 0:
                    idx = Prompt.ask('Index to view') if RICH else input('Index to view: ')
                    try:
                        i = int(idx)-1
                        item = last_results[i]
                        content = client.file_view(item.get('media') or 0, item.get('type') or 0, item.get('storageid'), item.get('bucket'))
                        if RICH:
                            console.pager(content)
                        else:
                            print(content[:4000])
                    except Exception as e:
                        console.print(f'[red]Preview failed: {e}[/]')
                    continue
                if a == 1:
                    idx = Prompt.ask('Index to download') if RICH else input('Index to download: ')
                    try:
                        i = int(idx)-1
                        item = last_results[i]
                        if not item.get('can_download', False):
                            console.print('[yellow]Not downloadable with your API key[/]')
                            continue
                        dest = Prompt.ask('Destination filename', default=f"{item.get('systemid')}.bin") if RICH else input('Destination filename: ')
                        dest = dest.strip() or f"{item.get('systemid')}.bin"
                        written = client.file_read_stream(item.get('systemid'), item.get('storageid'), item.get('bucket'), dest)
                        console.print(f'[green]Downloaded {written} bytes -> {dest}[/]')
                    except Exception as e:
                        console.print(f'[red]Download error: {e}[/]')
                    continue
        if choice == 3:
            if not last_results:
                console.print('[yellow]No results to export.[/]')
                continue
            out = Prompt.ask('Output filename (csv or xlsx)', default='intelx_results.xlsx') if RICH else input('Output filename: ')
            try:
                if PANDAS and out.lower().endswith(('.xls', '.xlsx')):
                    df = pd.DataFrame(last_results)
                    df.to_excel(out, index=False)
                elif PANDAS and out.lower().endswith('.csv'):
                    df = pd.DataFrame(last_results)
                    df.to_csv(out, index=False)
                else:
                    import csv
                    keys = set()
                    for r in last_results:
                        keys.update(r.keys())
                    keys = list(keys)
                    with open(out, 'w', newline='', encoding='utf-8') as fh:
                        w = csv.DictWriter(fh, keys)
                        w.writeheader()
                        w.writerows(last_results)
                console.print(f'[green]Exported -> {out}[/]')
            except Exception as e:
                console.print(f'[red]Export failed: {e}[/]')
            continue
        if choice == 4:
            opts = ['Show / Save API key', 'Change base URL', 'Change page size', 'Back']
            s = ask_menu('Settings', opts)
            if s is None or s == 3:
                continue
            if s == 0:
                console.print('[bold]Current API key:[/]', API_KEY[:8] + '...' if API_KEY else '[NONE]')
                if Confirm.ask('Replace API key?', default=False):
                    new = Prompt.ask('Paste new API key') if RICH else input('Paste new API key: ')
                    if new:
                        API_KEY = new.strip()
                        cfg['api_key'] = API_KEY
                        if Confirm.ask('Save to config file?', default=False):
                            save_config(cfg)
                            console.print('[green]Saved.[/]')
                        # re-run autodetect
                        best, diag = detect_best_instance(API_KEY)
                        if best:
                            BASE_URL = best
                            console.print(f'[green]Auto-detected new instance: {BASE_URL}[/]')
                            client = IntelXClient(API_KEY, base_url=BASE_URL)
            if s == 1:
                nb = Prompt.ask('New base URL', default=BASE_URL) if RICH else input(f'New base URL (default {BASE_URL}): ')
                if nb:
                    BASE_URL = nb.strip()
                    cfg['base_url'] = BASE_URL
                    if Confirm.ask('Save base URL to config?', default=False):
                        save_config(cfg)
                    client = IntelXClient(API_KEY, base_url=BASE_URL)
                    console.print(f'[green]Base URL updated to {BASE_URL}[/]')
            if s == 2:
                ps = Prompt.ask('Page size', default=str(page_size)) if RICH else input('Page size: ')
                try:
                    page_size = int(ps)
                except Exception:
                    console.print('[red]Invalid[/]')
            continue
        if choice == 5:
            console.print('[bold]Goodbye[/]')
            break

if __name__ == '__main__':
    try:
        run_tui()
    except KeyboardInterrupt:
        console.print('Interrupted. Exiting.')
    except Exception as e:
        console.print(f'[red]Fatal error: {e}[/]')
        log(f'Fatal: {e}')
        sys.exit(1)
