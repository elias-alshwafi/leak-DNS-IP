#!/usr/bin/env python3
# INTX TUI - Interactive IntelX client
# Language: English
# Features: Search, view results, preview, download, export, account capabilities, phonebook search

import requests
import time
import json
import os
from rich.console import Console
from rich.table import Table

console = Console()

# ------------------ CONFIG ------------------
API_KEY = "24fcfc64-849f-4e15-b365-40419b7d6624"
HOST = "https://free.intelx.io/"
HEADERS = {"x-key": API_KEY}
SEARCH_WAIT = 3  # seconds to wait before fetching search results
# --------------------------------------------

last_search_id = None

def get_capabilities():
    url = f"{HOST}authenticate/info"
    try:
        r = requests.get(url, headers=HEADERS)
        return r.json()
    except Exception as e:
        console.print(f"[red]Error fetching capabilities: {e}[/red]")
        return {}

def start_search(selector, buckets="", limit=10):
    global last_search_id
    url = f"{HOST}intelligent/search"
    payload = {"selector": selector, "buckets": buckets, "limit": limit}
    try:
        r = requests.post(url, headers=HEADERS, json=payload)
        r.raise_for_status()
        data = r.json()
        last_search_id = data.get("id")
        console.print(f"[green]Search started. ID: {last_search_id}[/green]")
        return last_search_id
    except Exception as e:
        console.print(f"[red]Error starting search: {e}[/red]")
        return None

def fetch_results(search_id):
    url = f"{HOST}intelligent/search/result?id={search_id}&limit=50"
    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        r.raise_for_status()
        data = r.json()
        return data.get("items", [])
    except Exception as e:
        console.print(f"[red]Error fetching results: {e}[/red]")
        return []

def preview_file(storage_id, lines=20):
    url = f"{HOST}file/preview?id={storage_id}&lines={lines}"
    try:
        r = requests.get(url, headers=HEADERS)
        r.raise_for_status()
        console.print(r.text)
    except Exception as e:
        console.print(f"[red]Error previewing file: {e}[/red]")

def download_file(storage_id, filename):
    url = f"{HOST}file/read?id={storage_id}"
    try:
        r = requests.get(url, headers=HEADERS)
        r.raise_for_status()
        with open(filename, "wb") as f:
            f.write(r.content)
        console.print(f"[green]File downloaded: {filename}[/green]")
    except Exception as e:
        console.print(f"[red]Error downloading file: {e}[/red]")

def export_selector_list(search_id, filename="export.csv"):
    url = f"{HOST}item/selector/list/export?id={search_id}"
    try:
        r = requests.get(url, headers=HEADERS)
        r.raise_for_status()
        with open(filename, "w") as f:
            f.write(r.text)
        console.print(f"[green]Exported selector list to {filename}[/green]")
    except Exception as e:
        console.print(f"[red]Error exporting selector list: {e}[/red]")

def phonebook_search(query):
    url = f"{HOST}phonebook/search/result?query={query}"
    try:
        r = requests.get(url, headers=HEADERS)
        r.raise_for_status()
        items = r.json().get("items", [])
        table = Table(title="Phonebook Results")
        table.add_column("ID")
        table.add_column("Name")
        table.add_column("Phone")
        for item in items:
            table.add_row(str(item.get("id", "")), item.get("name", ""), item.get("phone", ""))
        console.print(table)
    except Exception as e:
        console.print(f"[red]Error in phonebook search: {e}[/red]")

def main_menu():
    global API_KEY, HOST, HEADERS
    while True:
        console.print("\n[bold cyan]IntelX TUI - Interactive client[/bold cyan]")
        console.print("1) Search (email / phone / domain / IP)")
        console.print("2) View last search results / list search ID")
        console.print("3) Preview file (lines)")
        console.print("4) Download file")
        console.print("5) Export selector list (CSV)")
        console.print("6) Show account capabilities")
        console.print("7) Change settings (API key / Host)")
        console.print("8) Phonebook search")
        console.print("9) Exit")
        choice = input("Choose option [1-9]: ").strip()

        if choice == "1":
            selector = input("Enter selector (email, phone, domain, IP): ").strip()
            buckets = input("Buckets (comma-separated, leave blank for default): ").strip()
            limit = input("Max results (10): ").strip()
            limit = int(limit) if limit.isdigit() else 10
            sid = start_search(selector, buckets, limit)
            if sid:
                console.print(f"Waiting {SEARCH_WAIT} seconds for results...")
                time.sleep(SEARCH_WAIT)

        elif choice == "2":
            sid = input(f"Enter search ID (or press Enter for last) [{last_search_id}]: ").strip()
            sid = sid or last_search_id
            if sid:
                items = fetch_results(sid)
                if items:
                    table = Table(title="Search Results")
                    table.add_column("ID")
                    table.add_column("Selector")
                    table.add_column("Bucket")
                    for item in items:
                        table.add_row(str(item.get("id", "")), str(item.get("selector", "")), str(item.get("bucket", "")))
                    console.print(table)
                else:
                    console.print("[yellow]No results found[/yellow]")
            else:
                console.print("[red]No search ID provided[/red]")

        elif choice == "3":
            storage_id = input("Enter storage ID: ").strip()
            lines = input("Lines to preview (20): ").strip()
            lines = int(lines) if lines.isdigit() else 20
            preview_file(storage_id, lines)

        elif choice == "4":
            storage_id = input("Enter storage ID: ").strip()
            filename = input("Enter filename to save as: ").strip()
            if filename:
                download_file(storage_id, filename)
            else:
                console.print("[red]Filename required[/red]")

        elif choice == "5":
            sid = input(f"Enter search ID (or press Enter for last) [{last_search_id}]: ").strip()
            sid = sid or last_search_id
            filename = input("Enter filename for export (CSV): ").strip()
            filename = filename or "export.csv"
            if sid:
                export_selector_list(sid, filename)
            else:
                console.print("[red]No search ID provided[/red]")

        elif choice == "6":
            caps = get_capabilities()
            console.print_json(json.dumps(caps, indent=2))

        elif choice == "7":
            new_key = input("New API key (blank to keep current): ").strip()
            if new_key:
                API_KEY = new_key
                HEADERS = {"x-key": API_KEY}
                console.print("[green]API key updated[/green]")
            new_host = input("New host (blank to keep current): ").strip()
            if new_host:
                HOST = new_host if new_host.endswith("/") else new_host + "/"
                console.print(f"[green]Host updated to {HOST}[/green]")

        elif choice == "8":
            query = input("Phonebook query (name, phone, email): ").strip()
            phonebook_search(query)

        elif choice == "9":
            console.print("[bold red]Exiting...[/bold red]")
            break
        else:
            console.print("[red]Invalid choice[/red]")

if __name__ == "__main__":
    main_menu()
