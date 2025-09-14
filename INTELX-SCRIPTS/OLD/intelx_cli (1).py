
import requests
import json
import os
import datetime

INTELX_KEY = "24fcfc64-849f-4e15-b365-40419b7d6624"
INTELX_URL = "https://free.intelx.io/"

# --- Helper Functions ---

def _make_request(method, endpoint, json_data=None, params=None, stream=False):
    headers = {
        "x-key": INTELX_KEY,
        "User-Agent": "IntelX-CLI-Tool/2.0"
    }
    url = f"{INTELX_URL}{endpoint}"

    try:
        if method == "POST":
            response = requests.post(url, json=json_data, headers=headers, stream=stream)
        elif method == "GET":
            response = requests.get(url, params=params, headers=headers, stream=stream)
        else:
            print("Error: Unsupported HTTP method.")
            return None

        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        if stream:
            return response
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e.response.status_code} - {e.response.text}")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"Connection Error: {e}")
        return None
    except requests.exceptions.Timeout as e:
        print(f"Timeout Error: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"An unexpected error occurred: {e}")
        return None

def get_user_input(prompt, input_type=str, default=None, validation_func=None):
    while True:
        user_input = input(prompt).strip()
        if not user_input and default is not None:
            return default
        if not user_input and default is None:
            print("Input cannot be empty. Please try again.")
            continue
        try:
            value = input_type(user_input)
            if validation_func and not validation_func(value):
                print("Invalid input. Please try again.")
                continue
            return value
        except ValueError:
            print(f"Invalid input type. Expected {input_type.__name__}. Please try again.")

def validate_date(date_str):
    if not date_str:
        return True # Allow empty date strings
    try:
        datetime.datetime.strptime(date_str, "%Y-%m-%d")
        return True
    except ValueError:
        print("Invalid date format. Please use YYYY-MM-DD.")
        return False

def display_results(results):
    if not results or not results.get("records"):
        print("No results found.")
        return

    print("\n--- Search Results ---")
    for i, record in enumerate(results["records"]):
        print(f"\nResult {i+1}:")
        for key, value in record.items():
            # Basic formatting for better readability
            if isinstance(value, dict) or isinstance(value, list):
                print(f"  {key}: {json.dumps(value, indent=2)}")
            else:
                print(f"  {key}: {value}")
    print("\n----------------------")

# --- API Functions ---

def intelligent_search():
    print("\n--- Intelligent Search ---")
    term = get_user_input("Enter search term (e.g., email, domain, IP): ")
    
    maxresults = get_user_input("Max results per bucket (default: 100): ", int, 100, lambda x: x > 0)
    
    sort_options = {
        0: "No sorting",
        1: "X-Score ASC",
        2: "X-Score DESC",
        3: "Date ASC",
        4: "Date DESC"
    }
    print("\nSort options:")
    for k, v in sort_options.items():
        print(f"  {k}: {v}")
    sort = get_user_input("Enter sort option (default: 2): ", int, 2, lambda x: x in sort_options)

    media_options = {
        0: "Not set", 1: "Paste Document", 2: "Paste User", 3: "Forum", 4: "Forum Board",
        5: "Forum Thread", 6: "Forum Post", 7: "Forum User", 8: "Screenshot of a Website",
        9: "HTML copy of a Website", 13: "Tweet", 14: "URL", 15: "PDF document",
        16: "Word document", 17: "Excel document", 18: "PowerPoint document",
        19: "Picture", 20: "Audio file", 21: "Video file", 22: "Container files",
        23: "HTML file", 24: "Text file", 32: "CSV File"
    }
    print("\nMedia type options:")
    for k, v in media_options.items():
        print(f"  {k}: {v}")
    media = get_user_input("Enter media type (default: 0): ", int, 0, lambda x: x in media_options)

    timeout = get_user_input("Timeout in seconds (default: 0 for default API timeout): ", int, 0, lambda x: x >= 0)
    datefrom = get_user_input("Start date (YYYY-MM-DD, optional): ", str, "", validate_date)
    dateto = get_user_input("End date (YYYY-MM-DD, optional): ", str, "", validate_date)

    buckets_input = get_user_input("Enter buckets to search (comma-separated, optional): ", str, "")
    buckets = [b.strip() for b in buckets_input.split(",")] if buckets_input else []

    json_data = {
        "term": term,
        "buckets": buckets,
        "lookuplevel": 0,
        "maxresults": maxresults,
        "timeout": timeout,
        "datefrom": datefrom,
        "dateto": dateto,
        "sort": sort,
        "media": media,
        "terminate": []
    }
    
    print("Submitting search request...")
    response = _make_request("POST", "intelligent/search", json_data=json_data)
    if response:
        search_id = response.get("id")
        status = response.get("status")
        softselectorwarning = response.get("softselectorwarning")

        print(f"Search ID: {search_id}")
        print(f"Status: {status}")
        if softselectorwarning:
            print("Warning: Soft selector used. Results might be broad.")
        
        if search_id:
            print("Fetching results...")
            get_search_results(search_id)
        else:
            print("Failed to get a search ID.")

def get_search_results(search_id):
    print(f"\n--- Retrieving Results for Search ID: {search_id} ---")
    offset = 0
    limit = 100
    all_records = []

    while True:
        params = {
            "id": search_id,
            "offset": offset,
            "limit": limit
        }
        response = _make_request("GET", "intelligent/search/result", params=params)
        if not response:
            break

        status = response.get("status")
        records = response.get("records", [])
        all_records.extend(records)

        if status == 0: # Success with results
            print(f"Fetched {len(records)} records. Total: {len(all_records)}")
            offset += len(records)
            if len(records) < limit: # Less than limit means no more pages
                break
        elif status == 1: # No future results available, stop trying.
            print("No more results available. Search terminated.")
            break
        elif status == 2: # Search ID not found
            print("Search ID not found.")
            break
        elif status == 3: # No results yet available but keep trying.
            print("No results yet. Waiting and retrying...")
            # In a real application, you might want to add a delay here
            # time.sleep(5)
            pass # For now, just loop again quickly
        else:
            print(f"Unknown status: {status}")
            break
    
    if all_records:
        display_results({"records": all_records})
        post_search_options(all_records)
    else:
        print("No records found for this search.")

def post_search_options(records):
    while True:
        print("\n--- Post-Search Options ---")
        print("1. View a specific result (by index)")
        print("2. Download a specific file (by System ID)")
        print("3. Return to Main Menu")
        choice = get_user_input("Enter your choice: ", int)

        if choice == 1:
            if not records:
                print("No records to view.")
                continue
            index = get_user_input(f"Enter result number to view (1-{len(records)}): ", int, validation_func=lambda x: 1 <= x <= len(records))
            system_id = records[index-1].get("systemid")
            if system_id:
                view_file(system_id)
            else:
                print("System ID not found for this record.")
        elif choice == 2:
            if not records:
                print("No records to download.")
                continue
            system_id = get_user_input("Enter System ID of the file to download: ")
            output_filename = get_user_input("Enter output filename (e.g., file.txt): ")
            read_file(system_id, output_filename)
        elif choice == 3:
            break
        else:
            print("Invalid choice. Please try again.")

def terminate_intelligent_search():
    print("\n--- Terminate Search ---")
    search_id = get_user_input("Enter Search ID to terminate: ")
    json_data = {"id": search_id}
    response = _make_request("POST", "intelligent/search/terminate", json_data=json_data)
    if response:
        print(f"Search ID {search_id} terminated successfully.")

def phonebook_search():
    print("\n--- Phonebook Search ---")
    selector = get_user_input("Enter selector for phonebook search (e.g., domain): ")
    maxresults = get_user_input("Max results (default: 100): ", int, 100, lambda x: x > 0)

    json_data = {
        "selector": selector,
        "maxresults": maxresults
    }
    print("Submitting phonebook search request...")
    response = _make_request("POST", "phonebook/search", json_data=json_data)
    if response:
        search_id = response.get("id")
        status = response.get("status")
        print(f"Phonebook Search ID: {search_id}")
        print(f"Status: {status}")
        if search_id:
            print("Fetching phonebook results...")
            get_phonebook_results(search_id)
        else:
            print("Failed to get a phonebook search ID.")

def get_phonebook_results(search_id):
    print(f"\n--- Retrieving Phonebook Results for Search ID: {search_id} ---")
    offset = 0
    limit = 100
    all_records = []

    while True:
        params = {
            "id": search_id,
            "offset": offset,
            "limit": limit
        }
        response = _make_request("GET", "phonebook/search/result", params=params)
        if not response:
            break

        status = response.get("status")
        records = response.get("records", [])
        all_records.extend(records)

        if status == 0: # Success with results
            print(f"Fetched {len(records)} records. Total: {len(all_records)}")
            offset += len(records)
            if len(records) < limit:
                break
        elif status == 1: # No future results available
            print("No more results available. Phonebook search terminated.")
            break
        elif status == 2: # Search ID not found
            print("Phonebook Search ID not found.")
            break
        elif status == 3: # No results yet available
            print("No results yet. Waiting and retrying...")
            pass
        else:
            print(f"Unknown status: {status}")
            break
    
    if all_records:
        display_results({"records": all_records})
    else:
        print("No records found for this phonebook search.")

def read_file(system_id, output_file):
    print(f"\n--- Reading File with System ID: {system_id} ---")
    params = {"id": system_id}
    response = _make_request("GET", "file/read", params=params, stream=True)
    if response:
        try:
            with open(output_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"File successfully saved to {output_file}")
        except IOError as e:
            print(f"Error saving file: {e}")

def view_file(system_id):
    print(f"\n--- Viewing File with System ID: {system_id} ---")
    params = {"id": system_id}
    response = _make_request("GET", "file/view", params=params)
    if response:
        print("\n--- File Content ---")
        print(response) # This will print the raw content
        print("\n--------------------")

def preview_file(system_id):
    print(f"\n--- Previewing File with System ID: {system_id} ---")
    params = {"id": system_id}
    response = _make_request("GET", "file/preview", params=params)
    if response:
        print("\n--- File Preview (max 1000 chars) ---")
        print(response)
        print("\n------------------------------------")

# --- Main Menu ---

def main_menu():
    while True:
        print("\n--- IntelX CLI Tool Main Menu ---")
        print("1. Intelligent Search")
        print("2. Phonebook Search")
        print("3. File Operations (View/Read/Preview)")
        print("4. Terminate an Intelligent Search")
        print("5. Exit")

        choice = get_user_input("Enter your choice: ", int)

        if choice == 1:
            intelligent_search()
        elif choice == 2:
            phonebook_search()
        elif choice == 3:
            file_operations_menu()
        elif choice == 4:
            terminate_intelligent_search()
        elif choice == 5:
            print("Exiting IntelX CLI Tool. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")

def file_operations_menu():
    while True:
        print("\n--- File Operations Menu ---")
        print("1. View File (inline)")
        print("2. Preview File (first 1000 chars)")
        print("3. Read/Download File")
        print("4. Return to Main Menu")

        choice = get_user_input("Enter your choice: ", int)

        if choice == 1:
            system_id = get_user_input("Enter System ID to view: ")
            view_file(system_id)
        elif choice == 2:
            system_id = get_user_input("Enter System ID to preview: ")
            preview_file(system_id)
        elif choice == 3:
            system_id = get_user_input("Enter System ID to read/download: ")
            output_file = get_user_input("Enter output filename (e.g., document.pdf): ")
            read_file(system_id, output_file)
        elif choice == 4:
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")

if __name__ == '__main__':
    main_menu()


