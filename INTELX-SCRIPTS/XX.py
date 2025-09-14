
# intelx_cli_tool.py

import requests
import json
import time
import os

class IntelXAPI:
    def __init__(self, api_key, base_url="https://free.intelx.io/"):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            "x-key": self.api_key,
            "Content-Type": "application/json",
            "User-Agent": "IntelX-CLI-Tool/1.0"
        }

    def _make_request(self, method, endpoint, data=None, params=None):
        url = f"{self.base_url}{endpoint}"
        try:
            if method == "POST":
                response = requests.post(url, headers=self.headers, data=json.dumps(data))
            elif method == "GET":
                response = requests.get(url, headers=self.headers, params=params)
            else:
                raise ValueError("Unsupported HTTP method")
                      response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            return response.json()
        except requests.exceptions.HTTPError as e:
            print(f"Error: HTTP {e.response.status_code} - {e.response.text}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"Error: An unexpected error occurred - {e}")
            return None

    def search(self, query, max_results=10, media=0, sort=2):
        print(f"[INFO] Initiating search for: {query}")
        endpoint = "intelligent/search"
        payload = {
            "term": query,
            "maxresults": max_results,
            "media": media,
            "sort": sort
        }
        search_data = self._make_request("POST", endpoint, data=payload)
        if search_data and search_data.get("status") == 0:
            print(f"[SUCCESS] Search initiated. Search ID: {search_data.get('id')}")
            return search_data.get("id")
        else:
            print("[ERROR] Failed to initiate search.")
            return None

    def get_search_results(self, search_id):
        print(f"[INFO] Retrieving results for Search ID: {search_id}")
        endpoint = "intelligent/search/result"
        params = {"id": search_id}
        while True:
            results_data = self._make_request("GET", endpoint, params=params)
            if results_data:
                status = results_data.get("status")
                if status == 0: # Success with results
                    print("[INFO] Search results available.")
                    return results_data.get("records", [])
                elif status == 1: # No future results available, stop trying
                    print("[INFO] Search completed, no more results.")
                    return results_data.get("records", [])
                elif status == 3: # No results yet available but keep trying
                    print("[INFO] No results yet, retrying in 5 seconds...")
                    time.sleep(5)
                else:
                    print(f"[ERROR] Unexpected search result status: {status}")
                    return []
            else:
                print("[ERROR] Failed to retrieve search results.")
                return []

    def download_file(self, system_id, bucket, filename=None):
        print(f"[INFO] Attempting to download file with System ID: {system_id} from bucket: {bucket}")
        endpoint = "file/read"
        params = {"id": system_id, "bucket": bucket}
        url = f"{self.base_url}{endpoint}"
        try:
            response = requests.get(url, headers=self.headers, params=params, stream=True)
            response.raise_for_status()
             if filename is None:
                # Try to get filename from Content-Disposition header
                content_disposition = response.headers.get("Content-Disposition")
                if content_disposition:
                    # Example: attachment; filename="example.txt"
                    parts = content_disposition.split(";")
                    for part in parts:
                        if "filename=" in part:
                            filename = part.split("filename=")[1].strip("\"")
                            break
                if not filename:
                    filename = f"downloaded_file_{system_id}.bin"

            download_path = os.path.join(os.getcwd(), filename)
            with open(download_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"[SUCCESS] File downloaded to: {download_path}")
            return download_path
        except requests.exceptions.HTTPError as e:
            print(f"[ERROR] HTTP {e.response.status_code} - {e.response.text}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] An unexpected error occurred during download: {e}")
            return None

class IntelXCLI:
    def __init__(self, api_key):
        self.api = IntelXAPI(api_key)
        self.search_results = []

    def display_menu(self):
        print("\n--- IntelX CLI Tool Menu ---")
        print("1. Perform a new search")
        print("2. View current search results")
        print("3. Download a search result file")
        print("4. Exit")
        print("----------------------------")

    def run(self):
        while True:
            self.display_menu()
            choice = input("Enter your choice: ").strip()

            if choice == "1":
                self.handle_search()
            elif choice == "2":
                self.view_results()
            elif choice == "3":
                self.handle_download()
            elif choice == "4":
                print("Exiting IntelX CLI Tool. Goodbye!")
                break
            else:
                print("[WARNING] Invalid choice. Please try again.")

    def handle_search(self):
        query = input("Enter your search query (e.g., example.com, email@domain.com): ").strip()
        if not query:
            print("[WARNING] Search query cannot be empty.")
            return
        max_results_str = input("Enter max results (default 10): ").strip()
        max_results = int(max_results_str) if max_results_str.isdigit() else 10

        search_id = self.api.search(query, max_results=max_results)
        if search_id:
            self.search_results = self.api.get_search_results(search_id)
            if self.search_results:
                print(f"[INFO] Found {len(self.search_results)} results.")
                self.view_results()
            else:
                print("[INFO] No results found for your query.")

    def view_results(self):
        if not self.search_results:
            print("[INFO] No search results to display. Please perform a search first.")
            return
        print("\n--- Search Results ---")
        for i, result in enumerate(self.search_results):
            print(f'[{i+1}] System ID: {result.get("systemid")}')
            print(f"    Name: {result.get(\"name\", \"N/A\")}")
            print(f'    Bucket: {result.get("bucket", "N/A")}')
            print(f"    Media Type: {result.get("mediah", "N/A")}")
            print(f"    Description: {result.get("description", "N/A")}")
            print("------------------------")

    def handle_download(self):
        if not self.search_results:
            print("[INFO] No search results available to download. Please perform a search first.")
            return
        self.view_results()
        try:
            choice_index = int(input("Enter the number of the result to download: ").strip()) - 1
            if 0 <= choice_index < len(self.search_results):
                selected_result = self.search_results[choice_index]
                system_id = selected_result.get("systemid")
                bucket = selected_result.get("bucket")
                if system_id and bucket:
                    filename = input(f"Enter filename to save as (default: {system_id}.bin): ").strip()
                    self.api.download_file(system_id, bucket, filename if filename else None)
                else:
                    print("[ERROR] Missing System ID or Bucket for selected result.")
            else:
                print("[WARNING] Invalid result number.")
        except ValueError:
            print("[WARNING] Invalid input. Please enter a number.")

if __name__ == "__main__":
    # It's recommended to set your API key as an environment variable (INTELX_KEY)
    # For testing, you can hardcode it here, but remove before sharing.
    # api_key = os.getenv("INTELX_KEY") 
    api_key = "24fcfc64-849f-4e15-b365-40419b7d6624" # Replace with your actual API key

    if not api_key:
        print("Error: INTELX_KEY environment variable not set. Please set your IntelX API key.")
    else:
        cli = IntelXCLI(api_key)
        cli.run()

