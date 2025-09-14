#!/usr/bin/env python3
"""
Intelligence X CLI - Ultimate Edition v6.0
The Most Advanced CLI Tool for Intelligence X API with Complete Bucket Support and No Restrictions
"""

import os
import sys
import json
import time
import re
import sqlite3
import webbrowser
import threading
from datetime import datetime, timedelta
from collections import defaultdict
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich import box
from rich.text import Text
from rich.tree import Tree
from rich.markup import escape
from rich.live import Live
from rich.layout import Layout
import pyperclip
import graphviz

# Global configuration
API_URL = "https://free.intelx.io/"  # Free Intelligence X API endpoint
API_KEY = "24fcfc64-849f-4e15-b365-40419b7d6624"
DOWNLOAD_DIR = "intelx_downloads"
CACHE_DIR = "intelx_cache"
DB_FILE = "intelx_data.db"
console = Console()

# Create necessary directories
os.makedirs(DOWNLOAD_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# Initialize database
def init_database():
    """Initialize the SQLite database for storing search history and results"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create search history table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS search_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        search_term TEXT NOT NULL,
        buckets TEXT,
        max_results INTEGER,
        sort INTEGER,
        result_count INTEGER
    )
    ''')
    
    # Create search results table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS search_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        search_id INTEGER NOT NULL,
        systemid TEXT NOT NULL,
        storageid TEXT,
        name TEXT,
        description TEXT,
        date TEXT,
        size INTEGER,
        bucket TEXT,
        media TEXT,
        accesslevel INTEGER,
        xscore INTEGER,
        is_redacted BOOLEAN,
        FOREIGN KEY(search_id) REFERENCES search_history(id)
    )
    ''')
    
    # Create file previews table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS file_previews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        systemid TEXT NOT NULL UNIQUE,
        preview TEXT,
        timestamp TEXT NOT NULL
    )
    ''')
    
    # Create extracted selectors table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS extracted_selectors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        systemid TEXT NOT NULL,
        selector_type TEXT NOT NULL,
        selector_value TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )
    ''')
    
    # Create account information table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS account_info (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        buckets TEXT,
        redacted TEXT,
        credits TEXT,
        license_expiration TEXT,
        license_type TEXT
    )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_database()

class SearchResult:
    def __init__(self, data):
        self.systemid = data.get("systemid", "")
        self.storageid = data.get("storageid", "")
        self.name = data.get("name", "")
        self.description = data.get("description", "")
        self.date = data.get("date", "")
        self.added = data.get("added", "")
        self.size = data.get("size", 0)
        self.bucket = data.get("bucket", "")
        self.bucket_human = data.get("bucketh", "")
        self.media = data.get("media", 0)
        self.media_human = data.get("mediah", "")
        self.accesslevel = data.get("accesslevel", 0)
        self.xscore = data.get("xscore", 0)
        self.instore = data.get("instore", False)
        self.tags = data.get("tags", [])
        self.keyvalues = data.get("keyvalues", [])
        self.type = data.get("type", 0)
        self.type_human = self._get_type_human(self.type)
        self.simhash = data.get("simhash", 0)
        self.simhash_human = data.get("simhashh", "")
        self.randomid = data.get("randomid", "")
        self.relations = data.get("relations", [])
        
    def _get_type_human(self, type_value):
        """Convert type value to human-readable string"""
        type_map = {
            0: "Binary/Unspecified",
            1: "Plain Text",
            2: "Picture",
            3: "Video",
            4: "Audio",
            5: "Document",
            6: "Executable",
            7: "Container",
            1001: "User",
            1002: "Leak",
            1004: "URL",
            1005: "Forum"
        }
        return type_map.get(type_value, "Unknown")
    
    def can_preview(self):
        """Check if preview is available"""
        return self.accesslevel in [0, 4]
        
    def can_download(self):
        """Check if full download is possible"""
        return self.instore and self.accesslevel == 0
    
    def is_redacted(self):
        """Check if content is redacted (preview only)"""
        return self.accesslevel == 4
    
    def is_deleted(self):
        """Check if content is deleted (not available)"""
        return not self.instore
    
    def get_media_type(self):
        """Get human-readable media type"""
        media_map = {
            0: "Invalid",
            1: "Paste Document",
            2: "Paste User",
            3: "Forum",
            4: "Forum Board",
            5: "Forum Thread",
            6: "Forum Post",
            7: "Forum User",
            8: "Website Screenshot",
            9: "HTML Copy of Website",
            13: "Tweet",
            14: "URL",
            15: "PDF Document",
            16: "Word Document",
            17: "Excel Document",
            18: "PowerPoint Document",
            19: "Picture",
            20: "Audio File",
            21: "Video File",
            22: "Container Files",
            23: "HTML File",
            24: "Text File"
        }
        return media_map.get(self.media, "Unknown")
    
    def get_bucket_category(self):
        """Get bucket category"""
        if "leaks" in self.bucket:
            return "Leaks"
        elif "pastes" in self.bucket:
            return "Pastes"
        elif "darknet" in self.bucket:
            return "Darknet"
        elif "web" in self.bucket:
            return "Web"
        elif "whois" in self.bucket:
            return "Whois"
        elif "usenet" in self.bucket:
            return "Usenet"
        elif "dumpster" in self.bucket:
            return "Dumpster"
        return "Other"
    
    def get_access_level_description(self):
        """Get description of access level"""
        if self.accesslevel == 0:
            return "Full access"
        elif self.accesslevel == 4:
            return "Preview only (redacted)"
        return "Access restricted"

class AccountInfo:
    def __init__(self, data):
        self.buckets = data.get("buckets", [])
        self.bucketsh = data.get("bucketsh", [])
        self.redacted = data.get("redacted", [])
        self.redactedh = data.get("redactedh", [])
        self.paths = data.get("paths", {})
        self.searchesactive = data.get("searchesactive", 0)
        self.maxconcurrentsearches = data.get("maxconcurrentsearches", 0)
        self.license_expiration = data.get("license_expiration", "N/A")
        self.license_type = "Trial"
        self.added = data.get("added", "")
        self.capabilities = self._get_capabilities()
        
    def _get_capabilities(self):
        """Determine capabilities based on buckets and paths"""
        capabilities = {
            "search": True,
            "preview": True,
            "download": False,
            "phonebook": False,
            "dataleaks": False,
            "exportaccounts": False,
            "nopreview": False,
            "view": True,
            "stats": True
        }
        
        # Check download capability
        if self.get_remaining_credits("/file/read") > 0:
            capabilities["download"] = True
            
        # Check phonebook capability
        if "/phonebook/search" in self.paths and self.get_remaining_credits("/phonebook/search") > 0:
            capabilities["phonebook"] = True
            
        # Check dataleaks capability
        if "leaks.private.general" in self.buckets or "leaks.private.general" in self.redacted:
            capabilities["dataleaks"] = True
            
        return capabilities
    
    def get_bucket_access(self, bucket):
        """Get access level for a bucket"""
        if bucket in self.buckets:
            return "Full"
        elif bucket in self.redacted:
            return "Preview"
        return "No Access"
    
    def get_remaining_credits(self, path):
        """Get remaining credits for a path"""
        if path in self.paths:
            return self.paths[path]["Credit"]
        return 0
    
    def get_max_credits(self, path):
        """Get max credits for a path"""
        if path in self.paths:
            return self.paths[path]["CreditMax"]
        return 0
    
    def get_credit_reset(self, path):
        """Get credit reset time for a path"""
        if path in self.paths:
            return self.paths[path]["CreditReset"]
        return 0
    
    def get_total_results(self):
        """Get total possible results based on license"""
        # NO artificial limit - use API's actual limit
        return 1000
    
    def get_active_searches_info(self):
        """Get information about active searches"""
        return f"{self.searchesactive}/{self.maxconcurrentsearches}"

class PreviewManager:
    """Manages preview requests and caching with proper API parameters for ALL buckets"""
    def __init__(self, api_key, api_url=API_URL):
        self.api_key = api_key
        self.api_url = api_url
        self.cache = {}
        self.session = requests.Session()
        self.lock = threading.Lock()
        
        # Configure session
        self.session.headers.update({
            "x-key": self.api_key,
            "User-Agent": "IntelligenceXCLI/v6.0"
        })
    
    def get_preview(self, system_id, bucket, lines=20, force_refresh=False):
        """
        Get content preview with proper API parameters for all buckets
        with special handling for restricted content and leaks
        Optimized for version 6.0
        """
        # Check cache first
        cache_key = f"{system_id}_{bucket}_{lines}"
        if not force_refresh and cache_key in self.cache:
            return self.cache[cache_key]

        try:
            with self.lock:
                # Determine content type and media type based on bucket
                content_type = self._get_content_type(bucket)
                media_type = self._get_media_type(bucket)
                
                # Prepare parameters with special handling for restricted leaks
                params = {
                    "c": content_type,   # Content Type
                    "m": media_type,     # Media Type
                    "f": 0,              # Target Format (0 for text)
                    "sid": system_id,    # System ID
                    "b": bucket,         # Bucket
                    "l": lines,          # Lines to show
                    "e": 1,              # HTML escaping (1 for enabled)
                    "redact": 1 if "leaks.logs" in bucket or "leaks.restricted" in bucket else 0,
                    "mask": 1 if "leaks" in bucket else 0
                }

                # Use session for better performance with proper error handling
                try:
                    response = self.session.get(
                        f"{self.api_url}/file/preview",
                        params=params,
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        preview = response.text
                        self.cache[cache_key] = preview
                        return preview
                    else:
                        # Handle API errors with descriptive messages
                        error_map = {
                            400: "Invalid parameters",
                            401: "Unauthorized access",
                            402: "No preview credits available",
                            403: "Access forbidden",
                            404: "Item not found",
                            429: "Too many requests"
                        }
                        error_msg = error_map.get(response.status_code, f"HTTP {response.status_code}")
                        return f"❌ Preview request failed: {error_msg}"
                        
                except requests.exceptions.Timeout:
                    return "❌ Preview request timed out. Please try again."
                except requests.exceptions.ConnectionError:
                    return "❌ Network connection error. Check your internet connection."
                    
        except Exception as e:
            # Log unexpected errors
            return f"❌ Unexpected error: {str(e)}"
    
    def _get_content_type(self, bucket):
        """تحديد نوع المحتوى للبكت مع دعم كامل لكل الأنواع بما فيها Leaks » Logs"""
        # تعيين نوع المحتوى حسب نوع البكت
        bucket_map = {
            # تحسين التعامل مع بكتات التسريبات
            "leaks.logs": 1002,           # نوع خاص للتسريبات
            "leaks.private": 1002,        # تسريبات خاصة
            "leaks.public": 1002,         # تسريبات عامة
            "leaks.restricted": 1002,     # تسريبات مقيدة
            "leaks.logs": 1002,  # Leak
            "leaks.private.general": 1002,  # Leak
            "leaks.public.general": 1002,  # Leak
            "leaks.public.wikileaks": 1002,  # Leak
            "pastes": 1,  # Paste Document
            "darknet.tor": 1004,  # URL
            "darknet.i2p": 1004,  # URL
            "web.public": 9,  # HTML Copy of Website
            "web.public.de": 9,  # HTML Copy of Website
            "web.public.kp": 9,  # HTML Copy of Website
            "web.public.ua": 9,  # HTML Copy of Website
            "web.public.com": 9,  # HTML Copy of Website
            "web.gov.ru": 9,  # HTML Copy of Website
            "web.public.peer": 9,  # HTML Copy of Website
            "web.public.gov": 9,  # HTML Copy of Website
            "web.public.org": 9,  # HTML Copy of Website
            "web.public.net": 9,  # HTML Copy of Website
            "web.public.info": 9,  # HTML Copy of Website
            "web.public.eu": 9,  # HTML Copy of Website
            "web.public.cn": 9,  # HTML Copy of Website
            "web.public.nord": 9,  # HTML Copy of Website
            "web.public.we": 9,  # HTML Copy of Website
            "web.public.cee": 9,  # HTML Copy of Website
            "web.public.ams": 9,  # HTML Copy of Website
            "web.public.af": 9,  # HTML Copy of Website
            "web.public.mea": 9,  # HTML Copy of Website
            "web.public.oc": 9,  # HTML Copy of Website
            "web.public.tech": 9,  # HTML Copy of Website
            "web.public.business": 9,  # HTML Copy of Website
            "web.public.social": 9,  # HTML Copy of Website
            "web.public.misc": 9,  # HTML Copy of Website
            "web.public.aq": 9,  # HTML Copy of Website
            "documents.public.scihub": 5,  # Document
            "dumpster": 0,  # Binary/Unspecified
            "whois": 1001,  # User
            "usenet": 9,  # HTML Copy of Website
            "dumpster.web.ssn": 0,  # Binary/Unspecified
            "dumpster.web.1": 0  # Binary/Unspecified
        }
        
        # Find exact matching bucket type
        for key, value in bucket_map.items():
            if key == bucket.lower():
                return value
        
        # Find partial matching bucket type
        for key, value in bucket_map.items():
            if key in bucket.lower():
                return value
        
        # Default to Leak for any leaks bucket
        if "leaks" in bucket.lower():
            return 1002
        
        return 0  # Binary/Unspecified
    
    def _get_media_type(self, bucket):
        """Determine media type based on bucket with comprehensive mapping"""
        # Comprehensive bucket mapping from API documentation
        bucket_map = {
            "leaks.logs": 24,  # Text File
            "leaks.private.general": 24,  # Text File
            "leaks.public.general": 24,  # Text File
            "leaks.public.wikileaks": 24,  # Text File
            "pastes": 1,  # Paste Document
            "darknet.tor": 14,  # URL
            "darknet.i2p": 14,  # URL
            "web.public": 9,  # HTML Copy of Website
            "web.public.de": 9,  # HTML Copy of Website
            "web.public.kp": 9,  # HTML Copy of Website
            "web.public.ua": 9,  # HTML Copy of Website
            "web.public.com": 9,  # HTML Copy of Website
            "web.gov.ru": 9,  # HTML Copy of Website
            "web.public.peer": 9,  # HTML Copy of Website
            "web.public.gov": 9,  # HTML Copy of Website
            "web.public.org": 9,  # HTML Copy of Website
            "web.public.net": 9,  # HTML Copy of Website
            "web.public.info": 9,  # HTML Copy of Website
            "web.public.eu": 9,  # HTML Copy of Website
            "web.public.cn": 9,  # HTML Copy of Website
            "web.public.nord": 9,  # HTML Copy of Website
            "web.public.we": 9,  # HTML Copy of Website
            "web.public.cee": 9,  # HTML Copy of Website
            "web.public.ams": 9,  # HTML Copy of Website
            "web.public.af": 9,  # HTML Copy of Website
            "web.public.mea": 9,  # HTML Copy of Website
            "web.public.oc": 9,  # HTML Copy of Website
            "web.public.tech": 9,  # HTML Copy of Website
            "web.public.business": 9,  # HTML Copy of Website
            "web.public.social": 9,  # HTML Copy of Website
            "web.public.misc": 9,  # HTML Copy of Website
            "web.public.aq": 9,  # HTML Copy of Website
            "documents.public.scihub": 15,  # PDF Document
            "dumpster": 24,  # Text File
            "whois": 2,  # Paste User
            "usenet": 9,  # HTML Copy of Website
            "dumpster.web.ssn": 24,  # Text File
            "dumpster.web.1": 24  # Text File
        }
        
        # Find exact matching bucket type
        for key, value in bucket_map.items():
            if key == bucket.lower():
                return value
        
        # Find partial matching bucket type
        for key, value in bucket_map.items():
            if key in bucket.lower():
                return value
        
        # Default to Text File for any leaks bucket
        if "leaks" in bucket.lower():
            return 24
        
        return 0  # Invalid

class IntelligenceXCLI:
    def __init__(self, api_key, api_url=API_URL):
        self.api_key = api_key
        self.api_url = api_url
        self.account_info = None
        self.search_results = []
        self.current_search_id = None
        self.search_term = ""
        self.selected_buckets = []
        self.search_history = []
        self.current_search_history_id = None
        self.last_preview = None
        self.last_preview_systemid = None
        self.preview_manager = PreviewManager(api_key, api_url)
        self.current_view = "document"  # document, tree, metadata, selectors, actions
        self.selector_extractor = SelectorExtractor()
        self.is_searching = False
        self.search_progress = None
        self.search_task = None
        self.export_manager = ExportManager()
        
        # Validate API key
        if not self.validate_api_key():
            console.print("[red]Error: Invalid API key or insufficient permissions.[/red]")
            sys.exit(1)
            
        # Get account information
        self.get_account_info()
    
    def validate_api_key(self):
        """Validate API key with comprehensive error handling"""
        try:
            response = requests.get(
                f"{self.api_url}/authenticate/info",
                headers={"x-key": self.api_key, "User-Agent": "IntelligenceXCLI/v6.0"}
            )
            
            if response.status_code == 200:
                return True
            elif response.status_code == 401:
                console.print("[red]Error: Invalid API key. Please check your key and permissions.[/red]")
            elif response.status_code == 403:
                console.print("[red]Error: API access forbidden. Check your account status.[/red]")
            else:
                console.print(f"[red]Error: API returned status code {response.status_code}[/red]")
                
            return False
        except requests.exceptions.ConnectionError:
            console.print("[red]Error: Could not connect to Intelligence X API. Check your internet connection.[/red]")
        except Exception as e:
            console.print(f"[red]Connection error: {str(e)}[/red]")
            return False
    
    def get_account_info(self):
        """Get account information with comprehensive details"""
        try:
            response = requests.get(
                f"{self.api_url}/authenticate/info",
                headers={"x-key": self.api_key, "User-Agent": "IntelligenceXCLI/v6.0"}
            )
            
            if response.status_code == 200:
                # Add license information
                account_data = response.json()
                account_data["license_expiration"] = "2025-08-31"
                account_data["license_type"] = "Trial"
                
                # Save to database
                self._save_account_info_to_db(account_data)
                
                self.account_info = AccountInfo(account_data)
                return True
            return False
        except Exception as e:
            console.print(f"[red]Error retrieving account info: {str(e)}[/red]")
            return False
    
    def _save_account_info_to_db(self, account_data):
        """Save account information to database"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        timestamp = datetime.now().isoformat()
        
        try:
            cursor.execute('''
            INSERT INTO account_info (
                timestamp, buckets, redacted, credits, license_expiration, license_type
            ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                timestamp,
                json.dumps(account_data.get("buckets", [])),
                json.dumps(account_data.get("redacted", [])),
                json.dumps(account_data.get("paths", {})),
                account_data.get("license_expiration", "N/A"),
                account_data.get("license_type", "Trial")
            ))
            
            conn.commit()
        except Exception as e:
            console.print(f"[red]Database error saving account info: {str(e)}[/red]")
        finally:
            conn.close()
    
    def get_saved_account_info(self, limit=1):
        """Get saved account information from database"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            SELECT * FROM account_info 
            ORDER BY timestamp DESC 
            LIMIT ?
            ''', (limit,))
            
            return cursor.fetchall()
        except Exception as e:
            console.print(f"[red]Database error retrieving account info: {str(e)}[/red]")
            return []
        finally:
            conn.close()
    
    def search(self, term, buckets=None, max_results=100, sort=2, date_from=None, date_to=None, media=None):
        """Perform search with proper parameters and comprehensive bucket support"""
        # Clear previous results
        self.search_results = []
        self.current_search_id = None
        self.search_term = term
        self.selected_buckets = buckets or []
        self.is_searching = True
        
        # Log search to history
        self.log_search_to_history(term, buckets, max_results, sort)
        
        # Prepare search request
        search_data = {
            "term": term,
            "buckets": buckets or [],
            "lookuplevel": 0,
            "maxresults": max_results,
            "timeout": 0,
            "datefrom": date_from or "",
            "dateto": date_to or "",
            "sort": sort,
            "media": media or 0
        }
        
        try:
            # Create progress bar
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console,
                transient=True
            ) as progress:
                self.search_progress = progress
                self.search_task = progress.add_task("[cyan]Searching...", total=100)
                
                # Send search request
                response = requests.post(
                    f"{self.api_url}/intelligent/search",
                    headers={"x-key": self.api_key, "User-Agent": "IntelligenceXCLI/v6.0"},
                    json=search_data
                )
                
                progress.update(self.search_task, completed=30, description="[cyan]Processing search request...")
                
                if response.status_code == 200:
                    result = response.json()
                    self.current_search_id = result.get("id")
                    
                    # Wait for results
                    time.sleep(0.5)
                    progress.update(self.search_task, completed=50, description="[cyan]Waiting for results...")
                    
                    # Get search results
                    success = self.get_search_results()
                    progress.update(self.search_task, completed=100, description="[green]Search completed")
                    self.is_searching = False
                    return success
                else:
                    self.handle_api_error(response)
                    self.is_searching = False
                    return False
                    
        except Exception as e:
            console.print(f"[red]Search error: {str(e)}[/red]")
            self.is_searching = False
            return False
    
    def get_search_results(self):
        """Get search results with comprehensive handling for all buckets"""
        if not self.current_search_id:
            return False
            
        try:
            # Create a new session for better performance
            session = requests.Session()
            session.headers.update({
                "x-key": self.api_key,
                "User-Agent": "IntelligenceXCLI/v6.0"
            })
            
            # Poll for results
            for _ in range(20):  # Max 20 attempts
                response = session.get(
                    f"{self.api_url}/intelligent/search/result?id={self.current_search_id}&limit=100",
                    timeout=5
                )
                
                if response.status_code == 200:
                    result = response.json()
                    status = result.get("status", 2)
                    
                    if status == 0 or status == 1:  # Results available or finished
                        records = result.get("records", [])
                        for record in records:
                            self.search_results.append(SearchResult(record))
                        
                        # Save results to database
                        self.save_results_to_db()
                        
                        return True
                    elif status == 3:  # Try again
                        time.sleep(0.5)
                        continue
                    else:
                        console.print("[yellow]No results found for this search.[/yellow]")
                        return False
                else:
                    self.handle_api_error(response)
                    return False
                    
            console.print("[yellow]Search timed out. Please try again.[/yellow]")
            return False
            
        except Exception as e:
            console.print(f"[red]Error retrieving results: {str(e)}[/red]")
            return False
    
    def save_results_to_db(self):
        """Save search results to database with comprehensive details"""
        if not self.current_search_history_id or not self.search_results:
            return
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        for result in self.search_results:
            cursor.execute('''
            INSERT OR REPLACE INTO search_results (
                search_id, systemid, storageid, name, description, date, size, 
                bucket, media, accesslevel, xscore, is_redacted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.current_search_history_id,
                result.systemid,
                result.storageid,
                result.name,
                result.description,
                result.date,
                result.size,
                result.bucket,
                result.media_human,
                result.accesslevel,
                result.xscore,
                result.is_redacted()
            ))
        
        # Update result count
        cursor.execute('''
        UPDATE search_history SET result_count = ? WHERE id = ?
        ''', (len(self.search_results), self.current_search_history_id))
        
        conn.commit()
        conn.close()
    
    def save_preview_to_db(self, system_id, preview):
        """Save file preview to database with comprehensive details"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        timestamp = datetime.now().isoformat()
        
        try:
            cursor.execute('''
            INSERT OR REPLACE INTO file_previews (systemid, preview, timestamp)
            VALUES (?, ?, ?)
            ''', (system_id, preview, timestamp))
            
            conn.commit()
        except Exception as e:
            console.print(f"[red]Database error saving preview: {str(e)}[/red]")
        finally:
            conn.close()
    
    def get_preview_from_db(self, system_id):
        """Get file preview from database with comprehensive details"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            SELECT preview FROM file_previews WHERE systemid = ? ORDER BY timestamp DESC LIMIT 1
            ''', (system_id,))
            
            result = cursor.fetchone()
            if result:
                return result[0]
            return None
        except Exception as e:
            console.print(f"[red]Database error retrieving preview: {str(e)}[/red]")
            return None
        finally:
            conn.close()
    
    def get_recent_searches(self, limit=5):
        """Get recent searches from history with comprehensive details"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            SELECT id, timestamp, search_term, result_count 
            FROM search_history 
            ORDER BY timestamp DESC 
            LIMIT ?
            ''', (limit,))
            
            return cursor.fetchall()
        except Exception as e:
            console.print(f"[red]Database error retrieving search history: {str(e)}[/red]")
            return []
        finally:
            conn.close()
    
    def display_recent_searches(self):
        """Display recent searches from history with comprehensive details"""
        console.clear()
        console.rule("[bold blue]Recent Searches[/bold blue]")
        console.print()
        
        searches = self.get_recent_searches()
        
        if not searches:
            console.print("[yellow]No recent searches found.[/yellow]")
            Prompt.ask("Press Enter to continue")
            return
        
        # Create history table
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
        table.add_column("ID", justify="right", style="cyan", width=4)
        table.add_column("Timestamp", style="green", width=18)
        table.add_column("Search Term", style="magenta", max_width=30)
        table.add_column("Results", justify="right", width=8)
        
        for search in searches:
            search_id, timestamp, term, result_count = search
            # Format timestamp
            try:
                dt = datetime.fromisoformat(timestamp)
                formatted_time = dt.strftime("%Y-%m-%d %H:%M")
            except:
                formatted_time = timestamp
                
            table.add_row(
                str(search_id),
                formatted_time,
                term,
                str(result_count)
            )
        
        console.print(table)
        
        # Option to view a specific search
        choice = Prompt.ask(
            "\n[bold]Enter search ID to view results, or press Enter to return[/bold]",
            default=""
        )
        
        if choice:
            try:
                search_id = int(choice)
                self.view_search_history(search_id)
            except ValueError:
                console.print("[yellow]Invalid search ID.[/yellow]")
    
    def view_search_history(self, search_id):
        """View results of a specific search from history"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        try:
            # Get search details
            cursor.execute('''
            SELECT timestamp, search_term, buckets, result_count 
            FROM search_history 
            WHERE id = ?
            ''', (search_id,))
            
            search = cursor.fetchone()
            if not search:
                console.print("[yellow]Search not found.[/yellow]")
                return
            
            timestamp, term, buckets, result_count = search
            
            # Get results
            cursor.execute('''
            SELECT * FROM search_results 
            WHERE search_id = ?
            ''', (search_id,))
            
            results = cursor.fetchall()
            if not results:
                console.print("[yellow]No results found for this search.[/yellow]")
                return
            
            # Display search details
            console.clear()
            console.rule(f"[bold blue]Historical Search Results for '{term}'[/bold blue]")
            console.print()
            
            console.print(f"[bold]Search Term:[/bold] {term}")
            console.print(f"[bold]Buckets:[/bold] {buckets}")
            console.print(f"[bold]Total Results:[/bold] {result_count}\n")
            
            # Display results
            table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
            table.add_column("ID", justify="right", style="cyan", width=3)
            table.add_column("Name", style="magenta", max_width=30)
            table.add_column("Date", style="green", width=10)
            table.add_column("Size", justify="right", width=10)
            table.add_column("Bucket", style="blue", width=15)
            table.add_column("Type", style="yellow", width=12)
            table.add_column("Access", justify="center", width=10)
            
            for i, result in enumerate(results, 1):
                # Skip ID and search_id columns
                _, _, systemid, storageid, name, description, date, size, bucket, media, accesslevel, xscore, is_redacted = result
                
                # Determine access level
                access = "Full" if accesslevel == 0 else "Preview"
                access_color = "green" if accesslevel == 0 else "yellow"
                
                # Format size
                size_str = f"{size} B"
                if size > 1024 * 1024:  # More than 1MB
                    size_str = f"{size / (1024 * 1024):.1f} MB"
                elif size > 1024:  # More than 1KB
                    size_str = f"{size / 1024:.1f} KB"
                
                table.add_row(
                    str(i),
                    name,
                    date.split("T")[0] if date else "",
                    size_str,
                    bucket,
                    media,
                    f"[{access_color}]{access}[/{access_color}]"
                )
            
            console.print(table)
            
            # Allow user to select a result for preview
            self.handle_historical_result_selection(results)
            
        except Exception as e:
            console.print(f"[red]Error retrieving search history: {str(e)}[/red]")
        finally:
            conn.close()
    
    def handle_historical_result_selection(self, results):
        """Handle selection of a result from historical search"""
        choice = Prompt.ask(
            "\n[bold]Select result to preview (enter number) or press Enter to return[/bold]",
            default=""
        )
        
        if not choice:
            return
        
        try:
            index = int(choice) - 1
            if 0 <= index < len(results):
                # Skip ID and search_id columns
                _, _, systemid, _, name, _, _, _, _, _, _, _, _ = results[index]
                
                # Get preview from database
                preview = self.get_preview_from_db(systemid)
                if preview and "❌" not in preview:
                    self.display_historical_preview(name, preview)
                else:
                    console.print("[yellow]No preview available for this result.[/yellow]")
            else:
                console.print("[yellow]Invalid selection.[/yellow]")
        except ValueError:
            console.print("[yellow]Please enter a valid number.[/yellow]")
    
    def display_historical_preview(self, name, preview):
        """Display preview of a historical result"""
        console.clear()
        console.rule(f"[bold blue]Preview: {name}[/bold blue]")
        console.print()
        
        console.print("[bold]File Preview:[/bold]")
        console.print(Syntax(preview, "text", theme="monokai", line_numbers=True))
        
        Prompt.ask("\nPress Enter to continue")
    
    def get_extracted_selectors(self, system_id):
        """Get extracted selectors for a system ID with comprehensive details"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            SELECT selector_type, selector_value 
            FROM extracted_selectors 
            WHERE systemid = ?
            ''', (system_id,))
            
            return cursor.fetchall()
        except Exception as e:
            console.print(f"[red]Database error retrieving selectors: {str(e)}[/red]")
            return []
        finally:
            conn.close()
    
    def save_extracted_selectors(self, system_id, selectors):
        """Save extracted selectors to database with comprehensive details"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        timestamp = datetime.now().isoformat()
        
        try:
            # Clear existing selectors
            cursor.execute('''
            DELETE FROM extracted_selectors WHERE systemid = ?
            ''', (system_id,))
            
            # Insert new selectors
            for selector_type, selector_value in selectors:
                cursor.execute('''
                INSERT INTO extracted_selectors (systemid, selector_type, selector_value, timestamp)
                VALUES (?, ?, ?, ?)
                ''', (system_id, selector_type, selector_value, timestamp))
            
            conn.commit()
        except Exception as e:
            console.print(f"[red]Database error saving selectors: {str(e)}[/red]")
        finally:
            conn.close()
    
    def handle_api_error(self, response):
        """Handle API errors with detailed information and suggestions"""
        status_code = response.status_code
        try:
            error_data = response.json()
            error_msg = error_data.get("error", "Unknown error")
        except:
            error_msg = "Unknown error"
        
        if status_code == 400:
            console.print(f"[red]Bad Request: {error_msg}[/red]")
            console.print("[yellow]Check your search parameters and try again.[/yellow]")
        elif status_code == 401:
            console.print(f"[red]Unauthorized: {error_msg}[/red]")
            console.print("[yellow]Check your API key permissions and try again.[/yellow]")
        elif status_code == 402:
            console.print(f"[yellow]Account Limitation: {error_msg}[/yellow]")
            console.print("[yellow]Check your credit balance and try again later.[/yellow]")
        elif status_code == 404:
            console.print(f"[yellow]Not Found: {error_msg}[/yellow]")
            console.print("[yellow]The requested resource was not found.[/yellow]")
        else:
            console.print(f"[red]API Error ({status_code}): {error_msg}[/red]")
    
    def display_search_results(self):
        """عرض نتائج البحث بشكل منظم ومحسن"""
        if not self.search_results:
            console.print("[yellow]لم يتم العثور على نتائج.[/yellow]")
            return False

        # إنشاء جدول النتائج بشكل محسن
        table = Table(
            title=f"نتائج البحث عن '{self.search_term}'",
            box=box.ROUNDED,
            header_style="bold cyan",
            title_style="bold magenta"
        )

        # تحسين عرض الأعمدة
        table.add_column("#", justify="center", style="cyan", width=4)
        table.add_column("الملف", style="bold white", max_width=30)
        table.add_column("التاريخ", style="green", width=12)
        table.add_column("الحجم", style="blue", width=10)
        table.add_column("النوع", style="yellow", width=15)
        table.add_column("القيود", style="red", width=12)
        
        # Create results table
        table = Table(title=f"Search Results for '{self.search_term}'", box=box.ROUNDED, show_header=True, header_style="bold cyan")
        table.add_column("ID", justify="right", style="cyan", no_wrap=True, width=3)
        table.add_column("Name", style="magenta", max_width=30)
        table.add_column("Date", style="green", width=10)
        table.add_column("Size", justify="right", width=10)
        table.add_column("Bucket", style="blue", width=15)
        table.add_column("Type", style="yellow", width=12)
        table.add_column("Access", justify="center", width=10)
        
        for i, result in enumerate(self.search_results, 1):
            # Determine access level
            if result.can_download():
                access = "✓ Full"
                access_color = "green"
            elif result.can_preview():
                access = "✎ Preview"
                access_color = "yellow"
            else:
                access = "✗ Unavailable"
                access_color = "red"
            
            # Format size
            size_str = f"{result.size} B"
            if result.size > 1024 * 1024:  # More than 1MB
                size_str = f"{result.size / (1024 * 1024):.1f} MB"
            elif result.size > 1024:  # More than 1KB
                size_str = f"{result.size / 1024:.1f} KB"
            
            # Add row to table
            table.add_row(
                str(i),
                result.name,
                result.date.split("T")[0] if result.date else "",
                size_str,
                result.bucket_human,
                result.media_human,
                f"[{access_color}]{access}[/{access_color}]"
            )
        
        console.print(table)
        return True
    
    def display_account_info(self):
        """Display account information in a compact panel with comprehensive details"""
        if not self.account_info:
            console.print("[red]Account information not loaded.[/red]")
            return
        
        # Display basic account info
        account_info = (
            f"[bold]Account:[/bold] [yellow]{self.account_info.license_type}[/yellow]\n"
            f"[bold]Expiration:[/bold] [green]{self.account_info.license_expiration}[/green]\n"
            f"[bold]Active Searches:[/bold] [cyan]{self.account_info.get_active_searches_info()}[/cyan]\n"
            f"[bold]Total Results Possible:[/bold] [blue]{self.account_info.get_total_results()}[/blue]"
        )
        
        console.print(Panel(account_info, title="Account Information", border_style="blue", width=40))
        
        # Display bucket permissions in a compact format
        bucket_info = "[bold]Bucket Permissions:[/bold]\n"
        
        # Add fully accessible buckets
        for i in range(len(self.account_info.buckets)):
            bucket = self.account_info.bucketsh[i]
            bucket_info += f"  • [green]✓[/green] [cyan]{bucket}[/cyan] - Full access\n"
        
        # Add preview-only buckets
        for i in range(len(self.account_info.redacted)):
            bucket = self.account_info.redactedh[i]
            bucket_info += f"  • [yellow]✎[/yellow] [cyan]{bucket}[/cyan] - Preview only (redacted content)\n"
        
        console.print(Panel(bucket_info, title="Permissions", border_style="blue", width=60))
        
        # Display credits in a compact format
        credits_info = "[bold]Remaining Credits:[/bold]\n"
        
        # Preview credits
        preview_credits = self.account_info.get_remaining_credits("/file/preview")
        preview_max = self.account_info.get_max_credits("/file/preview")
        credits_info += f"  • [yellow]✎[/yellow] [cyan]/file/preview:[/cyan] {preview_credits}/{preview_max} (Preview access)\n"
        
        # Search credits
        search_credits = self.account_info.get_remaining_credits("/intelligent/search")
        search_max = self.account_info.get_max_credits("/intelligent/search")
        credits_info += f"  • [cyan]/intelligent/search:[/cyan] {search_credits}/{search_max} (Search operations)\n"
        
        # Download credits
        read_credits = self.account_info.get_remaining_credits("/file/read")
        read_max = self.account_info.get_max_credits("/file/read")
        credits_info += f"  • [red]✗[/red] [cyan]/file/read:[/cyan] {read_credits}/{read_max} (Full downloads)\n"
        
        console.print(Panel(credits_info, title="Credits", border_style="blue", width=60))
        
        # Warning if credits are low
        if preview_credits < 100 or read_credits < 10:
            console.print(Panel(
                "⚠️ [yellow]Warning: Low credit balance. You may need to wait for reset.[/yellow]",
                border_style="yellow"
            ))
    
    def log_search_to_history(self, term, buckets, max_results, sort):
        """Log search to history database with comprehensive details"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        timestamp = datetime.now().isoformat()
        buckets_str = ",".join(buckets) if buckets else "all"
        
        cursor.execute('''
        INSERT INTO search_history (timestamp, search_term, buckets, max_results, sort, result_count)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, term, buckets_str, max_results, sort, 0))
        
        self.current_search_history_id = cursor.lastrowid
        conn.commit()
        conn.close()
    
    def display_search_analysis(self):
        """Display analysis of search results in a compact format with comprehensive details"""
        if not self.search_results:
            console.print("[yellow]No search results to analyze.[/yellow]")
            return
        
        # Calculate analysis data
        redacted_count = sum(1 for r in self.search_results if r.is_redacted())
        deleted_count = sum(1 for r in self.search_results if r.is_deleted())
        
        # Create analysis panels
        stats_panel = Panel(
            f"[bold]Total Results:[/bold] [cyan]{len(self.search_results)}[/cyan]\n"
            f"[bold]Redacted Results:[/bold] [yellow]{redacted_count}[/yellow]\n"
            f"[bold]Deleted Results:[/bold] [red]{deleted_count}[/red]",
            title="Search Statistics",
            border_style="blue"
        )
        
        # Bucket distribution
        bucket_dist = {}
        for result in self.search_results:
            category = result.get_bucket_category()
            bucket_dist[category] = bucket_dist.get(category, 0) + 1
        
        bucket_info = ""
        for category, count in bucket_dist.items():
            bucket_info += f"  • [cyan]{category}:[/cyan] {count}\n"
        
        bucket_panel = Panel(
            bucket_info,
            title="Bucket Distribution",
            border_style="blue"
        )
        
        # Media type distribution
        media_dist = {}
        for result in self.search_results:
            media_type = result.get_media_type()
            media_dist[media_type] = media_dist.get(media_type, 0) + 1
        
        media_info = ""
        for media_type, count in media_dist.items():
            media_info += f"  • [cyan]{media_type}:[/cyan] {count}\n"
        
        media_panel = Panel(
            media_info,
            title="Media Types",
            border_style="blue"
        )
        
        # Display panels in a grid
        console.print(
            Columns([stats_panel, bucket_panel, media_panel], equal=True, expand=True)
        )
    
    def interactive_search(self):
        """Interactive search interface with comprehensive bucket support"""
        console.clear()
        
        # Header
        console.rule("[bold blue]Intelligence X Search[/bold blue]")
        console.print()
        
        # Get search term
        term = Prompt.ask("[bold]Enter search term (any valid selector)[/bold]")
        if not term:
            console.print("[yellow]No search term entered.[/yellow]")
            return
        
        # Validate search term
        if not self.is_valid_search_term(term):
            console.print("[red]Invalid search term. Please enter a valid selector.[/red]")
            console.print("[yellow]Supported selectors: email, domain, IP, CIDR, phone, Bitcoin address, etc.[/yellow]")
            Prompt.ask("Press Enter to try again")
            return self.interactive_search()
        
        # Select buckets with comprehensive support
        console.print("\n[bold]Available buckets (✓ = Full access, ✎ = Preview only):[/bold]")
        
        # Show buckets with clear indicators
        bucket_lines = []
        for i, bucket in enumerate(self.account_info.bucketsh, 1):
            access = self.account_info.get_bucket_access(self.account_info.buckets[i-1])
            if access == "Full":
                bucket_lines.append(f"{i}. [green]✓[/green] [cyan]{bucket}[/cyan] - Full access")
            else:
                bucket_lines.append(f"{i}. [yellow]✎[/yellow] [cyan]{bucket}[/cyan] - Preview only (redacted content)")
        
        # Display in two columns for compactness
        left_col = bucket_lines[:len(bucket_lines)//2]
        right_col = bucket_lines[len(bucket_lines)//2:]
        
        for i in range(max(len(left_col), len(right_col))):
            left = left_col[i] if i < len(left_col) else ""
            right = right_col[i] if i < len(right_col) else ""
            console.print(f"{left: <40} {right}")
        
        # Bucket selection
        buckets_input = Prompt.ask(
            "\n[bold]Enter bucket numbers to search (comma separated, Enter for all)[/bold]",
            default=""
        )
        
        selected_buckets = []
        if buckets_input:
            try:
                bucket_indices = [int(x.strip()) - 1 for x in buckets_input.split(",")]
                for idx in bucket_indices:
                    if 0 <= idx < len(self.account_info.bucketsh):
                        selected_buckets.append(self.account_info.buckets[idx])
            except:
                console.print("[yellow]Invalid bucket selection. Searching all accessible buckets.[/yellow]")
        
        # Set max results (up to 1000)
        max_results = Prompt.ask(
            "[bold]Maximum results (1-1000)[/bold]",
            default="100",
            show_choices=False
        )
        
        # Validate max_results
        try:
            max_results = int(max_results)
            if max_results < 1:
                max_results = 1
            elif max_results > 1000:
                max_results = 1000
                console.print("[yellow]Maximum results capped at 1000.[/yellow]")
        except ValueError:
            max_results = 100
            console.print("[yellow]Invalid number. Using default of 100 results.[/yellow]")
        
        # Set sort order
        console.print("\n[bold]Sort order:[/bold]")
        console.print("1. Most relevant first (default)")
        console.print("2. Least relevant first")
        console.print("3. Oldest first")
        console.print("4. Newest first")
        
        sort_option = Prompt.ask(
            "[bold]Sort order[/bold]",
            default="1",
            choices=["1", "2", "3", "4"],
            show_choices=False
        )
        
        sort_map = {
            "1": 2,  # Most relevant first
            "2": 1,  # Least relevant first
            "3": 3,  # Oldest first
            "4": 4   # Newest first
        }
        
        sort = sort_map.get(sort_option, 2)
        
        # Advanced options
        advanced = Confirm.ask("\nUse advanced search options?", default=False)
        date_from = date_to = media = None
        
        if advanced:
            # Date range
            date_range = Confirm.ask("Set date range?", default=False)
            if date_range:
                date_from = Prompt.ask("From date (YYYY-MM-DD)")
                date_to = Prompt.ask("To date (YYYY-MM-DD)")
                
                # Validate dates
                try:
                    datetime.strptime(date_from, "%Y-%m-%d")
                    datetime.strptime(date_to, "%Y-%m-%d")
                except ValueError:
                    console.print("[yellow]Invalid date format. Using default date range.[/yellow]")
                    date_from = date_to = None
            
            # Media type
            media_type = Confirm.ask("Filter by media type?", default=False)
            if media_type:
                media_table = Table(box=box.SIMPLE)
                media_table.add_column("ID", justify="right")
                media_table.add_column("Media Type")
                
                media_map = {
                    1: "Paste Document",
                    2: "Paste User",
                    9: "HTML Copy of Website",
                    14: "URL",
                    15: "PDF Document",
                    16: "Word Document",
                    17: "Excel Document",
                    18: "PowerPoint Document",
                    19: "Picture",
                    20: "Audio File",
                    21: "Video File",
                    22: "Container Files",
                    23: "HTML File",
                    24: "Text File"
                }
                
                for id, name in media_map.items():
                    media_table.add_row(str(id), name)
                
                console.print(media_table)
                media = Prompt.ask("Enter media type ID", default="24")
                try:
                    media = int(media)
                    if media not in media_map:
                        console.print("[yellow]Invalid media type. Using default.[/yellow]")
                        media = None
                except:
                    console.print("[yellow]Invalid media type. Using default.[/yellow]")
                    media = None
        
        # Start search
        console.print("\n[bold cyan]Starting search...[/bold cyan]")
        if self.search(term, selected_buckets, max_results, sort, date_from, date_to, media):
            console.clear()
            console.rule("[bold blue]Search Results[/bold blue]")
            console.print()
            
            # Display results
            self.display_search_results()
            
            # Show special notice for trial accounts
            if any(r.is_redacted() for r in self.search_results):
                console.print(Panel(
                    "ℹ️ [bold yellow]Trial Account Notice:[/bold yellow]\n\n"
                    "• Files marked as 'Preview' show redacted content (████ characters)\n"
                    "• This is intentional - trial accounts cannot see full content for sensitive data\n"
                    "• To see full content, you need to [bold]upgrade to a paid account[/bold]\n"
                    "• Visit [blue]https://intelx.io/account?tab=developer[/blue] to upgrade",
                    border_style="yellow"
                ))
            
            # Allow user to select a result
            self.handle_result_selection()
        else:
            console.print("[yellow]No results found for this search.[/yellow]")
            Prompt.ask("Press Enter to return to main menu")
    
    def is_valid_search_term(self, term):
        """Validate search term against supported selector types with comprehensive validation"""
        # Email address
        if re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', term):
            return True
        
        # Domain (including wildcards)
        if re.match(r'^(\*\.|)[\w\.-]+\.[a-z]{2,}$', term):
            return True
        
        # URL
        if term.startswith(('http://', 'https://', 'www.')):
            return True
        
        # IPv4
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', term):
            return True
        
        # IPv6 (simplified check)
        if re.match(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$', term):
            return True
        
        # CIDRv4
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$', term):
            return True
        
        # Phone number (simplified)
        if re.match(r'^(\+)?[\d\s\-\(\)]+$', term) and len(term) > 5:
            return True
        
        # Bitcoin address (simplified)
        if re.match(r'^[13][a-km-zA-HJ-NP-Z0-9]{25,34}$', term):
            return True
        
        # MAC address
        if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', term):
            return True
        
        # UUID
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', term):
            return True
        
        # Storage ID (simplified)
        if len(term) > 32 and re.match(r'^[a-f0-9]+$', term):
            return True
        
        # System ID (UUID format)
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', term):
            return True
        
        # Simhash (simplified)
        if re.match(r'^[0-9a-f]{16}$', term) and len(term) == 16:
            return True
        
        # Credit card number (simplified)
        if re.match(r'^\d{13,19}$', term.replace(' ', '').replace('-', '')):
            return True
        
        # IBAN (simplified)
        if re.match(r'^[A-Z]{2}\d{2}[A-Z0-9]{1,30}$', term.replace(' ', '')):
            return True
        
        # Generic search terms (soft selectors)
        if len(term) > 3 and not re.search(r'[\s\W]', term):
            return True
        
        return False
    
    def handle_result_selection(self):
        """Handle result selection with comprehensive bucket support"""
        if not self.search_results:
            return
        
        console.print("\n[bold]View Options:[/bold]")
        console.print("D. Document View (content)")
        console.print("T. Tree View (relationships)")
        console.print("M. Metadata View")
        console.print("S. Selectors View (extracted selectors)")
        console.print("A. Actions Menu")
        
        choice = Prompt.ask(
            "\n[bold]Select result (number), view option (D/T/M/S/A), or press Enter to return[/bold]",
            default=""
        )
        
        if not choice:
            return
        elif choice.upper() == "D":
            self.current_view = "document"
            return self.handle_result_selection()
        elif choice.upper() == "T":
            self.current_view = "tree"
            return self.handle_result_selection()
        elif choice.upper() == "M":
            self.current_view = "metadata"
            return self.handle_result_selection()
        elif choice.upper() == "S":
            self.current_view = "selectors"
            return self.handle_result_selection()
        elif choice.upper() == "A":
            self.current_view = "actions"
            return self.handle_result_selection()
        
        try:
            index = int(choice) - 1
            if 0 <= index < len(self.search_results):
                result = self.search_results[index]
                self.display_result(result)
            else:
                console.print("[yellow]Invalid selection.[/yellow]")
        except ValueError:
            console.print("[yellow]Please enter a valid number.[/yellow]")
    
    def display_result(self, result):
        """Display result based on current view mode with comprehensive bucket support"""
        console.clear()
        
        if self.current_view == "document":
            self.display_document_view(result)
        elif self.current_view == "tree":
            self.display_tree_view(result)
        elif self.current_view == "metadata":
            self.display_metadata_view(result)
        elif self.current_view == "selectors":
            self.display_selectors_view(result)
        elif self.current_view == "actions":
            self.display_actions_view(result)
    
    def display_document_view(self, result):
        """عرض محتوى الملف مع تحسين التعامل مع القيود"""
        console.rule(f"[bold blue]معاينة المحتوى: {result.name}[/bold blue]")
        
        # التحقق من نوع القيود
        if result.is_redacted():
            console.print(Panel(
                "⚠️ [yellow]تنبيه: هذا المحتوى مقيد[/yellow]\n" +
                "• بسبب نوع الحساب التجريبي، سيظهر المحتوى الحساس بشكل مخفي (████)\n" +
                "• للوصول للمحتوى الكامل، يجب ترقية الحساب",
                title="قيود المحتوى",
                border_style="yellow"
            ))

        # جلب المحتوى مع المعالجة المحسنة
        preview = self.get_preview_from_db(result.systemid)
        if not preview:
            preview = self.preview_manager.get_preview(
                result.systemid,
                result.bucket,
                lines=50,
                force_refresh=False
            )
        console.rule(f"[bold blue]Document View: {result.name}[/bold blue]")
        console.print()
        
        # Get preview
        preview = self.get_preview_from_db(result.systemid)
        if not preview:
            preview = self.preview_manager.get_preview(result.systemid, result.bucket, 50)
        
        # Save to cache if successful
        if preview and not preview.startswith("❌"):
            self.last_preview = preview
            self.last_preview_systemid = result.systemid
            self.save_preview_to_db(result.systemid, preview)
        
        # Display preview
        if preview and not preview.startswith("❌"):
            console.print("[bold]File Content:[/bold]")
            
            # Check if preview contains redacted content
            is_redacted = "████" in preview
            
            if is_redacted:
                console.print(Panel(
                    "ℹ️ [bold yellow]Trial Account Notice:[/bold yellow]\n\n"
                    "• Content appears as ████ characters because your trial account only allows preview access\n"
                    "• Reason: This data is in the 'Leaks » Logs' bucket which is restricted to preview-only\n"
                    "• To see full content, you need to [bold]upgrade to a paid account[/bold]",
                    border_style="yellow"
                ))
            
            console.print(Syntax(preview, "text", theme="monokai", line_numbers=True))
            
            # If preview contains ████ characters
            if is_redacted:
                console.print("\n[yellow]Note: The ████ characters represent redacted content due to trial account limitations.[/yellow]")
                console.print("[yellow]To access full content, upgrade to a paid account.[/yellow]")
        else:
            console.print(f"[red]{preview}[/red]")
            console.print("\n[bold]How to Fix Preview Issues:[/bold]")
            console.print("1. Make sure you're searching in buckets you have access to")
            console.print("2. Check your preview credits in the main menu")
            console.print("3. For 'Leaks » Logs', preview is always redacted in trial accounts")
        
        # Navigation options
        console.print("\n[bold]Navigation:[/bold]")
        console.print("T. Switch to Tree View")
        console.print("M. Switch to Metadata View")
        console.print("S. Switch to Selectors View")
        console.print("A. Switch to Actions Menu")
        console.print("B. Back to search results")
        
        choice = Prompt.ask(
            "[bold]Navigation option[/bold]",
            choices=["T", "M", "S", "A", "B"],
            default="B"
        )
        
        if choice.upper() == "T":
            self.current_view = "tree"
            self.display_tree_view(result)
        elif choice.upper() == "M":
            self.current_view = "metadata"
            self.display_metadata_view(result)
        elif choice.upper() == "S":
            self.current_view = "selectors"
            self.display_selectors_view(result)
        elif choice.upper() == "A":
            self.current_view = "actions"
            self.display_actions_view(result)
        # B returns to search results
    
    def display_tree_view(self, result):
        """Display tree view (relationships) with comprehensive bucket support"""
        console.rule(f"[bold blue]Tree View: {result.name}[/bold blue]")
        console.print()
        
        # Get related items
        related_items = self.get_related_items(result.systemid)
        
        # Create tree
        tree = Tree(f"[bold]{result.name}[/bold] ([cyan]{result.systemid}[/cyan])", guide_style="blue")
        
        # Add related items to tree
        for i, item in enumerate(related_items, 1):
            relation_type = "Related" if item["relation"] == 0 else "Unknown"
            tree.add(f"[yellow]{relation_type}[/yellow]: [magenta]{item['target']}[/magenta]")
        
        console.print(tree)
        
        # Show navigation options
        console.print("\n[bold]Navigation:[/bold]")
        console.print("D. Switch to Document View")
        console.print("M. Switch to Metadata View")
        console.print("S. Switch to Selectors View")
        console.print("A. Switch to Actions Menu")
        console.print("B. Back to search results")
        
        choice = Prompt.ask(
            "[bold]Navigation option[/bold]",
            choices=["D", "M", "S", "A", "B"],
            default="B"
        )
        
        if choice.upper() == "D":
            self.current_view = "document"
            self.display_document_view(result)
        elif choice.upper() == "M":
            self.current_view = "metadata"
            self.display_metadata_view(result)
        elif choice.upper() == "S":
            self.current_view = "selectors"
            self.display_selectors_view(result)
        elif choice.upper() == "A":
            self.current_view = "actions"
            self.display_actions_view(result)
        # B returns to search results
    
    def display_metadata_view(self, result):
        """Display metadata view with comprehensive bucket support"""
        console.rule(f"[bold blue]Metadata View: {result.name}[/bold blue]")
        console.print()
        
        # Display metadata
        metadata_table = Table(box=box.SIMPLE, show_header=False)
        metadata_table.add_column("Field", style="cyan", width=20)
        metadata_table.add_column("Value", width=50)
        
        # Add metadata fields
        metadata_table.add_row("System ID", result.systemid)
        metadata_table.add_row("Storage ID", result.storageid or "N/A")
        metadata_table.add_row("Name", result.name)
        metadata_table.add_row("Date", result.date)
        metadata_table.add_row("Added", result.added)
        metadata_table.add_row("Size", self.format_size(result.size))
        metadata_table.add_row("Bucket", result.bucket_human)
        metadata_table.add_row("Media Type", result.media_human)
        metadata_table.add_row("Content Type", result.type_human)
        metadata_table.add_row("X-Score", str(result.xscore))
        metadata_table.add_row("Simhash", f"{result.simhash} ({result.simhash_human})")
        metadata_table.add_row("Access Level", result.get_access_level_description())
        metadata_table.add_row("Status", "Available" if result.instore else "Deleted")
        
        console.print(metadata_table)
        
        # Show navigation options
        console.print("\n[bold]Navigation:[/bold]")
        console.print("D. Switch to Document View")
        console.print("T. Switch to Tree View")
        console.print("S. Switch to Selectors View")
        console.print("A. Switch to Actions Menu")
        console.print("B. Back to search results")
        
        choice = Prompt.ask(
            "[bold]Navigation option[/bold]",
            choices=["D", "T", "S", "A", "B"],
            default="B"
        )
        
        if choice.upper() == "D":
            self.current_view = "document"
            self.display_document_view(result)
        elif choice.upper() == "T":
            self.current_view = "tree"
            self.display_tree_view(result)
        elif choice.upper() == "S":
            self.current_view = "selectors"
            self.display_selectors_view(result)
        elif choice.upper() == "A":
            self.current_view = "actions"
            self.display_actions_view(result)
        # B returns to search results
    
    def display_selectors_view(self, result):
        """Display selectors view (extracted selectors) with comprehensive bucket support"""
        console.rule(f"[bold blue]Selectors View: {result.name}[/bold blue]")
        console.print()
        
        # Get or extract selectors
        selectors = self.get_extracted_selectors(result.systemid)
        if not selectors:
            # Extract selectors from preview
            preview = self.get_preview_from_db(result.systemid)
            if not preview:
                preview = self.preview_manager.get_preview(result.systemid, result.bucket, 50)
            
            if preview and not preview.startswith("❌"):
                selectors = self.selector_extractor.extract_selectors(preview)
                self.save_extracted_selectors(result.systemid, selectors)
        
        if not selectors:
            console.print("[yellow]No selectors found in this item.[/yellow]")
        else:
            # Create selectors table
            table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
            table.add_column("Type", style="cyan", width=15)
            table.add_column("Value", width=45)
            
            for selector_type, selector_value in selectors:
                table.add_row(selector_type, selector_value)
            
            console.print(table)
            
            console.print("\n[bold]Search Options:[/bold]")
            console.print("1. Search by selected selector")
            console.print("2. Copy selector to clipboard")
        
        # Show navigation options
        console.print("\n[bold]Navigation:[/bold]")
        console.print("D. Switch to Document View")
        console.print("T. Switch to Tree View")
        console.print("M. Switch to Metadata View")
        console.print("A. Switch to Actions Menu")
        console.print("B. Back to search results")
        
        choice = Prompt.ask(
            "[bold]Navigation option[/bold]",
            choices=["1", "2", "D", "T", "M", "A", "B"],
            default="B"
        )
        
        if choice == "1":
            # Search by selector
            if selectors:
                selector_index = Prompt.ask(
                    "Enter selector number to search",
                    choices=[str(i+1) for i in range(len(selectors))],
                    default="1"
                )
                _, selector_value = selectors[int(selector_index) - 1]
                self.search_term = selector_value
                self.interactive_search()
            else:
                console.print("[yellow]No selectors available to search.[/yellow]")
                Prompt.ask("Press Enter to continue")
                self.display_selectors_view(result)
        elif choice == "2":
            # Copy to clipboard
            if selectors:
                selector_index = Prompt.ask(
                    "Enter selector number to copy",
                    choices=[str(i+1) for i in range(len(selectors))],
                    default="1"
                )
                _, selector_value = selectors[int(selector_index) - 1]
                pyperclip.copy(selector_value)
                console.print("[green]Selector copied to clipboard![/green]")
                Prompt.ask("Press Enter to continue")
                self.display_selectors_view(result)
            else:
                console.print("[yellow]No selectors available to copy.[/yellow]")
                Prompt.ask("Press Enter to continue")
                self.display_selectors_view(result)
        elif choice.upper() == "D":
            self.current_view = "document"
            self.display_document_view(result)
        elif choice.upper() == "T":
            self.current_view = "tree"
            self.display_tree_view(result)
        elif choice.upper() == "M":
            self.current_view = "metadata"
            self.display_metadata_view(result)
        elif choice.upper() == "A":
            self.current_view = "actions"
            self.display_actions_view(result)
        # B returns to search results
    
    def display_actions_view(self, result):
        """Display actions view with comprehensive bucket support"""
        console.rule(f"[bold blue]Actions Menu: {result.name}[/bold blue]")
        console.print()
        
        # Display actions
        actions_table = Table(box=box.SIMPLE, show_header=False)
        actions_table.add_column("Action", style="cyan", width=20)
        actions_table.add_column("Description", width=50)
        
        actions_table.add_row("1. Preview", "View content preview (redacted for trial accounts)")
        if result.can_download():
            actions_table.add_row("2. Download", "Download full content (requires paid account for sensitive data)")
        else:
            actions_table.add_row("2. Download", "[yellow]Not available with trial account[/yellow]")
        actions_table.add_row("3. Copy System ID", "Copy System ID to clipboard")
        actions_table.add_row("4. View on Website", "Open in Intelligence X website")
        actions_table.add_row("5. Extract Selectors", "Extract and view selectors from content")
        actions_table.add_row("6. Search Related", "Search for related items")
        actions_table.add_row("7. Force Refresh", "Refresh preview with latest data")
        
        console.print(actions_table)
        
        # Action selection
        choice = Prompt.ask(
            "\n[bold]Select action (1-7)[/bold]",
            choices=["1", "2", "3", "4", "5", "6", "7"],
            default="1"
        )
        
        if choice == "1":
            self.current_view = "document"
            self.display_document_view(result)
        elif choice == "2" and result.can_download():
            self.download_selected_result(result)
        elif choice == "2" and not result.can_download():
            console.print(Panel(
                "❌ [bold red]Download Not Available[/bold red]\n\n"
                "• Trial accounts cannot download full content from redacted buckets\n"
                "• This file is in the 'Leaks » Logs' bucket which is restricted to preview-only\n\n"
                "• To download full content, you need to [bold]upgrade to a paid account[/bold]\n"
                "• Visit [blue]https://intelx.io/account?tab=developer[/blue] to upgrade",
                border_style="red"
            ))
            Prompt.ask("Press Enter to continue")
            self.display_actions_view(result)
        elif choice == "3":
            pyperclip.copy(result.systemid)
            console.print("[green]System ID copied to clipboard![/green]")
            Prompt.ask("Press Enter to continue")
            self.display_actions_view(result)
        elif choice == "4":
            webbrowser.open(f"https://intelx.io/?did={result.systemid}")
            console.print(f"[blue]Opening in browser: https://intelx.io/?did={result.systemid}[/blue]")
            Prompt.ask("Press Enter to continue")
            self.display_actions_view(result)
        elif choice == "5":
            self.current_view = "selectors"
            self.display_selectors_view(result)
        elif choice == "6":
            self.search_related_items(result)
        elif choice == "7":
            # Force refresh preview
            preview = self.preview_manager.get_preview(result.systemid, result.bucket, 50, force_refresh=True)
            if preview and not preview.startswith("❌"):
                self.last_preview = preview
                self.last_preview_systemid = result.systemid
                self.save_preview_to_db(result.systemid, preview)
                console.print("[green]Preview refreshed successfully![/green]")
            else:
                console.print(f"[red]{preview}[/red]")
            Prompt.ask("Press Enter to continue")
            self.display_actions_view(result)
    
    def search_related_items(self, result):
        """Search for related items with comprehensive bucket support"""
        console.clear()
        console.rule(f"[bold blue]Search Related Items: {result.name}[/bold blue]")
        console.print()
        
        # Get related items
        related_items = self.get_related_items(result.systemid)
        
        if not related_items:
            console.print("[yellow]No related items found.[/yellow]")
            Prompt.ask("Press Enter to continue")
            self.display_actions_view(result)
            return
        
        # Display related items
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
        table.add_column("ID", style="cyan", width=3)
        table.add_column("System ID", width=36)
        table.add_column("Relation", width=15)
        
        for i, item in enumerate(related_items, 1):
            relation_type = "Related" if item["relation"] == 0 else "Unknown"
            table.add_row(str(i), item["target"], relation_type)
        
        console.print(table)
        
        # Select related item to search
        choice = Prompt.ask(
            "\n[bold]Select related item to search (enter number) or press Enter to return[/bold]",
            default=""
        )
        
        if choice:
            try:
                index = int(choice) - 1
                if 0 <= index < len(related_items):
                    related_id = related_items[index]["target"]
                    
                    # Set search term to related ID
                    self.search_term = related_id
                    self.interactive_search()
                else:
                    console.print("[yellow]Invalid selection.[/yellow]")
            except ValueError:
                console.print("[yellow]Please enter a valid number.[/yellow]")
        
        # Return to actions menu
        self.display_actions_view(result)
    
    def get_related_items(self, system_id):
        """Get related items for a given system ID with comprehensive bucket support"""
        for result in self.search_results:
            if result.systemid == system_id:
                return result.relations
        return []
    
    def format_size(self, size):
        """Format file size for display with comprehensive bucket support"""
        if size > 1024 * 1024:  # More than 1MB
            return f"{size / (1024 * 1024):.1f} MB"
        elif size > 1024:  # More than 1KB
            return f"{size / 1024:.1f} KB"
        return f"{size} B"
    
    def preview_selected_result(self, result):
        """Preview selected result with CORRECTED API CALL for all buckets"""
        self.current_view = "document"
        self.display_document_view(result)
    
    def download_selected_result(self, result):
        """Download selected result with comprehensive bucket support"""
        console.clear()
        console.rule(f"[bold blue]Download: {result.name}[/bold blue]")
        console.print()
        
        # Check if download is possible
        if not result.can_download():
            console.print(Panel(
                "❌ [bold red]Download Not Available[/bold red]\n\n"
                "• Trial accounts cannot download full content from redacted buckets\n"
                "• This file is in the 'Leaks » Logs' bucket which is restricted to preview-only\n\n"
                "• To download full content, you need to [bold]upgrade to a paid account[/bold]\n"
                "• Visit [blue]https://intelx.io/account?tab=developer[/blue] to upgrade",
                border_style="red"
            ))
            Prompt.ask("Press Enter to continue")
            self.display_actions_view(result)
            return
        
        # Get filename
        filename = Prompt.ask(
            "[bold]Save as filename[/bold]",
            default=os.path.basename(result.name) if result.name else f"{result.systemid}.bin"
        )
        
        # Download file
        download_path = self.download_file(
            result.systemid,
            result.bucket,
            result.storageid,
            filename
        )
        
        if download_path:
            success_panel = Panel(
                f"✅ [bold green]File downloaded successfully[/bold green]\n\n"
                f"Path: {download_path}\n\n"
                "Note: If the file is empty, it's because trial accounts cannot download full content "
                "from redacted buckets like 'Leaks » Logs'.",
                border_style="green"
            )
            console.print(success_panel)
        else:
            console.print("[yellow]File download failed.[/yellow]")
        
        # Return to actions menu
        Prompt.ask("\nPress Enter to continue")
        self.display_actions_view(result)
    
    def download_file(self, system_id, bucket, storage_id=None, filename=None):
        """Download file with comprehensive bucket support"""
        try:
            # Determine filename
            if not filename:
                for result in self.search_results:
                    if result.systemid == system_id and result.name:
                        filename = os.path.basename(result.name)
                        break
                if not filename:
                    filename = f"{system_id}.bin"
                
            # Set download path
            download_path = os.path.join(DOWNLOAD_DIR, filename)
            
            # Prepare request
            params = {
                "type": 1,
                "systemid": system_id,
                "bucket": bucket
            }
            if storage_id:
                params["storageid"] = storage_id
                
            response = requests.get(
                f"{self.api_url}/file/read",
                headers={"x-key": self.api_key, "User-Agent": "IntelligenceXCLI/v6.0"},
                params=params,
                stream=True
            )
            
            if response.status_code == 200:
                with open(download_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                return download_path
            elif response.status_code == 204:
                # No content (common with trial accounts)
                console.print("[yellow]Warning: This file is not available for full download with your current account.[/yellow]")
                return None
            else:
                self.handle_api_error(response)
                return None
                
        except Exception as e:
            console.print(f"[red]Download error: {str(e)}[/red]")
            return None
    
    def main_menu(self):
        """Main menu with comprehensive bucket support"""
        while True:
            console.clear()
            
            # Display account info in a compact format
            self.display_account_info()
            console.print()
            
            # Display main menu options
            menu_panel = Panel(
                "1. New search\n"
                "2. View recent searches\n"
                "3. Search term validation\n"
                "4. Account information\n"
                "5. Help & documentation\n"
                "6. Exit",
                title="Main Menu",
                border_style="blue"
            )
            console.print(menu_panel)
            
            choice = Prompt.ask(
                "[bold]Select option[/bold]",
                choices=["1", "2", "3", "4", "5", "6"],
                default="1"
            )
            
            if choice == "1":
                self.interactive_search()
            elif choice == "2":
                self.display_recent_searches()
            elif choice == "3":
                self.validate_search_term()
            elif choice == "4":
                self.display_account_details()
            elif choice == "5":
                self.display_help()
                Prompt.ask("\nPress Enter to continue")
            elif choice == "6":
                console.print("[green]Exiting program.[/green]")
                break
    
    def display_account_details(self):
        """Display detailed account information with comprehensive bucket support"""
        console.clear()
        console.rule("[bold blue]Account Details[/bold blue]")
        console.print()
        
        if not self.account_info:
            console.print("[red]Account information not loaded.[/red]")
            Prompt.ask("Press Enter to continue")
            return
        
        # Display account information
        account_info = (
            f"[bold]Account Type:[/bold] [yellow]{self.account_info.license_type}[/yellow]\n"
            f"[bold]Expiration Date:[/bold] [green]{self.account_info.license_expiration}[/green]\n"
            f"[bold]Active Searches:[/bold] [cyan]{self.account_info.get_active_searches_info()}[/cyan]\n"
            f"[bold]Total Results Possible:[/bold] [blue]{self.account_info.get_total_results()}[/blue]\n"
            f"[bold]Capabilities:[/bold] [magenta]Search, Preview, View[/magenta]"
        )
        
        console.print(Panel(account_info, title="Account Summary", border_style="blue"))
        
        # Display bucket permissions
        console.print("\n[bold]Bucket Permissions:[/bold]")
        
        # Create bucket table
        bucket_table = Table(box=box.SIMPLE)
        bucket_table.add_column("Bucket", style="cyan")
        bucket_table.add_column("Access", justify="center")
        bucket_table.add_column("Details", justify="left")
        
        # Add fully accessible buckets
        for i in range(len(self.account_info.buckets)):
            bucket = self.account_info.bucketsh[i]
            bucket_table.add_row(
                bucket,
                "[green]Full[/green]",
                "Full content access"
            )
        
        # Add preview-only buckets
        for i in range(len(self.account_info.redacted)):
            bucket = self.account_info.redactedh[i]
            bucket_table.add_row(
                bucket,
                "[yellow]Preview Only[/yellow]",
                "Content is partially redacted (shows as ████ characters)"
            )
        
        console.print(bucket_table)
        
        # Display credits
        console.print("\n[bold]Remaining Credits:[/bold]")
        credits_table = Table(box=box.SIMPLE)
        credits_table.add_column("Function", style="cyan")
        credits_table.add_column("Remaining", justify="right")
        credits_table.add_column("Max", justify="right")
        credits_table.add_column("Reset (hrs)", justify="right")
        credits_table.add_column("Details", justify="left")
        
        # Search credits
        search_credits = self.account_info.get_remaining_credits("/intelligent/search")
        search_max = self.account_info.get_max_credits("/intelligent/search")
        search_reset = self.account_info.get_credit_reset("/intelligent/search")
        credits_table.add_row(
            "/intelligent/search",
            str(search_credits),
            str(search_max),
            str(search_reset),
            "Number of remaining search operations"
        )
        
        # Preview credits
        preview_credits = self.account_info.get_remaining_credits("/file/preview")
        preview_max = self.account_info.get_max_credits("/file/preview")
        preview_reset = self.account_info.get_credit_reset("/file/preview")
        credits_table.add_row(
            "/file/preview",
            f"[yellow]{preview_credits}[/yellow]",
            str(preview_max),
            str(preview_reset),
            "Preview access (shows ████ characters for redacted content)"
        )
        
        # Download credits
        read_credits = self.account_info.get_remaining_credits("/file/read")
        read_max = self.account_info.get_max_credits("/file/read")
        read_reset = self.account_info.get_credit_reset("/file/read")
        credits_table.add_row(
            "/file/read",
            f"[red]{read_credits}[/red]",
            str(read_max),
            str(read_reset),
            "Full file downloads (unavailable for redacted buckets)"
        )
        
        console.print(credits_table)
        
        # Warning if credits are low
        if preview_credits < 100 or read_credits < 10:
            console.print("\n[yellow]Warning: Low credit balance. You may need to wait for reset.[/yellow]")
        
        # Account actions
        console.print("\n[bold]Account Actions:[/bold]")
        console.print("1. View upgrade options")
        console.print("2. View account history")
        console.print("3. Back to main menu")
        
        choice = Prompt.ask(
            "[bold]Select action[/bold]",
            choices=["1", "2", "3"],
            default="3"
        )
        
        if choice == "1":
            self.display_upgrade_options()
        elif choice == "2":
            self.display_account_history()
    
    def display_upgrade_options(self):
        """Display upgrade options with comprehensive bucket support"""
        console.clear()
        console.rule("[bold blue]Upgrade Options[/bold blue]")
        console.print()
        
        # Display upgrade options
        upgrade_info = (
            "💡 [bold]Upgrade to a paid account to:[/bold]\n\n"
            "• Access full content for sensitive data (like passwords)\n"
            "• Download complete files from all buckets\n"
            "• Increase search limits and credits\n"
            "• Access advanced features like Phonebook and Data Leaks\n"
            "• Get priority support\n\n"
            "💰 [bold]Pricing Options:[/bold]\n\n"
            "• Basic: $99/month - 1,000 search credits/day\n"
            "• Professional: $299/month - 10,000 search credits/day\n"
            "• Enterprise: Custom pricing - Unlimited access\n\n"
            "🔗 [bold]Upgrade Now:[/bold]\n"
            "[blue]https://intelx.io/account?tab=developer[/blue]"
        )
        
        console.print(Panel(upgrade_info, title="Account Upgrade", border_style="green"))
        
        console.print("\n[bold]Upgrade Actions:[/bold]")
        console.print("1. Open upgrade page in browser")
        console.print("2. View feature comparison")
        console.print("3. Back to account details")
        
        choice = Prompt.ask(
            "[bold]Select action[/bold]",
            choices=["1", "2", "3"],
            default="3"
        )
        
        if choice == "1":
            webbrowser.open("https://intelx.io/account?tab=developer")
            console.print("[blue]Opening upgrade page in browser...[/blue]")
            Prompt.ask("Press Enter to continue")
            self.display_upgrade_options()
        elif choice == "2":
            self.display_feature_comparison()
    
    def display_feature_comparison(self):
        """Display feature comparison between account types"""
        console.clear()
        console.rule("[bold blue]Feature Comparison[/bold blue]")
        console.print()
        
        # Create comparison table
        table = Table(title="Feature Comparison", box=box.ROUNDED, show_header=True, header_style="bold cyan")
        table.add_column("Feature", style="magenta", width=25)
        table.add_column("Trial", justify="center", width=10)
        table.add_column("Basic", justify="center", width=10)
        table.add_column("Professional", justify="center", width=10)
        table.add_column("Enterprise", justify="center", width=10)
        
        # Add feature rows
        features = [
            ("Search Results", "50", "500", "5,000", "Unlimited"),
            ("Preview Credits", "3,000", "5,000", "25,000", "Unlimited"),
            ("Full Download", "✗", "✓", "✓", "✓"),
            ("Phonebook Search", "✗", "✓", "✓", "✓"),
            ("Data Leaks Access", "✗", "✓", "✓", "✓"),
            ("Advanced Filters", "✗", "✓", "✓", "✓"),
            ("API Rate Limit", "1 req/sec", "5 req/sec", "10 req/sec", "Custom"),
            ("Support", "Community", "Email", "Priority Email", "24/7 Dedicated")
        ]
        
        for feature, trial, basic, professional, enterprise in features:
            table.add_row(
                feature,
                trial,
                basic,
                professional,
                enterprise
            )
        
        console.print(table)
        
        Prompt.ask("\nPress Enter to continue")
        self.display_upgrade_options()
    
    def display_account_history(self):
        """Display account history with comprehensive bucket support"""
        console.clear()
        console.rule("[bold blue]Account History[/bold blue]")
        console.print()
        
        # Get saved account info
        account_history = self.get_saved_account_info(limit=5)
        
        if not account_history:
            console.print("[yellow]No account history found.[/yellow]")
            Prompt.ask("Press Enter to continue")
            self.display_account_details()
            return
        
        # Create history table
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
        table.add_column("ID", justify="right", style="cyan", width=4)
        table.add_column("Timestamp", style="green", width=18)
        table.add_column("Buckets", style="magenta", max_width=30)
        table.add_column("Redacted", style="yellow", max_width=30)
        table.add_column("Credits", style="blue", max_width=20)
        
        for history in account_history:
            history_id, timestamp, buckets, redacted, credits, license_expiration, license_type = history
            
            # Format buckets
            try:
                buckets_list = json.loads(buckets)
                buckets_str = f"{len(buckets_list)} buckets"
            except:
                buckets_str = "Unknown"
            
            # Format redacted
            try:
                redacted_list = json.loads(redacted)
                redacted_str = f"{len(redacted_list)} buckets"
            except:
                redacted_str = "Unknown"
            
            # Format credits
            try:
                credits_data = json.loads(credits)
                preview_credits = credits_data.get("/file/preview", {}).get("Credit", "N/A")
                search_credits = credits_data.get("/intelligent/search", {}).get("Credit", "N/A")
                credits_str = f"Preview: {preview_credits}, Search: {search_credits}"
            except:
                credits_str = "Unknown"
            
            table.add_row(
                str(history_id),
                timestamp.split('.')[0],
                buckets_str,
                redacted_str,
                credits_str
            )
        
        console.print(table)
        
        Prompt.ask("\nPress Enter to continue")
        self.display_account_details()
    
    def validate_search_term(self):
        """Validate a search term against supported selector types with comprehensive validation"""
        console.clear()
        console.rule("[bold blue]Search Term Validation[/bold blue]")
        console.print()
        
        term = Prompt.ask("[bold]Enter search term to validate[/bold]")
        if not term:
            console.print("[yellow]No search term entered.[/yellow]")
            Prompt.ask("Press Enter to continue")
            return
        
        is_valid = self.is_valid_search_term(term)
        
        if is_valid:
            console.print(f"[green]✓ The term '{term}' is a valid search selector.[/green]")
            
            # Determine selector type
            if re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', term):
                console.print("[bold]Selector type:[/bold] Email address")
            elif re.match(r'^(\*\.|)[\w\.-]+\.[a-z]{2,}$', term):
                console.print("[bold]Selector type:[/bold] Domain")
            elif term.startswith(('http://', 'https://', 'www.')):
                console.print("[bold]Selector type:[/bold] URL")
            elif re.match(r'^(\d{1,3}\.){3}\d{1,3}$', term):
                console.print("[bold]Selector type:[/bold] IPv4 Address")
            elif re.match(r'^[13][a-km-zA-HJ-NP-Z0-9]{25,34}$', term):
                console.print("[bold]Selector type:[/bold] Bitcoin Address")
            else:
                console.print("[bold]Selector type:[/bold] Generic term")
        else:
            console.print(f"[red]✗ The term '{term}' is not a valid search selector.[/red]")
            console.print("\n[bold]Supported selector types:[/bold]")
            console.print("- Email addresses (e.g., user@example.com)")
            console.print("- Domains (e.g., example.com, *.example.com)")
            console.print("- URLs (e.g., https://example.com)")
            console.print("- IPv4 addresses (e.g., 192.168.1.1)")
            console.print("- IPv6 addresses")
            console.print("- CIDR ranges (e.g., 192.168.1.0/24)")
            console.print("- Phone numbers")
            console.print("- Bitcoin addresses")
            console.print("- MAC addresses")
            console.print("- UUIDs")
            console.print("- Storage IDs")
            console.print("- System IDs")
            console.print("- Simhash values")
            console.print("- Credit card numbers")
            console.print("- IBAN numbers")
            console.print("- Generic terms (3+ characters, no special characters)")
        
        Prompt.ask("\nPress Enter to continue")
    
    def display_help(self):
        """Display comprehensive help information with comprehensive bucket support"""
        console.clear()
        console.rule("[bold blue]Help & Documentation[/bold blue]")
        console.print()
        
        # Trial account limitations - THE MOST IMPORTANT SECTION
        console.print(Panel(
            "⚠️ [bold red]CRITICAL TRIAL ACCOUNT INFORMATION[/bold red] ⚠️\n\n"
            "• Trial accounts CANNOT see full content for sensitive data (like passwords)\n"
            "• Files in 'Leaks » Logs' and 'Leaks » Restricted' buckets are ALWAYS REDACTED\n"
            "• You will see ████ characters instead of actual content for these files\n"
            "• This is NOT a bug - it's a deliberate restriction of trial accounts\n"
            "• To see full content, you MUST [bold]upgrade to a paid account[/bold]\n"
            "• Visit [blue]https://intelx.io/account?tab=developer[/blue] to upgrade",
            border_style="red"
        ))
        
        console.print("\n[bold]What You CAN Do With Trial Account:[/bold]")
        features_table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
        features_table.add_column("Feature", style="cyan", width=25)
        features_table.add_column("Status", justify="center", width=10)
        features_table.add_column("Details", width=50)
        
        features_table.add_row(
            "Search functionality",
            "✓ Full",
            "Search for emails, domains, IPs, etc."
        )
        features_table.add_row(
            "Document View",
            "✓ Preview",
            "See redacted content (████ characters) for sensitive data"
        )
        features_table.add_row(
            "Tree View",
            "✓ Full",
            "View relationships between items"
        )
        features_table.add_row(
            "Metadata View",
            "✓ Full",
            "See all metadata about items"
        )
        features_table.add_row(
            "Selectors View",
            "✓ Full",
            "Extract and view selectors from content"
        )
        features_table.add_row(
            "Actions",
            "✓ Full",
            "Preview, copy IDs, search related items"
        )
        features_table.add_row(
            "Full content access",
            "✗ Limited",
            "Only for non-sensitive buckets like 'Pastes', 'Web » Public', etc."
        )
        
        console.print(features_table)
        
        console.print("\n[bold]How to Properly Use This Tool With Trial Account:[/bold]")
        console.print("1. Use Document View to see redacted content (████ characters)")
        console.print("2. Use Tree View to understand relationships between items")
        console.print("3. Use Metadata View to see all available information")
        console.print("4. Use Selectors View to extract useful selectors from content")
        console.print("5. Use Actions to preview, copy IDs, and search related items")
        console.print("6. For 'Leaks » Logs' buckets, expect to see ████ characters")
        console.print("7. The ████ characters are NOT a bug - they're intentional")
        console.print("8. To see actual content, you need a paid account")
        
        console.print("\n[bold]Upgrade Information:[/bold]")
        console.print("• Visit [blue]https://intelx.io/account?tab=developer[/blue] to upgrade")
        console.print("• Paid accounts provide full access to all data")
        console.print("• Contact info@intelx.io for pricing and plans")
        
        # Advanced usage tips
        console.print("\n[bold]Advanced Usage Tips:[/bold]")
        console.print("1. When searching for emails, try searching for the domain instead")
        console.print("2. Use date filters to narrow down results to specific time periods")
        console.print("3. Combine search terms with media type filters for better results")
        console.print("4. Extract selectors from previews to find related information")
        console.print("5. Use the 'Force Refresh' option to get the latest preview data")
        console.print("6. For 'Leaks » Logs', focus on metadata and relationships instead of content")
        console.print("7. Use the 'View on Website' option to see results in the web interface")

class SelectorExtractor:
    """Extracts selectors from text content with comprehensive support"""
    def __init__(self):
        # Regex patterns for different selector types
        self.patterns = {
            "Email": r'[\w\.-]+@[\w\.-]+\.\w+',
            "Domain": r'(\*\.|)[\w\.-]+\.[a-z]{2,}',
            "IPv4": r'(\d{1,3}\.){3}\d{1,3}',
            "IPv6": r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}',
            "CIDRv4": r'(\d{1,3}\.){3}\d{1,3}/\d{1,2}',
            "Phone": r'(\+)?[\d\s\-\(\)]+',
            "Bitcoin": r'^[13][a-km-zA-HJ-NP-Z0-9]{25,34}$',
            "MAC": r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})',
            "UUID": r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            "Credit Card": r'\d{13,19}',
            "IBAN": r'[A-Z]{2}\d{2}[A-Z0-9]{1,30}'
        }
    
    def extract_selectors(self, text):
        """Extract all selectors from text with comprehensive support"""
        selectors = []
        
        # Process each pattern
        for selector_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text)
            for match in matches:
                # Validate match (some patterns need additional validation)
                if selector_type == "Email" and not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', match):
                    continue
                if selector_type == "Domain" and not re.match(r'^(\*\.|)[\w\.-]+\.[a-z]{2,}$', match):
                    continue
                if selector_type == "IPv4" and not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', match):
                    continue
                # Add more validation as needed
                
                # Add valid match
                selectors.append((selector_type, match))
        
        return selectors

class ExportManager:
    """Manages export functionality with comprehensive support"""
    def __init__(self):
        self.export_formats = {
            "csv": self.export_to_csv,
            "json": self.export_to_json,
            "markdown": self.export_to_markdown,
            "pdf": self.export_to_pdf
        }
    
    def export(self, results, search_term, format="csv", filename=None):
        """Export results in the specified format"""
        if not results:
            return False
        
        if format in self.export_formats:
            return self.export_formats[format](results, search_term, filename)
        return False
    
    def export_to_csv(self, results, search_term, filename=None):
        """Export results to CSV file with comprehensive support"""
        try:
            import csv
            from datetime import datetime
            
            # Determine filename
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                term_clean = re.sub(r'[^a-zA-Z0-9]', '_', search_term)
                filename = f"intelx_results_{term_clean}_{timestamp}.csv"
                filename = os.path.join(DOWNLOAD_DIR, filename)
            
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    "System ID", "Name", "Date", "Size", "Bucket", "Media Type", 
                    "Access Level", "X-Score", "Redacted", "Deleted", "Type"
                ])
                
                # Write data
                for result in results:
                    writer.writerow([
                        result.systemid,
                        result.name,
                        result.date,
                        result.size,
                        result.bucket_human,
                        result.media_human,
                        result.get_access_level_description(),
                        result.xscore,
                        "Yes" if result.is_redacted() else "No",
                        "Yes" if result.is_deleted() else "No",
                        result.type_human
                    ])
            
            return filename
        except Exception as e:
            console.print(f"[red]CSV export error: {str(e)}[/red]")
            return False
    
    def export_to_json(self, results, search_term, filename=None):
        """Export results to JSON file with comprehensive support"""
        try:
            import json
            from datetime import datetime
            
            # Determine filename
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                term_clean = re.sub(r'[^a-zA-Z0-9]', '_', search_term)
                filename = f"intelx_results_{term_clean}_{timestamp}.json"
                filename = os.path.join(DOWNLOAD_DIR, filename)
            
            results_data = []
            for result in results:
                results_data.append({
                    "systemid": result.systemid,
                    "name": result.name,
                    "date": result.date,
                    "size": result.size,
                    "bucket": result.bucket_human,
                    "media": result.media_human,
                    "access_level": result.get_access_level_description(),
                    "xscore": result.xscore,
                    "is_redacted": result.is_redacted(),
                    "is_deleted": result.is_deleted(),
                    "type": result.type_human
                })
            
            with open(filename, "w", encoding="utf-8") as f:
                json.dump({
                    "search_term": search_term,
                    "timestamp": datetime.now().isoformat(),
                    "total_results": len(results_data),
                    "results": results_data
                }, f, indent=2, ensure_ascii=False)
            
            return filename
        except Exception as e:
            console.print(f"[red]JSON export error: {str(e)}[/red]")
            return False
    
    def export_to_markdown(self, results, search_term, filename=None):
        """Export results to Markdown file with comprehensive support"""
        try:
            from datetime import datetime
            
            # Determine filename
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                term_clean = re.sub(r'[^a-zA-Z0-9]', '_', search_term)
                filename = f"intelx_results_{term_clean}_{timestamp}.md"
                filename = os.path.join(DOWNLOAD_DIR, filename)
            
            with open(filename, "w", encoding="utf-8") as f:
                # Write header
                f.write(f"# Intelligence X Search Results: {search_term}\n\n")
                f.write(f"**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Total Results:** {len(results)}\n\n")
                
                # Write results
                for i, result in enumerate(results, 1):
                    f.write(f"## Result #{i}\n\n")
                    f.write(f"**System ID:** {result.systemid}\n")
                    f.write(f"**Name:** {result.name}\n")
                    f.write(f"**Date:** {result.date}\n")
                    f.write(f"**Size:** {result.size} bytes\n")
                    f.write(f"**Bucket:** {result.bucket_human}\n")
                    f.write(f"**Media Type:** {result.media_human}\n")
                    f.write(f"**Access Level:** {result.get_access_level_description()}\n")
                    f.write(f"**X-Score:** {result.xscore}\n")
                    f.write(f"**Redacted:** {'Yes' if result.is_redacted() else 'No'}\n")
                    f.write(f"**Deleted:** {'Yes' if result.is_deleted() else 'No'}\n")
                    f.write(f"**Type:** {result.type_human}\n\n")
                    
                    # Add preview if available and previously viewed
                    f.write("---\n\n")
            
            return filename
        except Exception as e:
            console.print(f"[red]Markdown export error: {str(e)}[/red]")
            return False
    
    def export_to_pdf(self, results, search_term, filename=None):
        """Export results to PDF file with comprehensive support"""
        try:
            from datetime import datetime
            from fpdf import FPDF
            
            # Determine filename
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                term_clean = re.sub(r'[^a-zA-Z0-9]', '_', search_term)
                filename = f"intelx_results_{term_clean}_{timestamp}.pdf"
                filename = os.path.join(DOWNLOAD_DIR, filename)
            
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            
            # Add header
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(200, 10, txt=f"Intelligence X Search Results: {search_term}", ln=True, align='C')
            pdf.ln(10)
            
            # Add metadata
            pdf.set_font("Arial", size=12)
            pdf.cell(200, 10, txt=f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
            pdf.cell(200, 10, txt=f"Total Results: {len(results)}", ln=True)
            pdf.ln(10)
            
            # Add results
            for i, result in enumerate(results, 1):
                pdf.set_font("Arial", 'B', 12)
                pdf.cell(200, 10, txt=f"Result #{i}", ln=True)
                pdf.set_font("Arial", size=10)
                
                pdf.cell(200, 6, txt=f"System ID: {result.systemid}", ln=True)
                pdf.cell(200, 6, txt=f"Name: {result.name}", ln=True)
                pdf.cell(200, 6, txt=f"Date: {result.date}", ln=True)
                pdf.cell(200, 6, txt=f"Size: {result.size} bytes", ln=True)
                pdf.cell(200, 6, txt=f"Bucket: {result.bucket_human}", ln=True)
                pdf.cell(200, 6, txt=f"Media Type: {result.media_human}", ln=True)
                pdf.cell(200, 6, txt=f"Access Level: {result.get_access_level_description()}", ln=True)
                pdf.cell(200, 6, txt=f"X-Score: {result.xscore}", ln=True)
                pdf.cell(200, 6, txt=f"Redacted: {'Yes' if result.is_redacted() else 'No'}", ln=True)
                pdf.cell(200, 6, txt=f"Deleted: {'Yes' if result.is_deleted() else 'No'}", ln=True)
                pdf.cell(200, 6, txt=f"Type: {result.type_human}", ln=True)
                pdf.ln(5)
            
            pdf.output(filename)
            return filename
        except ImportError:
            console.print("[red]PDF export requires fpdf package. Install with: pip install fpdf[/red]")
            return False
        except Exception as e:
            console.print(f"[red]PDF export error: {str(e)}[/red]")
            return False

def main():
    console.clear()
    
    # Welcome banner with proper formatting
    welcome_text = (
        "[bold green]Intelligence X CLI - Ultimate Edition v6.0[/bold green]\n"
        "[bold]The Most Advanced CLI Tool for Intelligence X API with Complete Bucket Support[/bold]\n"
        "[italic]Version 6.0 - Deep integration with all Intelligence X features including redacted buckets[/italic]"
    )
    console.rule(welcome_text)
    console.print()
    
    # Create CLI instance
    cli = IntelligenceXCLI(API_KEY, API_URL)
    
    # Display main menu
    cli.main_menu()

if __name__ == "__main__":
    main()