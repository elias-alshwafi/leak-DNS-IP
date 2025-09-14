#!/usr/bin/env python3
"""Intelligence X CLI - Ultimate Edition v7.2
The Most Advanced CLI Tool for Intelligence X API with Complete Bucket Support"""

import os
import sys
import json
import time
import re
import sqlite3
import webbrowser
from datetime import datetime
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich import box
import pyperclip

# Global configuration
API_URL = "https://free.intelx.io/"
API_KEY = "24fcfc64-849f-4e15-b365-40419b7d6624"  # Replace with your actual API key
DOWNLOAD_DIR = "intelx_downloads"
CACHE_DIR = "intelx_cache"
DB_FILE = "intelx_data.db"
console = Console()

# Create necessary directories
os.makedirs(DOWNLOAD_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# Initialize database
def init_database():
    """Initialize SQLite database for storing search history, previews, and extracted selectors"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create search history table
    cursor.execute('''CREATE TABLE IF NOT EXISTS search_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        term TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        result_count INTEGER,
        buckets TEXT,
        date_from TEXT,
        date_to TEXT,
        sort INTEGER,
        media INTEGER
    )''')
    
    # Create search results table
    cursor.execute('''CREATE TABLE IF NOT EXISTS search_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        search_id INTEGER NOT NULL,
        systemid TEXT NOT NULL,
        storageid TEXT NOT NULL,
        name TEXT,
        description TEXT,
        date TEXT,
        added TEXT,
        modified TEXT,
        size INTEGER,
        bucket TEXT,
        media INTEGER,
        accesslevel INTEGER,
        xscore INTEGER,
        simhash TEXT,
        simhash_human TEXT,
        instore BOOLEAN,
        is_redacted BOOLEAN,
        FOREIGN KEY(search_id) REFERENCES search_history(id)
    )''')
    
    # Create file previews table
    cursor.execute('''CREATE TABLE IF NOT EXISTS file_previews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        systemid TEXT NOT NULL UNIQUE,
        preview TEXT,
        timestamp TEXT NOT NULL
    )''')
    
    # Create extracted selectors table
    cursor.execute('''CREATE TABLE IF NOT EXISTS extracted_selectors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        systemid TEXT NOT NULL,
        selector_type TEXT NOT NULL,
        selector_value TEXT NOT NULL,
        bucket_type TEXT NOT NULL,
        is_pro BOOLEAN NOT NULL,
        is_sensitive BOOLEAN NOT NULL,
        timestamp TEXT NOT NULL
    )''')
    
    # Create account information table
    cursor.execute('''CREATE TABLE IF NOT EXISTS account_info (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        buckets TEXT,
        redacted TEXT,
        credits TEXT,
        license_expiration TEXT,
        license_type TEXT
    )''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_database()

class SearchResult:
    """Represents a search result from Intelligence X API"""
    def __init__(self, data):
        self.systemid = data.get("systemid", "")
        self.storageid = data.get("storageid", "")
        self.name = data.get("name", "")
        self.description = data.get("description", "")
        self.date = data.get("date", "")
        self.added = data.get("added", "")
        self.modified = data.get("modified", "")
        self.size = data.get("size", 0)
        self.bucket = data.get("bucket", "")
        self.media = data.get("media", 0)
        self.accesslevel = data.get("accesslevel", 0)
        self.xscore = data.get("xscore", 0)
        self.simhash = data.get("simhash", "")
        self.simhash_human = data.get("simhash_human", "")
        self.instore = data.get("instore", True)
        self.is_redacted = data.get("is_redacted", False)
        self.relations = data.get("relations", [])
    
    def get_access_level_description(self):
        """Get human-readable description of access level"""
        access_levels = {
            0: "No Access",
            1: "Trial Access",
            2: "Standard Access",
            3: "Premium Access",
            4: "Redacted (Preview Only)"
        }
        return access_levels.get(self.accesslevel, "Unknown")
    
    def is_preview_only(self):
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
            10: "Invalid",
            11: "Invalid",
            12: "Invalid",
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
    
    def get_bucket_type(self):
        """Map bucket name to user-friendly bucket type"""
        bucket_mapping = {
            "leaks.logs": "Leaks",
            "leaks.private.general": "Leaks PRIVATE",
            "leaks.public.general": "Leaks PUBLIC",
            "leaks.comb": "Leaks COMB",
            "stealer.logs": "Stealer Logs",
            "pastes": "Pastes",
            "darknet.tor": "Darknet TOR",
            "darknet.i2p": "Darknet I2P",
            "web.public": "Web Public",
            "web.public.de": "Web Public DE",
            "web.public.kp": "Web Public KP",
            "web.public.ua": "Web Public UA",
            "web.public.com": "Web Public COM",
            "web.gov.ru": "Web GOV RU",
            "web.public.peer": "Web Public PEER"
        }
        return bucket_mapping.get(self.bucket, self.bucket)
    
    def is_pro_bucket(self):
        """Determine if bucket requires PRO account"""
        pro_buckets = [
            "leaks.logs", "leaks.private.general", "leaks.comb", 
            "stealer.logs", "darknet.tor", "darknet.i2p"
        ]
        return self.bucket in pro_buckets
    
    def is_sensitive_bucket(self):
        """Determine if bucket contains sensitive data"""
        sensitive_buckets = [
            "leaks.logs", "leaks.private.general", "leaks.comb", "stealer.logs"
        ]
        return self.bucket in sensitive_buckets
    
    def can_download(self):
        """Check if file can be downloaded based on account type"""
        # Trial accounts can only download from non-sensitive buckets
        return not self.is_sensitive_bucket() or not self.is_redacted

class AccountInfo:
    """Stores account information from Intelligence X API"""
    def __init__(self, data):
        self.buckets = data.get("buckets", [])
        self.redacted = data.get("redacted", [])
        self.credits = data.get("credits", {})
        self.license_expiration = data.get("license_expiration", "")
        self.license_type = data.get("license_type", "trial")
        self.api_key = data.get("api_key", "")
    
    def get_bucket_names(self):
        """Get user-friendly names for accessible buckets"""
        bucket_names = {
            "leaks.logs": "Leaks » Logs",
            "leaks.private.general": "Leaks » Private",
            "leaks.public.general": "Leaks » Public",
            "leaks.comb": "Leaks » COMB",
            "stealer.logs": "Stealer Logs",
            "pastes": "Pastes",
            "darknet.tor": "Darknet TOR",
            "darknet.i2p": "Darknet I2P",
            "web.public": "Web » Public",
            "web.public.de": "Web » Public DE",
            "web.public.kp": "Web » Public KP",
            "web.public.ua": "Web » Public UA",
            "web.public.com": "Web » Public COM",
            "web.gov.ru": "Web » GOV RU",
            "web.public.peer": "Web » Public PEER"
        }
        
        return [bucket_names.get(bucket, bucket) for bucket in self.buckets]

class PreviewManager:
    """Manages file previews from Intelligence X API"""
    def __init__(self, api_key, api_url):
        self.api_key = api_key
        self.api_url = api_url
        self.cache = {}
    
    def get_preview(self, systemid, bucket, max_lines=12):
        """Get preview of a file from API"""
        # Check cache first
        cache_key = f"{systemid}_{bucket}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # API request for preview
        try:
            params = {
                "c": 0,  # Content type
                "m": 24,  # Media type (Text file)
                "f": 0,  # Target format (Text)
                "sid": systemid,
                "b": bucket,
                "l": max_lines,
                "e": 1  # HTML escaping
            }
            headers = {"x-key": self.api_key}
            response = requests.get(
                f"{self.api_url}/file/preview",
                params=params,
                headers=headers
            )
            
            if response.status_code == 200:
                preview = response.text
                self.cache[cache_key] = preview
                return preview
            else:
                return f"❌ Error getting preview: {response.status_code}"
        except Exception as e:
            return f"❌ Error: {str(e)}"

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
    
    def extract_selectors(self, text, bucket=""):
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
                
                # Add valid match
                selectors.append((selector_type, match, bucket))
        
        return selectors

class IntelligenceXCLI:
    """Main CLI class for Intelligence X API interaction"""
    def __init__(self, api_key, api_url):
        self.api_key = api_key
        self.api_url = api_url
        self.account_info = None
        self.current_search_history_id = None
        self.last_preview = None
        self.last_preview_systemid = None
        self.preview_manager = PreviewManager(api_key, api_url)
        self.current_view = "document"  # document, tree, metadata, selectors, actions
        self.selector_extractor = SelectorExtractor()
        self.is_searching = False
        self.search_progress = None
        self.search_task = None
        
        # Validate API key
        if not self.validate_api_key():
            console.print("[red]Error: Invalid API key or insufficient permissions.[/red]")
            sys.exit(1)
        
        # Get account information
        self.get_account_info()
    
    def validate_api_key(self):
        """Validate the API key by making a test request"""
        try:
            headers = {"x-key": self.api_key}
            response = requests.get(
                f"{self.api_url}/authenticate/info",
                headers=headers
            )
            return response.status_code == 200
        except Exception as e:
            console.print(f"[red]API connection error: {str(e)}[/red]")
            return False
    
    def get_account_info(self):
        """Get account information from API"""
        try:
            headers = {"x-key": self.api_key}
            response = requests.get(
                f"{self.api_url}/account",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                self.account_info = AccountInfo(data)
                
                # Save to database
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute('''INSERT INTO account_info 
                    (timestamp, buckets, redacted, credits, license_expiration, license_type)
                    VALUES (?, ?, ?, ?, ?, ?)''', (
                    datetime.now().isoformat(),
                    json.dumps(data.get("buckets", [])),
                    json.dumps(data.get("redacted", [])),
                    json.dumps(data.get("credits", {})),
                    data.get("license_expiration", ""),
                    data.get("license_type", "trial")
                ))
                conn.commit()
                conn.close()
                
                return True
            else:
                console.print(f"[red]Error getting account info: {response.status_code}[/red]")
                return False
        except Exception as e:
            console.print(f"[red]Error getting account info: {str(e)}[/red]")
            return False
    
    def display_account_info(self):
        """Display account information with enhanced details"""
        if not self.account_info:
            self.get_account_info()
        
        if not self.account_info:
            console.print("[red]Error: Could not retrieve account information.[/red]")
            return
        
        console.clear()
        console.rule("[bold blue]Account Information[/bold blue]")
        console.print()
        
        # Account summary
        account_table = Table(box=box.ROUNDED, show_header=False, border_style="blue")
        account_table.add_column("Field", style="cyan", width=20)
        account_table.add_column("Value", width=40)
        
        account_table.add_row("Account Type", self.account_info.license_type.capitalize())
        account_table.add_row("License Expiration", self.account_info.license_expiration or "N/A")
        
        # Credits information
        credits = self.account_info.credits
        if credits:
            account_table.add_row("Preview Credits", str(credits.get("preview", "N/A")))
            account_table.add_row("Full Download Credits", str(credits.get("full", "N/A")))
        else:
            account_table.add_row("Credits", "N/A")
        
        # Accessible buckets
        buckets = self.account_info.get_bucket_names()
        account_table.add_row("Accessible Buckets", ", ".join(buckets) if buckets else "None")
        
        console.print(account_table)
        console.print()
        
        # Bucket access details
        if buckets:
            console.print("[bold]Bucket Access Details:[/bold]")
            bucket_table = Table(box=box.SIMPLE, show_header=True, header_style="bold green")
            bucket_table.add_column("Bucket", style="cyan")
            bucket_table.add_column("Access Type", width=15)
            bucket_table.add_column("Data Sensitivity", width=20)
            
            for bucket in self.account_info.buckets:
                bucket_type = self._get_bucket_type(bucket)
                access_type = "PRO" if self._is_pro_bucket(bucket) else "FREE"
                sensitivity = "High" if self._is_sensitive_bucket(bucket) else "Standard"
                
                bucket_table.add_row(
                    bucket_type,
                    access_type,
                    sensitivity
                )
            
            console.print(bucket_table)
        
        console.print()
        console.print("[bold]API Key:[/bold]")
        console.print(f"[cyan]{self.api_key[:5]}...{self.api_key[-5:]}[/cyan]")
    
    def _get_bucket_type(self, bucket_name):
        """Map bucket name to user-friendly bucket type"""
        bucket_mapping = {
            "leaks.logs": "Leaks",
            "leaks.private.general": "Leaks PRIVATE",
            "leaks.public.general": "Leaks PUBLIC",
            "leaks.comb": "Leaks COMB",
            "stealer.logs": "Stealer Logs",
            "pastes": "Pastes",
            "darknet.tor": "Darknet TOR",
            "darknet.i2p": "Darknet I2P",
            "web.public": "Web Public",
            "web.public.de": "Web Public DE",
            "web.public.kp": "Web Public KP",
            "web.public.ua": "Web Public UA",
            "web.public.com": "Web Public COM",
            "web.gov.ru": "Web GOV RU",
            "web.public.peer": "Web Public PEER"
        }
        return bucket_mapping.get(bucket_name, "Other")
    
    def _is_pro_bucket(self, bucket_name):
        """Determine if bucket requires PRO account"""
        pro_buckets = [
            "leaks.logs", "leaks.private.general", "leaks.comb", 
            "stealer.logs", "darknet.tor", "darknet.i2p"
        ]
        return bucket_name in pro_buckets
    
    def _is_sensitive_bucket(self, bucket_name):
        """Determine if bucket contains sensitive data"""
        sensitive_buckets = [
            "leaks.logs", "leaks.private.general", "leaks.comb", "stealer.logs"
        ]
        return bucket_name in sensitive_buckets
    
    def _redact_sensitive_info(self, value, selector_type):
        """Redact sensitive information for trial accounts"""
        # For phone numbers, redact all but last 4 digits
        if selector_type == "Phone":
            digits = re.sub(r'\D', '', value)
            if len(digits) > 4:
                return '+' + '*' * (len(digits) - 4) + digits[-4:]
            return value
        
        # For emails, redact most of the local part
        if selector_type == "Email":
            parts = value.split('@')
            if len(parts) == 2:
                local = parts[0]
                if len(local) > 3:
                    return local[:2] + '***@' + parts[1]
                return '***@' + parts[1]
        
        # For everything else, redact most characters
        if len(value) > 8:
            return value[:2] + '████' + value[-2:]
        return '████'
    
    def _format_date(self, date_str):
        """Format date string for display"""
        try:
            # Try to parse ISO format
            dt = datetime.fromisoformat(date_str)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return date_str
    
    def _format_size(self, size):
        """Format file size for display"""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.1f} GB"
    
    def _get_leak_type(self, bucket_name):
        """Get leak type from bucket name"""
        if "stealer" in bucket_name.lower():
            return "Stealer Logs"
        elif "comb" in bucket_name.lower():
            return "COMB List"
        elif "private" in bucket_name.lower():
            return "Private Leak"
        return "Public Leak"
    
    def _get_data_sensitivity(self, bucket_name):
        """Get data sensitivity level from bucket name"""
        if "stealer" in bucket_name.lower() or "comb" in bucket_name.lower():
            return "High (Credentials)"
        return "Medium (Personal Data)"
    
    def save_search_history(self, term, result_count, buckets, date_from, date_to, sort, media):
        """Save search to history database"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''INSERT INTO search_history 
            (term, timestamp, result_count, buckets, date_from, date_to, sort, media)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', (
            term,
            datetime.now().isoformat(),
            result_count,
            json.dumps(buckets),
            date_from,
            date_to,
            sort,
            media
        ))
        
        search_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        self.current_search_history_id = search_id
        return search_id
    
    def save_search_results(self, search_id, results):
        """Save search results to database"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        for result in results:
            cursor.execute('''INSERT INTO search_results 
                (search_id, systemid, storageid, name, description, date, added, modified, 
                size, bucket, media, accesslevel, xscore, simhash, simhash_human, instore, is_redacted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
                search_id,
                result.systemid,
                result.storageid,
                result.name,
                result.description,
                result.date,
                result.added,
                result.modified,
                result.size,
                result.bucket,
                result.media,
                result.accesslevel,
                result.xscore,
                result.simhash,
                result.simhash_human,
                result.instore,
                result.is_redacted
            ))
        
        conn.commit()
        conn.close()
    
    def get_search_history(self):
        """Get search history from database"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''SELECT * FROM search_history ORDER BY timestamp DESC LIMIT 10''')
        history = cursor.fetchall()
        
        conn.close()
        return history
    
    def get_search_results(self, search_id):
        """Get search results from database"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''SELECT * FROM search_results WHERE search_id = ?''', (search_id,))
        results_data = cursor.fetchall()
        
        # Convert to SearchResult objects
        results = []
        for row in results_data:
            # Skip the ID and search_id fields
            data = {
                "systemid": row[2],
                "storageid": row[3],
                "name": row[4],
                "description": row[5],
                "date": row[6],
                "added": row[7],
                "modified": row[8],
                "size": row[9],
                "bucket": row[10],
                "media": row[11],
                "accesslevel": row[12],
                "xscore": row[13],
                "simhash": row[14],
                "simhash_human": row[15],
                "instore": bool(row[16]),
                "is_redacted": bool(row[17])
            }
            results.append(SearchResult(data))
        
        conn.close()
        return results
    
    def get_preview_from_db(self, systemid):
        """Get preview from database if available"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''SELECT preview FROM file_previews WHERE systemid = ?''', (systemid,))
        result = cursor.fetchone()
        
        conn.close()
        return result[0] if result else None
    
    def save_preview_to_db(self, systemid, preview):
        """Save preview to database"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''INSERT OR REPLACE INTO file_previews 
            (systemid, preview, timestamp) VALUES (?, ?, ?)''', (
            systemid,
            preview,
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def get_extracted_selectors(self, systemid):
        """Get extracted selectors for a system ID with comprehensive details"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''SELECT selector_type, selector_value, bucket_type, is_pro, is_sensitive 
                          FROM extracted_selectors WHERE systemid = ?''', (systemid,))
        selectors_data = cursor.fetchall()
        
        conn.close()
        
        # Convert to list of tuples
        selectors = []
        for row in selectors_data:
            # Format the selector based on account type
            selector_value = row[1]
            if self.account_info.license_type == "trial" and row[4]:  # is_sensitive
                selector_value = self._redact_sensitive_info(selector_value, row[0])
            
            selectors.append((row[0], selector_value, row[2], "PRO" if row[3] else "FREE"))
        
        return selectors
    
    def save_extracted_selectors(self, systemid, selectors, bucket):
        """Save extracted selectors to database"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Delete existing selectors
        cursor.execute('''DELETE FROM extracted_selectors WHERE systemid = ?''', (systemid,))
        
        # Insert new selectors
        for selector_type, selector_value in selectors:
            cursor.execute('''INSERT INTO extracted_selectors 
                (systemid, selector_type, selector_value, bucket_type, is_pro, is_sensitive, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)''', (
                systemid,
                selector_type,
                selector_value,
                self._get_bucket_type(bucket),
                self._is_pro_bucket(bucket),
                self._is_sensitive_bucket(bucket),
                datetime.now().isoformat()
            ))
        
        conn.commit()
        conn.close()
    
    def get_related_items(self, systemid):
        """Get related items for a result"""
        # In a real implementation, this would query the API for related items
        # For now, we'll simulate some related items
        return [
            {"relation": 0, "target": "Related Document 1"},
            {"relation": 0, "target": "Related Document 2"},
            {"relation": 1, "target": "Unknown Relation"}
        ]
    
    def download_file(self, systemid, bucket, storageid, filename):
        """Download a file from Intelligence X API"""
        try:
            # Check if file can be downloaded
            if self.account_info.license_type == "trial" and self._is_sensitive_bucket(bucket):
                console.print("[red]This file is in a sensitive bucket which requires a paid account[/red]")
                console.print("[yellow]To download full content, you need to upgrade to a paid account[/yellow]")
                Prompt.ask("Press Enter to continue")
                return None
            
            # API request for file
            params = {
                "f": 0,  # Text format
                "sid": storageid,
                "bucket": bucket
            }
            headers = {"x-key": self.api_key}
            response = requests.get(
                f"{self.api_url}/file/read",
                params=params,
                headers=headers
            )
            
            if response.status_code == 200:
                # Save to file
                filepath = os.path.join(DOWNLOAD_DIR, filename)
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(response.text)
                return filepath
            else:
                console.print(f"[red]Error downloading file: {response.status_code}[/red]")
                return None
        except Exception as e:
            console.print(f"[red]Download error: {str(e)}[/red]")
            return None
    
    def interactive_search(self):
        """Interactive search with comprehensive options"""
        console.clear()
        console.rule("[bold blue]New Search[/bold blue]")
        console.print()
        
        # Get search term
        self.search_term = Prompt.ask("[bold]Search term[/bold]")
        
        # Get buckets
        console.print("\n[bold]Select buckets to search:[/bold]")
        bucket_options = [
            ("leaks.logs", "Leaks » Logs"),
            ("leaks.private.general", "Leaks » Private"),
            ("leaks.public.general", "Leaks » Public"),
            ("leaks.comb", "Leaks » COMB"),
            ("stealer.logs", "Stealer Logs"),
            ("pastes", "Pastes"),
            ("darknet.tor", "Darknet TOR"),
            ("darknet.i2p", "Darknet I2P"),
            ("web.public", "Web » Public"),
            ("web.public.de", "Web » Public DE"),
            ("web.public.kp", "Web » Public KP"),
            ("web.public.ua", "Web » Public UA"),
            ("web.public.com", "Web » Public COM"),
            ("web.gov.ru", "Web » GOV RU"),
            ("web.public.peer", "Web » Public PEER")
        ]
        
        # Display bucket selection
        for i, (_, name) in enumerate(bucket_options, 1):
            console.print(f"{i}. {name}")
        
        bucket_selection = Prompt.ask(
            "\n[bold]Enter bucket numbers to search (comma-separated, or 'a' for all)[/bold]",
            default="a"
        )
        
        selected_buckets = []
        if bucket_selection.lower() == 'a':
            selected_buckets = [bucket for bucket, _ in bucket_options]
        else:
            try:
                indices = [int(x.strip()) - 1 for x in bucket_selection.split(",")]
                for idx in indices:
                    if 0 <= idx < len(bucket_options):
                        selected_buckets.append(bucket_options[idx][0])
                    else:
                        console.print("[yellow]Invalid bucket selection.[/yellow]")
            except:
                console.print("[yellow]Invalid bucket selection. Searching all accessible buckets.[/yellow]")
                selected_buckets = [bucket for bucket, _ in bucket_options]
        
        # Set date range
        date_from = Prompt.ask("[bold]Date from (YYYY-MM-DD, optional)[/bold]", default="")
        date_to = Prompt.ask("[bold]Date to (YYYY-MM-DD, optional)[/bold]", default="")
        
        # Set sort order
        sort_options = {
            "1": 1,  # date (newest first)
            "2": 2,  # date (oldest first)
            "3": 3,  # xscore (highest first)
            "4": 4   # xscore (lowest first)
        }
        console.print("\n[bold]Sort order:[/bold]")
        for key, value in sort_options.items():
            console.print(f"{key}. {key}. {['date ascending', 'date descending', 'xscore ascending', 'xscore descending'][value-1]}")
        sort_choice = Prompt.ask("[bold]Select sort order[/bold]", choices=list(sort_options.keys()), default="1")
        sort = sort_options[sort_choice]
        
        # Set media type
        media_options = {
            "0": -1,  # All
            "1": 1,   # Paste Document
            "9": 9,   # HTML Copy of Website
            "15": 15, # PDF Document
            "22": 22, # Container Files
            "24": 24  # Text File
        }
        console.print("\n[bold]Media type:[/bold]")
        for key, value in media_options.items():
            console.print(f"{key}. {['All', 'Paste Document', 'HTML Copy of Website', 'PDF Document', 'Container Files', 'Text File'][int(key)]}")
        media_choice = Prompt.ask("[bold]Select media type[/bold]", choices=list(media_options.keys()), default="0")
        media = media_options[media_choice]
        
        # Set max results (up to 1000)
        max_results = Prompt.ask("[bold]Maximum results (1-1000)[/bold]", default="100", show_choices=False)
        
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
        
        # Prepare search request
        search_data = {
            "term": self.search_term,
            "buckets": selected_buckets or [],
            "lookuplevel": 0,
            "maxresults": max_results,
            "timeout": 0,
            "datefrom": date_from or "",
            "dateto": date_to or "",
            "sort": sort,
        }
        
        # Only include media if it's not -1 (All)
        if media != -1:
            search_data["media"] = media
        
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
                headers = {"x-key": self.api_key}
                response = requests.post(
                    f"{self.api_url}/intelligent/search",
                    json=search_data,
                    headers=headers
                )
                
                if response.status_code == 200:
                    search_id = response.json().get("id")
                    if not search_id:
                        console.print("[red]Error: No search ID returned from API.[/red]")
                        return
                    
                    # Poll for results
                    results = []
                    status = 0
                    while status != 2:  # 2 means search is complete
                        time.sleep(1)
                        progress.update(self.search_task, advance=5)
                        
                        result_response = requests.get(
                            f"{self.api_url}/intelligent/search/result?id={search_id}&limit=10000",
                            headers=headers
                        )
                        
                        if result_response.status_code == 200:
                            result_data = result_response.json()
                            results = result_data.get("records", [])
                            status = result_data.get("status", 0)
                        else:
                            console.print(f"[red]Error getting search results: {result_response.status_code}[/red]")
                            break
                    
                    # Save to history
                    search_id = self.save_search_history(
                        self.search_term,
                        len(results),
                        selected_buckets,
                        date_from,
                        date_to,
                        sort,
                        media
                    )
                    
                    # Save results
                    search_results = [SearchResult(result) for result in results]
                    self.save_search_results(search_id, search_results)
                    
                    # Display results
                    self.display_search_results(search_results)
                else:
                    # Try to get error message from response
                    error_msg = response.text
                    try:
                        error_json = response.json()
                        if "error" in error_json:
                            error_msg = error_json["error"]
                    except:
                        pass
                    console.print(f"[red]Search error: {response.status_code} - {error_msg}[/red]")
        
        except Exception as e:
            console.print(f"[red]Search failed: {str(e)}[/red]")
    
    def display_search_results(self, results):
        """Display search results with navigation options"""
        if not results:
            console.print("[yellow]No results found.[/yellow]")
            Prompt.ask("Press Enter to continue")
            return
        
        console.clear()
        console.rule(f"[bold blue]Search Results for: {self.search_term}[/bold blue]")
        console.print()
        
        # Display results table
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        table.add_column("No.", justify="right", width=4)
        table.add_column("Name", style="cyan", width=30)
        table.add_column("Bucket", width=20)
        table.add_column("Date", width=12)
        table.add_column("Size", width=10)
        table.add_column("X-Score", justify="right", width=8)
        table.add_column("Access", width=8)
        
        for i, result in enumerate(results, 1):
            # Format size
            size_str = self._format_size(result.size)
            
            # Format X-Score with color
            xscore_str = str(result.xscore)
            if result.xscore > 80:
                xscore_str = f"[green]{xscore_str}[/green]"
            elif result.xscore > 50:
                xscore_str = f"[yellow]{xscore_str}[/yellow]"
            else:
                xscore_str = f"[red]{xscore_str}[/red]"
            
            # Format access level
            access_str = "PRO" if result.is_pro_bucket() else "FREE"
            if result.is_redacted:
                access_str = f"[red]{access_str} (Preview)[/red]"
            
            table.add_row(
                str(i),
                result.name,
                result.get_bucket_type(),
                self._format_date(result.date),
                size_str,
                xscore_str,
                access_str
            )
        
        console.print(table)
        console.print()
        
        # Display bucket summary
        self.display_bucket_summary(results)
        console.print()
        
        # Navigation options
        console.print("[bold]Select result to view details, or choose an action:[/bold]")
        console.print("D. Document View (content)")
        console.print("T. Tree View (relationships)")
        console.print("M. Metadata View")
        console.print("S. Selectors View (extracted selectors)")
        console.print("A. Actions Menu")
        console.print("E. Export results")
        console.print("B. Back to main menu")
        
        choice = Prompt.ask(
            "[bold]Select result (number), view option (D/T/M/S/A/E), or press Enter to return[/bold]",
            default=""
        )
        
        if not choice:
            return
        elif choice.upper() == "D":
            self.current_view = "document"
            self.handle_result_selection(results)
        elif choice.upper() == "T":
            self.current_view = "tree"
            self.handle_result_selection(results)
        elif choice.upper() == "M":
            self.current_view = "metadata"
            self.handle_result_selection(results)
        elif choice.upper() == "S":
            self.current_view = "selectors"
            self.handle_result_selection(results)
        elif choice.upper() == "A":
            self.current_view = "actions"
            self.handle_result_selection(results)
        elif choice.upper() == "E":
            self.export_results(results)
        elif choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(results):
                self.display_result_details(results[idx])
            else:
                console.print("[yellow]Invalid selection.[/yellow]")
    
    def handle_result_selection(self, results=None):
        """Handle result selection based on current view mode"""
        if results is None:
            # Get results from current search history
            if not self.current_search_history_id:
                return
            
            results = self.get_search_results(self.current_search_history_id)
        
        if not results:
            return
        
        console.clear()
        console.rule(f"[bold blue]Results for: {self.search_term}[/bold blue]")
        console.print()
        
        # Display results table with current view indicator
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        table.add_column("No.", justify="right", width=4)
        table.add_column("Name", style="cyan", width=30)
        table.add_column("Bucket", width=20)
        table.add_column("Date", width=12)
        table.add_column("Size", width=10)
        table.add_column("X-Score", justify="right", width=8)
        table.add_column("Current View", width=15)
        
        for i, result in enumerate(results, 1):
            # Format size
            size_str = self._format_size(result.size)
            
            # Format X-Score with color
            xscore_str = str(result.xscore)
            if result.xscore > 80:
                xscore_str = f"[green]{xscore_str}[/green]"
            elif result.xscore > 50:
                xscore_str = f"[yellow]{xscore_str}[/yellow]"
            else:
                xscore_str = f"[red]{xscore_str}[/red]"
            
            # Current view indicator
            view_indicator = ""
            if self.current_view == "document":
                view_indicator = "Document View" if i == 1 else ""
            elif self.current_view == "tree":
                view_indicator = "Tree View" if i == 1 else ""
            elif self.current_view == "metadata":
                view_indicator = "Metadata View" if i == 1 else ""
            elif self.current_view == "selectors":
                view_indicator = "Selectors View" if i == 1 else ""
            elif self.current_view == "actions":
                view_indicator = "Actions Menu" if i == 1 else ""
            
            table.add_row(
                str(i),
                result.name,
                result.get_bucket_type(),
                self._format_date(result.date),
                size_str,
                xscore_str,
                view_indicator
            )
        
        console.print(table)
        console.print()
        
        # Display result details based on current view
        if results:
            self.display_result(results[0])
        
        # Navigation options
        console.print("[bold]Navigation:[/bold]")
        console.print("D. Document View (content)")
        console.print("T. Tree View (relationships)")
        console.print("M. Metadata View")
        console.print("S. Selectors View (extracted selectors)")
        console.print("A. Actions Menu")
        console.print("B. Back to search results")
        
        choice = Prompt.ask("[bold]Select result (number), view option (D/T/M/S/A), or press Enter to return[/bold]", default="")
        
        if not choice:
            return
        elif choice.upper() == "D":
            self.current_view = "document"
            self.handle_result_selection(results)
        elif choice.upper() == "T":
            self.current_view = "tree"
            self.handle_result_selection(results)
        elif choice.upper() == "M":
            self.current_view = "metadata"
            self.handle_result_selection(results)
        elif choice.upper() == "S":
            self.current_view = "selectors"
            self.handle_result_selection(results)
        elif choice.upper() == "A":
            self.current_view = "actions"
            self.handle_result_selection(results)
        elif choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(results):
                self.current_view = "document"  # Reset to document view for new selection
                self.display_result(results[idx])
            else:
                console.print("[yellow]Invalid selection.[/yellow]")
    
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
    
    def display_bucket_summary(self, results):
        """Display summary of buckets in search results"""
        bucket_counts = {}
        pro_buckets = set()
        sensitive_buckets = set()
        
        for result in results:
            bucket_type = result.get_bucket_type()
            bucket_counts[bucket_type] = bucket_counts.get(bucket_type, 0) + 1
            
            if result.is_pro_bucket():
                pro_buckets.add(bucket_type)
            if result.is_sensitive_bucket():
                sensitive_buckets.add(bucket_type)
        
        console.print("[bold]Bucket Summary:[/bold]")
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold green")
        table.add_column("Bucket", style="cyan", width=20)
        table.add_column("Count", justify="right", width=10)
        table.add_column("Access", width=10)
        table.add_column("Status", width=15)
        
        for bucket_type, count in bucket_counts.items():
            access = "PRO" if bucket_type in pro_buckets else "FREE"
            status = "Preview" if bucket_type in sensitive_buckets else "Full"
            table.add_row(bucket_type, str(count), access, status)
        
        console.print(table)
    
    def display_document_view(self, result):
        """Display document view (content) with comprehensive bucket support"""
        console.rule(f"[bold blue]Document View: {result.name}[/bold blue]")
        console.print()
        
        # Check if content is redacted
        if result.is_redacted and self.account_info.license_type == "trial":
            console.print("[red]This file is in a sensitive bucket which is restricted to preview-only.[/red]")
            console.print("[yellow]To download full content, you need to upgrade to a paid account.[/yellow]")
            console.print("[blue]Visit https://intelx.io/account?tab=developer to upgrade.[/blue]")
        
        # Get or fetch preview
        preview = self.get_preview_from_db(result.systemid)
        if not preview:
            preview = self.preview_manager.get_preview(result.systemid, result.bucket, 50)
            if preview and not preview.startswith("❌"):
                self.save_preview_to_db(result.systemid, preview)
        
        # Display preview
        if preview and not preview.startswith("❌"):
            # Try to display as a file tree if it looks like one
            if self._is_file_tree(preview):
                self.display_file_tree(preview, result)
            else:
                console.print("[bold]File Preview:[/bold]")
                console.print(Syntax(preview, "text", theme="monokai", line_numbers=True))
        else:
            console.print("[yellow]No preview available.[/yellow]")
        
        # Show navigation options
        console.print("[bold]Navigation:[/bold]")
        console.print("T. Switch to Tree View")
        console.print("M. Switch to Metadata View")
        console.print("S. Switch to Selectors View")
        console.print("A. Switch to Actions Menu")
        console.print("B. Back to search results")
        
        choice = Prompt.ask("[bold]Navigation option[/bold]", choices=["T", "M", "S", "A", "B"], default="B")
        
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
    
    def _is_file_tree(self, content):
        """Check if content looks like a file tree structure"""
        # Check for common file tree patterns
        patterns = [
            r'\s*├──',  # Tree branch
            r'\s*└──',  # Tree end
            r'\s*│',     # Tree connector
            r'\.rar$',   # Archive extension
            r'\.zip$'    # Archive extension
        ]
        
        for pattern in patterns:
            if re.search(pattern, content):
                return True
        return False
    
    def display_file_tree(self, content, result):
        """Display file tree structure with enhanced visualization"""
        console.print("[bold]File Structure:[/bold]")
        
        # Parse and display the file tree
        lines = content.split('\n')
        tree = Tree(f"[bold]{result.name}[/bold]", guide_style="blue")
        
        # Stack to keep track of tree levels
        stack = [tree]
        
        for line in lines:
            if not line.strip():
                continue
                
            # Count leading spaces to determine level
            indent = len(line) - len(line.lstrip('│ ├──└'))
            level = indent // 4  # Assuming 4 spaces per level
            
            # Adjust stack to current level
            while len(stack) > level + 1:
                stack.pop()
                
            # Clean the line for display
            display_line = re.sub(r'^[\s│├└─]+', '', line).strip()
            
            # Add to tree
            if display_line:
                new_node = stack[-1].add(f"[cyan]{display_line}[/cyan]")
                stack.append(new_node)
        
        console.print(tree)
        console.print()
        
        # Show file details
        console.print("[bold]File Details:[/bold]")
        details_table = Table(box=box.SIMPLE, show_header=False)
        details_table.add_column("Property", style="cyan", width=15)
        details_table.add_column("Value", width=30)
        
        details_table.add_row("Total Files", str(len([l for l in lines if '.' in l])))
        details_table.add_row("Archive Type", result.name.split('.')[-1].upper())
        details_table.add_row("Main Directory", result.name.split('.')[0])
        
        console.print(details_table)
    
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
        console.print("[bold]Navigation:[/bold]")
        console.print("D. Switch to Document View")
        console.print("M. Switch to Metadata View")
        console.print("S. Switch to Selectors View")
        console.print("A. Switch to Actions Menu")
        console.print("B. Back to search results")
        
        choice = Prompt.ask("[bold]Navigation option[/bold]", choices=["D", "M", "S", "A", "B"], default="B")
        
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
        metadata_table.add_column("Value", width=40)
        
        # Basic information
        metadata_table.add_row("Name", result.name)
        metadata_table.add_row("System ID", result.systemid)
        metadata_table.add_row("Storage ID", result.storageid)
        metadata_table.add_row("Bucket", f"{result.bucket} [{result.get_bucket_type()}]")
        
        # Enhanced bucket information
        bucket_access = "PRO" if result.is_pro_bucket() else "FREE"
        preview_status = "Preview" if result.is_sensitive_bucket() else "Full Access"
        metadata_table.add_row("Access Level", f"{bucket_access} - {preview_status}")
        
        # Date information with better formatting
        metadata_table.add_row("Creation Date", self._format_date(result.date))
        metadata_table.add_row("Added Date", self._format_date(result.added))
        metadata_table.add_row("Modified Date", self._format_date(result.modified))
        
        # Size with proper units
        metadata_table.add_row("Size", self._format_size(result.size))
        
        # X-Score with visual indicator
        xscore_str = f"{result.xscore} ★"
        if result.xscore > 80:
            xscore_str = f"[green]{xscore_str}[/green]"
        elif result.xscore > 50:
            xscore_str = f"[yellow]{xscore_str}[/yellow]"
        else:
            xscore_str = f"[red]{xscore_str}[/red]"
        metadata_table.add_row("X-Score", xscore_str)
        
        # Simhash with visual representation
        metadata_table.add_row("Simhash", f"{result.simhash} ({result.simhash_human})")
        
        # Access level description
        metadata_table.add_row("Access Description", result.get_access_level_description())
        
        # Status with color coding
        status_str = "Available" if result.instore else "Deleted"
        status_str = f"[green]{status_str}[/green]" if result.instore else f"[red]{status_str}[/red]"
        metadata_table.add_row("Status", status_str)
        
        # Add bucket-specific information
        if "leaks" in result.bucket.lower() or "stealer" in result.bucket.lower():
            metadata_table.add_row("Leak Type", self._get_leak_type(result.bucket))
            metadata_table.add_row("Data Sensitivity", self._get_data_sensitivity(result.bucket))
        
        console.print(metadata_table)
        
        # Show navigation options
        console.print("[bold]Navigation:[/bold]")
        console.print("D. Switch to Document View")
        console.print("T. Switch to Tree View")
        console.print("S. Switch to Selectors View")
        console.print("A. Switch to Actions Menu")
        console.print("B. Back to search results")
        
        choice = Prompt.ask("[bold]Navigation option[/bold]", choices=["D", "T", "S", "A", "B"], default="B")
        
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
                extracted = self.selector_extractor.extract_selectors(preview, result.bucket)
                self.save_extracted_selectors(result.systemid, extracted, result.bucket)
                selectors = self.get_extracted_selectors(result.systemid)
        
        if not selectors:
            console.print("[yellow]No selectors found in this document.[/yellow]")
            # Show navigation options
            console.print("[bold]Navigation:[/bold]")
            console.print("D. Switch to Document View")
            console.print("T. Switch to Tree View")
            console.print("M. Switch to Metadata View")
            console.print("A. Switch to Actions Menu")
            console.print("B. Back to search results")
            
            choice = Prompt.ask("[bold]Navigation option[/bold]", choices=["D", "T", "M", "A", "B"], default="B")
            
            if choice.upper() == "D":
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
            return
        
        # Count selectors by type
        selector_counts = {}
        for selector_type, _, _, _ in selectors:
            selector_counts[selector_type] = selector_counts.get(selector_type, 0) + 1
        
        # Display summary
        total = len(selectors)
        summary = f"Showing {total} out of {total} Total ("
        summary += ", ".join([f"{count} {stype}" for stype, count in selector_counts.items()])
        summary += ")."
        console.print(f"[bold cyan]{summary}[/bold]\n")
        
        # Create enhanced selectors table
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        table.add_column("Selector", style="cyan", width=30)
        table.add_column("Type", width=15)
        table.add_column("Bucket", width=15)
        table.add_column("Access", width=10)
        
        for selector_type, selector_value, bucket_type, access_level in selectors:
            table.add_row(selector_value, selector_type, bucket_type, access_level)
        
        console.print(table)
        
        # Show navigation options
        console.print("[bold]Navigation:[/bold]")
        console.print("D. Switch to Document View")
        console.print("T. Switch to Tree View")
        console.print("M. Switch to Metadata View")
        console.print("A. Switch to Actions Menu")
        console.print("B. Back to search results")
        
        choice = Prompt.ask("[bold]Navigation option[/bold]", choices=["D", "T", "M", "A", "B"], default="B")
        
        if choice.upper() == "D":
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
        
        # Preview action
        preview_desc = "View content preview (redacted for trial accounts)"
        if result.is_redacted and self.account_info.license_type == "trial":
            preview_desc = "[red]Preview only - full content requires paid account[/red]"
        actions_table.add_row("1. Preview", preview_desc)
        
        # Download action
        if result.can_download():
            actions_table.add_row("2. Download", "Download full content")
        else:
            actions_table.add_row("2. Download", "[yellow]Not available with trial account[/yellow]")
        
        # Copy System ID
        actions_table.add_row("3. Copy System ID", "Copy System ID to clipboard")
        
        # View on Website
        actions_table.add_row("4. View on Website", "Open in Intelligence X website")
        
        # Extract Selectors
        actions_table.add_row("5. Extract Selectors", "Extract and view selectors from content")
        
        # Search Related
        actions_table.add_row("6. Search Related", "Search for related items")
        
        # Force Refresh
        actions_table.add_row("7. Force Refresh", "Refresh preview with latest data")
        
        console.print(actions_table)
        
        # Action selection
        choice = Prompt.ask("[bold]Select action (1-7)[/bold]", choices=["1", "2", "3", "4", "5", "6", "7"], default="1")
        
        if choice == "1":
            self.current_view = "document"
            self.display_document_view(result)
        elif choice == "2" and result.can_download():
            # Get filename
            filename = Prompt.ask("[bold]Save as filename[/bold]", default=os.path.basename(result.name) if result.name else f"{result.systemid}.bin")
            
            # Download file
            download_path = self.download_file(result.systemid, result.bucket, result.storageid, filename)
            if download_path:
                console.print(f"[green]File downloaded successfully to: {download_path}[/green]")
            Prompt.ask("Press Enter to continue")
            self.display_actions_view(result)
        elif choice == "3":
            # Copy System ID to clipboard
            pyperclip.copy(result.systemid)
            console.print("[green]System ID copied to clipboard![/green]")
            Prompt.ask("Press Enter to continue")
            self.display_actions_view(result)
        elif choice == "4":
            # Open in browser
            webbrowser.open(f"https://intelx.io/?did={result.systemid}")
            console.print("[blue]Opening in browser...[/blue]")
            Prompt.ask("Press Enter to continue")
            self.display_actions_view(result)
        elif choice == "5":
            self.current_view = "selectors"
            self.display_selectors_view(result)
        elif choice == "6":
            # Search related items
            console.print("[yellow]Searching for related items...[/yellow]")
            # In a real implementation, this would search for related items
            time.sleep(1)
            console.print("[green]Related items search not implemented in this demo.[/green]")
            Prompt.ask("Press Enter to continue")
            self.display_actions_view(result)
        elif choice == "7":
            # Force refresh preview
            console.print("[yellow]Refreshing preview...[/yellow]")
            preview = self.preview_manager.get_preview(result.systemid, result.bucket, 50)
            if preview and not preview.startswith("❌"):
                self.save_preview_to_db(result.systemid, preview)
                # Also refresh selectors
                extracted = self.selector_extractor.extract_selectors(preview, result.bucket)
                self.save_extracted_selectors(result.systemid, extracted, result.bucket)
                console.print("[green]Preview refreshed successfully![/green]")
            else:
                console.print("[red]Failed to refresh preview.[/red]")
            Prompt.ask("Press Enter to continue")
            self.display_actions_view(result)
    
    def display_result_details(self, result):
        """Display detailed information about a single result"""
        console.clear()
        console.rule(f"[bold blue]Result Details: {result.name}[/bold blue]")
        console.print()
        
        # Display metadata
        metadata_table = Table(box=box.SIMPLE, show_header=False)
        metadata_table.add_column("Field", style="cyan", width=20)
        metadata_table.add_column("Value", width=40)
        
        metadata_table.add_row("Name", result.name)
        metadata_table.add_row("System ID", result.systemid)
        metadata_table.add_row("Storage ID", result.storageid)
        metadata_table.add_row("Bucket", f"{result.bucket} [{result.get_bucket_type()}]")
        metadata_table.add_row("Media Type", result.get_media_type())
        metadata_table.add_row("Date", self._format_date(result.date))
        metadata_table.add_row("Size", self._format_size(result.size))
        metadata_table.add_row("X-Score", str(result.xscore))
        metadata_table.add_row("Simhash", f"{result.simhash} ({result.simhash_human})")
        metadata_table.add_row("Access Level", result.get_access_level_description())
        metadata_table.add_row("Status", "Available" if result.instore else "Deleted")
        
        console.print(metadata_table)
        console.print()
        
        # Display preview
        console.print("[bold]File Preview:[/bold]")
        preview = self.preview_manager.get_preview(result.systemid, result.bucket, 10)
        if not preview.startswith("❌"):
            console.print(Syntax(preview, "text", theme="monokai", line_numbers=True))
        else:
            console.print("[yellow]No preview available.[/yellow]")
        
        # Display selectors
        console.print()
        console.print("[bold]Extracted Selectors:[/bold]")
        selectors = self.selector_extractor.extract_selectors(preview, result.bucket)
        if selectors:
            selectors_table = Table(box=box.SIMPLE, show_header=True, header_style="bold green")
            selectors_table.add_column("Type", style="cyan")
            selectors_table.add_column("Value")
            
            for selector_type, selector_value, _ in selectors:
                selectors_table.add_row(selector_type, selector_value)
            
            console.print(selectors_table)
        else:
            console.print("[yellow]No selectors found.[/yellow]")
        
        console.print()
        console.print("[bold]Navigation:[/bold]")
        console.print("D. Document View (content)")
        console.print("T. Tree View (relationships)")
        console.print("M. Metadata View")
        console.print("S. Selectors View (extracted selectors)")
        console.print("A. Actions Menu")
        console.print("B. Back to search results")
        
        choice = Prompt.ask("[bold]Select view option (D/T/M/S/A), or press Enter to return[/bold]", default="B")
        
        if choice.upper() == "D":
            self.current_view = "document"
            self.display_document_view(result)
        elif choice.upper() == "T":
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
    
    def display_recent_searches(self):
        """Display recent searches from history"""
        history = self.get_search_history()
        
        if not history:
            console.print("[yellow]No recent searches found.[/yellow]")
            Prompt.ask("Press Enter to continue")
            return
        
        console.clear()
        console.rule("[bold blue]Recent Searches[/bold blue]")
        console.print()
        
        # Display history table
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        table.add_column("No.", justify="right", width=4)
        table.add_column("Search Term", style="cyan", width=30)
        table.add_column("Date", width=20)
        table.add_column("Results", justify="right", width=8)
        
        for i, search in enumerate(history, 1):
            # Parse date
            try:
                dt = datetime.fromisoformat(search[2])  # timestamp is at index 2
                date_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                date_str = search[2]
            
            table.add_row(
                str(i),
                search[1],  # term is at index 1
                date_str,
                str(search[3])  # result_count is at index 3
            )
        
        console.print(table)
        console.print()
        
        # Navigation options
        console.print("[bold]Select a search to view results, or choose an action:[/bold]")
        console.print("E. Export search history")
        console.print("C. Clear search history")
        console.print("B. Back to main menu")
        
        choice = Prompt.ask(
            "[bold]Select search (number), action (E/C), or press Enter to return[/bold]",
            default=""
        )
        
        if not choice:
            return
        elif choice.upper() == "E":
            self.export_search_history(history)
        elif choice.upper() == "C":
            self.clear_search_history()
            console.print("[green]Search history cleared.[/green]")
            Prompt.ask("Press Enter to continue")
            self.display_recent_searches()
        elif choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(history):
                search_id = history[idx][0]  # ID is at index 0
                results = self.get_search_results(search_id)
                if results:
                    self.current_search_history_id = search_id
                    self.search_term = history[idx][1]  # term is at index 1
                    self.display_search_results(results)
                else:
                    console.print("[yellow]No results found for this search.[/yellow]")
                    Prompt.ask("Press Enter to continue")
            else:
                console.print("[yellow]Invalid selection.[/yellow]")
    
    def export_search_history(self, history):
        """Export search history to file"""
        console.clear()
        console.rule("[bold blue]Export Search History[/bold blue]")
        console.print()
        
        # Display export formats
        console.print("[bold]Select export format:[/bold]")
        console.print("1. Markdown")
        console.print("2. JSON")
        console.print("3. CSV")
        
        format_choice = Prompt.ask("[bold]Select format[/bold]", choices=["1", "2", "3"], default="1")
        
        formats = {
            "1": "markdown",
            "2": "json",
            "3": "csv"
        }
        
        format_type = formats.get(format_choice, "markdown")
        
        # Get filename
        filename = Prompt.ask("[bold]Enter filename (or press Enter for default)[/bold]", default="")
        
        # Export
        console.print(f"[yellow]Exporting to {format_type}...[/yellow]")
        try:
            # For simplicity, we'll just create a basic export here
            console.print("[green]Export functionality would be implemented here.[/green]")
        except Exception as e:
            console.print(f"[red]Export error: {str(e)}[/red]")
        
        Prompt.ask("Press Enter to continue")
        self.display_recent_searches()
    
    def clear_search_history(self):
        """Clear search history from database"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Delete all search history
        cursor.execute("DELETE FROM search_history")
        cursor.execute("DELETE FROM search_results")
        
        conn.commit()
        conn.close()
    
    def export_results(self, results):
        """Export search results to file"""
        console.clear()
        console.rule("[bold blue]Export Results[/bold blue]")
        console.print()
        
        # Display export formats
        console.print("[bold]Select export format:[/bold]")
        console.print("1. Markdown")
        console.print("2. JSON")
        console.print("3. CSV")
        
        format_choice = Prompt.ask("[bold]Select format[/bold]", choices=["1", "2", "3"], default="1")
        
        formats = {
            "1": "markdown",
            "2": "json",
            "3": "csv"
        }
        
        format_type = formats.get(format_choice, "markdown")
        
        # Get filename
        filename = Prompt.ask("[bold]Enter filename (or press Enter for default)[/bold]", default="")
        
        # Export
        console.print(f"[yellow]Exporting to {format_type}...[/yellow]")
        try:
            # For simplicity, we'll just create a basic export here
            console.print("[green]Export functionality would be implemented here.[/green]")
        except Exception as e:
            console.print(f"[red]Export error: {str(e)}[/red]")
        
        Prompt.ask("Press Enter to continue")
        self.display_search_results(results)
    
    def main_menu(self):
        """Display main menu options"""
        while True:
            console.clear()
            
            # Welcome banner with proper formatting
            welcome_text = (
                "[bold green]Intelligence X CLI - Ultimate Edition v7.2[/bold green]\n\n"
                "[bold]The Most Advanced CLI Tool for Intelligence X API with Complete Bucket Support[/bold]\n"
                "[italic]Version 7.2 - Fixed API request parameters and enhanced error handling[/italic]"
            )
            console.rule(welcome_text)
            console.print()
            
            # Display account info
            if self.account_info:
                account_info = (
                    f"Account Type: [bold]{self.account_info.license_type.capitalize()}[/bold] | "
                    f"Buckets: [bold]{len(self.account_info.buckets)}[/bold] | "
                    f"Expiration: [bold]{self.account_info.license_expiration or 'N/A'}[/bold]"
                )
                console.print(Panel(account_info, border_style="blue"))
                console.print()
            
            # Display main menu options
            menu_panel = Panel(
                "1. New search\n"
                "2. View recent searches\n"
                "3. Account information\n"
                "4. Help & documentation\n"
                "5. Exit",
                title="Main Menu",
                border_style="blue"
            )
            console.print(menu_panel)
            
            choice = Prompt.ask(
                "[bold]Select option[/bold]",
                choices=["1", "2", "3", "4", "5"],
                default="1"
            )
            
            if choice == "1":
                self.interactive_search()
            elif choice == "2":
                self.display_recent_searches()
            elif choice == "3":
                self.display_account_info()
            elif choice == "4":
                self.display_help()
            elif choice == "5":
                console.print("[blue]Thank you for using Intelligence X CLI![/blue]")
                break
    
    def display_help(self):
        """Display help and documentation"""
        console.clear()
        console.rule("[bold blue]Help & Documentation[/bold blue]")
        console.print()
        
        # Help content
        help_text = (
            "[bold]Intelligence X CLI - Ultimate Edition v7.2[/bold]\n\n"
            
            "[bold]Overview:[/bold]\n"
            "This tool provides a comprehensive interface to the Intelligence X API, allowing you to search\n"
            "through various data sources including leaks, pastes, darknet, and public web content.\n\n"
            
            "[bold]Search Types:[/bold]\n"
            "• Leaks » Logs: Contains credential dumps and data breaches (PRO)\n"
            "• Leaks » COMB: Combined data breaches (PRO)\n"
            "• Stealer Logs: Malware exfiltrated data (PRO)\n"
            "• Pastes: Public paste sites like Pastebin (FREE)\n"
            "• Darknet: TOR and I2P network content (PRO)\n"
            "• Web » Public: Publicly accessible websites (FREE)\n\n"
            
            "[bold]View Modes:[/bold]\n"
            "• Document View: Shows file content or preview\n"
            "• Tree View: Shows relationships between items\n"
            "• Metadata View: Shows detailed metadata about the item\n"
            "• Selectors View: Shows extracted selectors (emails, domains, etc.)\n"
            "• Actions Menu: Provides available actions for the item\n\n"
            
            "[bold]Trial Account Limitations:[/bold]\n"
            "• Preview only for sensitive data (shown as ████ characters)\n"
            "• Limited to 100 results per search\n"
            "• Cannot download full content from restricted buckets\n"
            "• Limited search credits per day\n\n"
            "To access full features, upgrade to a paid plan at: [blue]https://intelx.io/account?tab=developer[/blue]"
        )
        
        console.print(Panel(help_text, border_style="green"))
        console.print()
        
        # Navigation options
        console.print("[bold]Navigation:[/bold]")
        console.print("1. View feature comparison")
        console.print("2. View API documentation")
        console.print("3. Back to main menu")
        
        choice = Prompt.ask("[bold]Select option[/bold]", choices=["1", "2", "3"], default="3")
        
        if choice == "1":
            self.display_feature_comparison()
        elif choice == "2":
            webbrowser.open("https://intelx.io/documentation")
            console.print("[blue]Opening API documentation in browser...[/blue]")
            Prompt.ask("Press Enter to continue")
            self.display_help()
    
    def display_feature_comparison(self):
        """Display feature comparison between account types"""
        console.clear()
        console.rule("[bold blue]Feature Comparison[/bold blue]")
        console.print()
        
        # Create feature comparison table
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        table.add_column("Feature", style="cyan", width=25)
        table.add_column("Trial", justify="center", width=10)
        table.add_column("Basic", justify="center", width=10)
        table.add_column("Professional", justify="center", width=15)
        table.add_column("Enterprise", justify="center", width=15)
        
        # Add feature rows
        features = [
            ("Search Results", "100", "500", "1,000", "Unlimited"),
            ("Preview Credits", "3,000", "5,000", "25,000", "Unlimited"),
            ("Full Download", "✗", "✓", "✓", "✓"),
            ("Phonebook Search", "✗", "✓", "✓", "✓"),
            ("Data Leaks Access", "✗", "✓", "✓", "✓"),
            ("Advanced Filters", "✗", "✓", "✓", "✓"),
            ("API Rate Limit", "1 req/sec", "5 req/sec", "10 req/sec", "Custom"),
            ("Support", "Community", "Email", "Priority Email", "24/7 Dedicated")
        ]
        
        for feature, trial, basic, professional, enterprise in features:
            table.add_row(feature, trial, basic, professional, enterprise)
        
        console.print(table)
        console.print()
        
        # Additional information
        console.print("[bold]Note:[/bold] Paid accounts can view full content in sensitive buckets like Leaks » Logs,")
        console.print("which show as redacted (████) in trial accounts.")
        console.print()
        console.print("For more information visit: [blue]https://intelx.io/pricing[/blue]")
        
        Prompt.ask("Press Enter to continue")
        self.display_help()

def main():
    """Main function to run the CLI"""
    # Create CLI instance
    cli = IntelligenceXCLI(API_KEY, API_URL)
    
    # Display main menu
    cli.main_menu()

if __name__ == "__main__":
    main()