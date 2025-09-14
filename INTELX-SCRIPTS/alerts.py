"""
Alert System for Intelligence X CLI
Monitors search results and triggers notifications based on configured rules
"""

import json
import os
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
import threading
import sqlite3
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class AlertSystem:
    """Advanced alert system for monitoring search results"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.rules = []
        self.active_monitors = {}
        self.load_rules()
        self._init_database()
    
    def _init_database(self):
        """Initialize alert system database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create alerts table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_id INTEGER NOT NULL,
            alert_type TEXT NOT NULL,
            message TEXT NOT NULL,
            data TEXT,
            status TEXT DEFAULT 'new'
        )
        ''')
        
        # Create rules table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            conditions TEXT NOT NULL,
            actions TEXT NOT NULL,
            enabled BOOLEAN DEFAULT true,
            created_at TEXT NOT NULL,
            last_triggered TEXT
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def load_rules(self):
        """Load alert rules from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM alert_rules WHERE enabled = true')
        rules = cursor.fetchall()
        
        self.rules = []
        for rule in rules:
            self.rules.append({
                'id': rule[0],
                'name': rule[1],
                'description': rule[2],
                'conditions': json.loads(rule[3]),
                'actions': json.loads(rule[4]),
                'enabled': rule[5],
                'created_at': rule[6],
                'last_triggered': rule[7]
            })
        
        conn.close()
    
    def add_rule(self, rule: Dict[str, Any]) -> bool:
        """Add a new alert rule"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT INTO alert_rules (
                name, description, conditions, actions, enabled, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                rule['name'],
                rule.get('description', ''),
                json.dumps(rule['conditions']),
                json.dumps(rule['actions']),
                True,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            self.load_rules()
            return True
        except Exception as e:
            console.print(f"[red]Error adding rule: {str(e)}[/red]")
            return False
    
    def remove_rule(self, rule_id: int) -> bool:
        """Remove an alert rule"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM alert_rules WHERE id = ?', (rule_id,))
            
            conn.commit()
            conn.close()
            
            self.load_rules()
            return True
        except Exception as e:
            console.print(f"[red]Error removing rule: {str(e)}[/red]")
            return False
    
    def enable_rule(self, rule_id: int) -> bool:
        """Enable an alert rule"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('UPDATE alert_rules SET enabled = true WHERE id = ?', (rule_id,))
            
            conn.commit()
            conn.close()
            
            self.load_rules()
            return True
        except Exception as e:
            console.print(f"[red]Error enabling rule: {str(e)}[/red]")
            return False
    
    def disable_rule(self, rule_id: int) -> bool:
        """Disable an alert rule"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('UPDATE alert_rules SET enabled = false WHERE id = ?', (rule_id,))
            
            conn.commit()
            conn.close()
            
            self.load_rules()
            return True
        except Exception as e:
            console.print(f"[red]Error disabling rule: {str(e)}[/red]")
            return False
    
    def check_conditions(self, result: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
        """Check if result matches alert conditions"""
        for condition_type, condition_value in conditions.items():
            if condition_type == 'bucket':
                if result.get('bucket') != condition_value:
                    return False
            elif condition_type == 'keywords':
                if not any(kw.lower() in result.get('name', '').lower() for kw in condition_value):
                    return False
            elif condition_type == 'size_min':
                if result.get('size', 0) < condition_value:
                    return False
            elif condition_type == 'size_max':
                if result.get('size', 0) > condition_value:
                    return False
            elif condition_type == 'date_after':
                if result.get('date', '') < condition_value:
                    return False
            elif condition_type == 'date_before':
                if result.get('date', '') > condition_value:
                    return False
            elif condition_type == 'media_type':
                if result.get('media') != condition_value:
                    return False
        return True
    
    def process_result(self, result: Dict[str, Any]):
        """Process a single result against all rules"""
        for rule in self.rules:
            if self.check_conditions(result, rule['conditions']):
                self.trigger_alert(rule, result)
    
    def trigger_alert(self, rule: Dict[str, Any], result: Dict[str, Any]):
        """Trigger alert actions when conditions are met"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            alert_data = {
                'result_id': result.get('systemid'),
                'result_name': result.get('name'),
                'bucket': result.get('bucket'),
                'date': result.get('date')
            }
            
            cursor.execute('''
            INSERT INTO alerts (
                timestamp, rule_id, alert_type, message, data
            ) VALUES (?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                rule['id'],
                'match',
                f"Match found for rule: {rule['name']}",
                json.dumps(alert_data)
            ))
            
            # Update rule's last triggered time
            cursor.execute('''
            UPDATE alert_rules 
            SET last_triggered = ? 
            WHERE id = ?
            ''', (datetime.now().isoformat(), rule['id']))
            
            conn.commit()
            conn.close()
            
            # Execute alert actions
            self.execute_actions(rule['actions'], alert_data)
            
        except Exception as e:
            console.print(f"[red]Error triggering alert: {str(e)}[/red]")
    
    def execute_actions(self, actions: Dict[str, Any], alert_data: Dict[str, Any]):
        """Execute configured alert actions"""
        for action_type, action_config in actions.items():
            if action_type == 'console':
                self._action_console(action_config, alert_data)
            elif action_type == 'file':
                self._action_file(action_config, alert_data)
            elif action_type == 'webhook':
                self._action_webhook(action_config, alert_data)
    
    def _action_console(self, config: Dict[str, Any], alert_data: Dict[str, Any]):
        """Display alert in console"""
        message = config.get('message', 'Alert triggered: {result_name}').format(**alert_data)
        panel = Panel(
            message,
            title="[bold red]Alert![/bold red]",
            border_style="red"
        )
        console.print(panel)
    
    def _action_file(self, config: Dict[str, Any], alert_data: Dict[str, Any]):
        """Write alert to file"""
        filepath = config.get('path', 'alerts.log')
        message = config.get('format', '{timestamp}: {message}').format(
            timestamp=datetime.now().isoformat(),
            **alert_data
        )
        
        try:
            with open(filepath, 'a') as f:
                f.write(message + '\n')
        except Exception as e:
            console.print(f"[red]Error writing to alert file: {str(e)}[/red]")
    
    def _action_webhook(self, config: Dict[str, Any], alert_data: Dict[str, Any]):
        """Send alert to webhook"""
        import requests
        
        url = config.get('url')
        if not url:
            return
            
        try:
            payload = {
                'timestamp': datetime.now().isoformat(),
                'alert_data': alert_data
            }
            
            headers = config.get('headers', {})
            
            response = requests.post(url, json=payload, headers=headers)
            response.raise_for_status()
        except Exception as e:
            console.print(f"[red]Error sending webhook: {str(e)}[/red]")
    
    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT * FROM alerts 
        ORDER BY timestamp DESC 
        LIMIT ?
        ''', (limit,))
        
        alerts = []
        for alert in cursor.fetchall():
            alerts.append({
                'id': alert[0],
                'timestamp': alert[1],
                'rule_id': alert[2],
                'type': alert[3],
                'message': alert[4],
                'data': json.loads(alert[5]) if alert[5] else None,
                'status': alert[6]
            })
        
        conn.close()
        return alerts
    
    def display_alerts(self):
        """Display recent alerts in a formatted table"""
        alerts = self.get_recent_alerts()
        
        if not alerts:
            console.print("[yellow]No recent alerts found.[/yellow]")
            return
        
        table = Table(title="Recent Alerts")
        table.add_column("ID", justify="right", style="cyan")
        table.add_column("Time", style="green")
        table.add_column("Rule", style="blue")
        table.add_column("Message", style="white")
        table.add_column("Status", style="yellow")
        
        for alert in alerts:
            timestamp = datetime.fromisoformat(alert['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
            table.add_row(
                str(alert['id']),
                timestamp,
                str(alert['rule_id']),
                alert['message'],
                alert['status']
            )
        
        console.print(table)
    
    def clear_old_alerts(self, days: int = 30):
        """Clear alerts older than specified days"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            DELETE FROM alerts 
            WHERE datetime(timestamp) < datetime('now', ?)
            ''', (f'-{days} days',))
            
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            
            console.print(f"[green]Cleared {deleted} old alerts.[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Error clearing old alerts: {str(e)}[/red]")
            return False
