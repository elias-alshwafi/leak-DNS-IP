#!/usr/bin/env python3
"""
Intelligence X CLI - أداة بحث احترافية لـ Intelligence X API
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime
import requests
from tabulate import tabulate
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich import box

# إعدادات عالمية
API_URL = "https://free.intelx.io/"
API_KEY = "24fcfc64-849f-4e15-b365-40419b7d6624"  # يمكن للمستخدم تغييره
DOWNLOAD_DIR = "intelx_downloads"
console = Console()

# فئة لتمثيل نتيجة البحث
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
        
    def can_preview(self):
        """التحقق مما إذا كان يمكن عرض المعاينة"""
        # في الحساب التجريبي، accesslevel = 4 يعني معاينة فقط
        return self.accesslevel == 4 or self.accesslevel == 0
        
    def can_download(self):
        """التحقق مما إذا كان يمكن تنزيل الملف"""
        # في الحساب التجريبي، لا يمكن تنزيل ملفات الفئات المخفية (مثل leaks.logs)
        return self.instore and self.accesslevel == 0
    
    def is_redacted(self):
        """التحقق مما إذا كانت البيانات مخفية جزئياً (مثل الحساب التجريبي)"""
        return self.accesslevel == 4

# فئة لتمثيل الحساب
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
        
    def get_bucket_access(self, bucket):
        """التحقق من صلاحيات الوصول إلى الـ bucket"""
        if bucket in self.buckets:
            return "Full"
        elif bucket in self.redacted:
            return "Preview"
        return "No Access"
    
    def get_remaining_credits(self, path):
        """الحصول على الائتمانات المتبقية لمسار معين"""
        if path in self.paths:
            return self.paths[path]["Credit"]
        return 0
    
    def get_max_credits(self, path):
        """الحصول على الحد الأقصى للائتمانات لمسار معين"""
        if path in self.paths:
            return self.paths[path]["CreditMax"]
        return 0

# فئة لواجهة سطر الأوامر
class IntelligenceXCLI:
    def __init__(self, api_key, api_url=API_URL):
        self.api_key = api_key
        self.api_url = api_url
        self.account_info = None
        self.search_results = []
        self.current_search_id = None
        self.search_term = ""
        self.selected_buckets = []
        
        # التحقق من تهيئة المجلد للتنزيلات
        os.makedirs(DOWNLOAD_DIR, exist_ok=True)
        
        # التحقق من صلاحية المفتاح
        if not self.validate_api_key():
            console.print("[red]خطأ: مفتاح API غير صالح أو لا يملك الصلاحيات المطلوبة.[/red]")
            sys.exit(1)
            
        # الحصول على معلومات الحساب
        self.get_account_info()
    
    def validate_api_key(self):
        """التحقق من صلاحية مفتاح API"""
        try:
            response = requests.get(
                f"{self.api_url}/authenticate/info",
                headers={"x-key": self.api_key}
            )
            return response.status_code == 200
        except Exception as e:
            console.print(f"[red]خطأ في الاتصال بالـ API: {str(e)}[/red]")
            return False
    
    def get_account_info(self):
        """الحصول على معلومات الحساب"""
        try:
            response = requests.get(
                f"{self.api_url}/authenticate/info",
                headers={"x-key": self.api_key}
            )
            if response.status_code == 200:
                # إضافة معلومات انتهاء الصلاحية من البيانات التي قدمها المستخدم
                account_data = response.json()
                account_data["license_expiration"] = "2025-08-31"
                self.account_info = AccountInfo(account_data)
                return True
            return False
        except Exception as e:
            console.print(f"[red]خطأ في الحصول على معلومات الحساب: {str(e)}[/red]")
            return False
    
    def search(self, term, buckets=None, max_results=10, sort=2):
        """البحث عن مصطلح معين"""
        # مسح النتائج السابقة
        self.search_results = []
        self.current_search_id = None
        self.search_term = term
        self.selected_buckets = buckets or []
        
        # إعداد الطلب
        search_data = {
            "term": term,
            "buckets": buckets or [],
            "lookuplevel": 0,
            "maxresults": max_results,
            "timeout": 0,
            "datefrom": "",
            "dateto": "",
            "sort": sort,
            "media": 0
        }
        
        try:
            # إرسال طلب البحث
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task("[cyan]جاري البحث...", total=None)
                
                response = requests.post(
                    f"{self.api_url}/intelligent/search",
                    headers={"x-key": self.api_key},
                    json=search_data
                )
                
                progress.update(task, completed=1)
            
            if response.status_code == 200:
                result = response.json()
                self.current_search_id = result.get("id")
                
                # انتظار حتى تكون النتائج جاهزة
                time.sleep(0.5)
                
                # جلب النتائج
                return self.get_search_results()
            else:
                self.handle_api_error(response)
                return False
                
        except Exception as e:
            console.print(f"[red]خطأ في عملية البحث: {str(e)}[/red]")
            return False
    
    def get_search_results(self):
        """جلب نتائج البحث"""
        if not self.current_search_id:
            return False
            
        try:
            response = requests.get(
                f"{self.api_url}/intelligent/search/result?id={self.current_search_id}&limit=100",
                headers={"x-key": self.api_key}
            )
            
            if response.status_code == 200:
                result = response.json()
                status = result.get("status", 2)
                
                if status == 0 or status == 1:  # نتائج موجودة أو نتائج انتهت
                    records = result.get("records", [])
                    for record in records:
                        self.search_results.append(SearchResult(record))
                    return True
                elif status == 3:  # لا توجد نتائج بعد ولكن جرب مرة أخرى
                    time.sleep(1)
                    return self.get_search_results()
                else:
                    console.print("[yellow]لم يتم العثور على نتائج لهذا البحث.[/yellow]")
                    return False
            else:
                self.handle_api_error(response)
                return False
                
        except Exception as e:
            console.print(f"[red]خطأ في جلب نتائج البحث: {str(e)}[/red]")
            return False
    
    def preview_file(self, system_id, bucket, lines=20):
        """عرض معاينة للملف"""
        try:
            response = requests.get(
                f"{self.api_url}/file/preview?sid={system_id}&b={bucket}&l={lines}",
                headers={"x-key": self.api_key}
            )
            
            if response.status_code == 200:
                return response.text
            else:
                self.handle_api_error(response)
                return None
                
        except Exception as e:
            console.print(f"[red]خطأ في عرض المعاينة: {str(e)}[/red]")
            return None
    
    def download_file(self, system_id, bucket, storage_id=None, filename=None):
        """تنزيل الملف"""
        try:
            # تحديد اسم الملف
            if not filename:
                # استخدام اسم الملف الأصلي من البيانات إن وجد
                for result in self.search_results:
                    if result.systemid == system_id:
                        if result.name:
                            filename = os.path.basename(result.name)
                            break
                if not filename:
                    filename = f"{system_id}.bin"
                
            # تحديد مسار التنزيل
            download_path = os.path.join(DOWNLOAD_DIR, filename)
            
            # إعداد الطلب
            params = {
                "type": 1,
                "systemid": system_id,
                "bucket": bucket
            }
            if storage_id:
                params["storageid"] = storage_id
                
            response = requests.get(
                f"{self.api_url}/file/read",
                headers={"x-key": self.api_key},
                params=params,
                stream=True
            )
            
            if response.status_code == 200:
                with open(download_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                return download_path
            elif response.status_code == 204:
                # لا يوجد محتوى (خاصة مع الحسابات التجريبية)
                console.print("[yellow]تحذير: هذا الملف غير متاح للتنزيل الكامل مع حسابك الحالي.[/yellow]")
                return None
            else:
                self.handle_api_error(response)
                return None
                
        except Exception as e:
            console.print(f"[red]خطأ في تنزيل الملف: {str(e)}[/red]")
            return None
    
    def handle_api_error(self, response):
        """معالجة أخطاء الـ API"""
        status_code = response.status_code
        try:
            error_data = response.json()
            error_msg = error_data.get("error", "خطأ غير معروف")
        except:
            error_msg = "خطأ غير معروف"
        
        if status_code == 400:
            console.print(f"[red]خطأ في الطلب: {error_msg}[/red]")
        elif status_code == 401:
            console.print(f"[red]خطأ في المصادقة: {error_msg}[/red]")
        elif status_code == 402:
            console.print(f"[yellow]الحساب: {error_msg}[/yellow]")
        elif status_code == 404:
            console.print(f"[yellow]لم يتم العثور على العنصر: {error_msg}[/yellow]")
        else:
            console.print(f"[red]خطأ في الـ API (الكود {status_code}): {error_msg}[/red]")
    
    def display_search_results(self):
        """عرض نتائج البحث في جدول"""
        if not self.search_results:
            console.print("[yellow]لم يتم العثور على نتائج للبحث.[/yellow]")
            return False
        
        # إنشاء جدول لعرض النتائج
        table = Table(title=f"نتائج البحث عن '{self.search_term}'", box=box.ROUNDED)
        table.add_column("رقم", justify="right", style="cyan", no_wrap=True)
        table.add_column("الاسم", style="magenta", max_width=40)
        table.add_column("التاريخ", style="green")
        table.add_column("الحجم", justify="right")
        table.add_column("الـ Bucket", style="blue")
        table.add_column("النوع", style="yellow")
        table.add_column("الوصول", justify="center")
        table.add_column("الإجراء", justify="center")
        
        for i, result in enumerate(self.search_results, 1):
            # تحديد نوع الوصول
            if result.can_download():
                access = "✓ كامل"
                access_color = "green"
            elif result.can_preview():
                access = "✎ معاينة"
                access_color = "yellow"
            else:
                access = "✗ غير متاح"
                access_color = "red"
            
            # تحديد الحجم
            size_str = f"{result.size} بايت"
            if result.size > 1024 * 1024:  # أكثر من ميغابايت
                size_str = f"{result.size / (1024 * 1024):.2f} ميغابايت"
            elif result.size > 1024:  # أكثر من كيلوبايت
                size_str = f"{result.size / 1024:.2f} كيلوبايت"
            
            # تحديد الإجراء المتاح
            action = ""
            if result.can_preview():
                action = "[blue]عرض المعاينة[/blue]"
            if result.can_download():
                if action:
                    action += " / "
                action += "[green]تنزيل[/green]"
            
            # إضافة صف للجدول
            table.add_row(
                str(i),
                result.name,
                result.date.split("T")[0],
                size_str,
                result.bucket_human,
                result.media_human,
                f"[{access_color}]{access}[/{access_color}]",
                action
            )
        
        console.print(table)
        return True
    
    def display_account_info(self):
        """عرض معلومات الحساب"""
        if not self.account_info:
            console.print("[red]لم يتم تحميل معلومات الحساب.[/red]")
            return
        
        # عرض معلومات الحساب الأساسية
        account_panel = Panel.fit(
            f"[bold]الحساب: تجريبي (Trial)[/bold]\n"
            f"[bold]نهاية الصلاحية:[/bold] {self.account_info.license_expiration}\n"
            f"[bold]البحث النشط:[/bold] {self.account_info.searchesactive}/{self.account_info.maxconcurrentsearches}",
            title="معلومات الحساب",
            border_style="blue"
        )
        console.print(account_panel)
        
        # عرض صلاحيات الـ buckets
        console.print("\n[bold]صلاحيات الـ Buckets:[/bold]")
        
        # إنشاء جدول لعرض الـ buckets
        bucket_table = Table(box=box.SIMPLE)
        bucket_table.add_column("الـ Bucket", style="cyan")
        bucket_table.add_column("الوصول", justify="center")
        bucket_table.add_column("التفاصيل", justify="left")
        
        # إضافة الـ buckets المتاحة بالكامل
        for i in range(len(self.account_info.buckets)):
            bucket = self.account_info.bucketsh[i]
            bucket_table.add_row(
                bucket,
                "[green]كامل[/green]",
                "الوصول الكامل للمحتوى"
            )
        
        # إضافة الـ buckets المخفية (معاينة فقط)
        for i in range(len(self.account_info.redacted)):
            bucket = self.account_info.redactedh[i]
            bucket_table.add_row(
                bucket,
                "[yellow]معاينة فقط[/yellow]",
                "المحتوى مخفي جزئياً (يظهر كرموز █████)"
            )
        
        console.print(bucket_table)
        
        # عرض الائتمانات
        console.print("\n[bold]الائتمانات المتبقية:[/bold]")
        credits_table = Table(box=box.SIMPLE)
        credits_table.add_column("الوظيفة", style="cyan")
        credits_table.add_column("المتبقية", justify="right")
        credits_table.add_column("الحد الأقصى", justify="right")
        credits_table.add_column("التفاصيل", justify="left")
        
        # وظائف البحث
        search_credits = self.account_info.get_remaining_credits("/intelligent/search")
        search_max = self.account_info.get_max_credits("/intelligent/search")
        credits_table.add_row(
            "/intelligent/search",
            str(search_credits),
            str(search_max),
            "عدد عمليات البحث المتبقية"
        )
        
        # وظائف المعاينة
        preview_credits = self.account_info.get_remaining_credits("/file/preview")
        preview_max = self.account_info.get_max_credits("/file/preview")
        credits_table.add_row(
            "/file/preview",
            f"[yellow]{preview_credits}[/yellow]",
            str(preview_max),
            "عرض المعاينة (للحصول على رموز █████)"
        )
        
        # وظائف التنزيل
        read_credits = self.account_info.get_remaining_credits("/file/read")
        read_max = self.account_info.get_max_credits("/file/read")
        credits_table.add_row(
            "/file/read",
            f"[red]{read_credits}[/red]",
            str(read_max),
            "تنزيل الملفات الكاملة (غير متاح لفئات مخفية)"
        )
        
        console.print(credits_table)
        
        # عرض تحذير إذا كانت الائتمانات منخفضة
        if preview_credits < 100 or read_credits < 10:
            console.print("\n[yellow]تحذير: الائتمانات المتبقية منخفضة. قد تحتاج إلى الانتظار حتى إعادة التعيين.[/yellow]")
    
    def interactive_search(self):
        """واجهة بحث تفاعلية"""
        console.clear()
        console.print(Panel.fit(
            "[bold]البحث في Intelligence X[/bold]",
            title="بحث جديد",
            border_style="blue"
        ))
        
        # إدخال مصطلح البحث
        term = Prompt.ask("\n[bold]أدخل مصطلح البحث[/bold] (البريد الإلكتروني، النطاق، IP، إلخ)")
        if not term:
            console.print("[yellow]لم يتم إدخال مصطلح بحث.[/yellow]")
            return
        
        # اختيار الـ buckets
        console.print("\n[bold]اختر الـ buckets للبحث:[/bold]")
        for i, bucket in enumerate(self.account_info.bucketsh, 1):
            access = self.account_info.get_bucket_access(self.account_info.buckets[i-1])
            access_color = "green" if access == "Full" else "yellow"
            console.print(f"{i}. [cyan]{bucket}[/cyan] - [bold][{access_color}]{access}[/{access_color}][/bold]")
        
        buckets_input = Prompt.ask(
            "\nأدخل أرقام الـ buckets مفصولة بفواصل (اتركه فارغاً للبحث في جميع الـ buckets المسموح بها)",
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
                console.print("[yellow]لم يتم تحديد الـ buckets بشكل صحيح. سيتم البحث في جميع الـ buckets المسموح بها.[/yellow]")
        
        # تحديد الحد الأقصى للنتائج
        max_results = Prompt.ask(
            "الحد الأقصى للنتائج",
            default="10",
            choices=["5", "10", "20", "50", "100"],
            show_choices=False
        )
        
        # تحديد الترتيب
        console.print("\n[bold]اختر طريقة الترتيب:[/bold]")
        console.print("1. الأكثر صلة أولاً (الافتراضي)")
        console.print("2. الأقل صلة أولاً")
        console.print("3. الأقدم أولاً")
        console.print("4. الأحدث أولاً")
        
        sort_option = Prompt.ask(
            "أدخل رقم الترتيب",
            default="1",
            choices=["1", "2", "3", "4"],
            show_choices=False
        )
        
        sort_map = {
            "1": 2,  # الأكثر صلة أولاً
            "2": 1,  # الأقل صلة أولاً
            "3": 3,  # الأقدم أولاً
            "4": 4   # الأحدث أولاً
        }
        
        sort = sort_map.get(sort_option, 2)
        
        # بدء البحث
        console.print("\n[bold cyan]جاري بدء البحث...[/bold cyan]")
        if self.search(term, selected_buckets, int(max_results), sort):
            console.clear()
            console.print(Panel.fit(
                f"[bold]نتائج البحث عن '{term}'[/bold]",
                title="نتائج البحث",
                border_style="blue"
            ))
            self.display_search_results()
            
            # السماح للمستخدم باختيار نتيجة للعرض أو التنزيل
            self.handle_result_selection()
        else:
            console.print("[yellow]لم يتم العثور على نتائج للبحث.[/yellow]")
            Prompt.ask("اضغط Enter للعودة إلى القائمة الرئيسية")
    
    def handle_result_selection(self):
        """التعامل مع اختيار نتيجة من النتائج"""
        if not self.search_results:
            return
        
        choice = Prompt.ask(
            "\n[bold]اختر نتيجة للعرض (أدخل رقم) أو اضغط Enter للعودة إلى القائمة الرئيسية[/bold]",
            default=""
        )
        
        if not choice:
            return
        
        try:
            index = int(choice) - 1
            if 0 <= index < len(self.search_results):
                result = self.search_results[index]
                self.display_result_details(result)
            else:
                console.print("[yellow]رقم غير صحيح.[/yellow]")
        except ValueError:
            console.print("[yellow]الرجاء إدخال رقم صحيح.[/yellow]")
    
    def display_result_details(self, result):
        """عرض تفاصيل نتيجة محددة"""
        console.clear()
        console.print(Panel.fit(
            f"[bold]{result.name}[/bold]",
            title="تفاصيل النتيجة",
            border_style="blue"
        ))
        
        # عرض المعلومات الأساسية
        info_table = Table.grid(padding=(0, 1))
        info_table.add_column(ratio=1)
        info_table.add_column(ratio=2)
        
        # تحديد حجم الملف
        size_str = f"{result.size} بايت"
        if result.size > 1024 * 1024:  # أكثر من ميغابايت
            size_str = f"{result.size / (1024 * 1024):.2f} ميغابايت"
        elif result.size > 1024:  # أكثر من كيلوبايت
            size_str = f"{result.size / 1024:.2f} كيلوبايت"
        
        # تحديد صلاحية الوصول
        access_level = "كامل" if result.accesslevel == 0 else "معاينة فقط"
        access_level_color = "green" if result.accesslevel == 0 else "yellow"
        
        # تحديد إمكانية الوصول
        can_download = "نعم" if result.can_download() else "لا"
        can_download_color = "green" if result.can_download() else "red"
        
        can_preview = "نعم" if result.can_preview() else "لا"
        can_preview_color = "green" if result.can_preview() else "red"
        
        # تحديد ما إذا كانت البيانات مخفية
        is_redacted = "نعم" if result.is_redacted() else "لا"
        is_redacted_color = "yellow" if result.is_redacted() else "green"
        
        info_table.add_row("[bold]النوع:[/bold]", result.media_human)
        info_table.add_row("[bold]التاريخ:[/bold]", result.date)
        info_table.add_row("[bold]الحجم:[/bold]", size_str)
        info_table.add_row("[bold]الـ Bucket:[/bold]", result.bucket_human)
        info_table.add_row("[bold]الصلاحية:[/bold]", f"[{access_level_color}]{access_level}[/{access_level_color}]")
        info_table.add_row("[bold]التنزيل:[/bold]", f"[{can_download_color}]{can_download}[/{can_download_color}]")
        info_table.add_row("[bold]المعاينة:[/bold]", f"[{can_preview_color}]{can_preview}[/{can_preview_color}]")
        info_table.add_row("[bold]المحتوى مخفي:[/bold]", f"[{is_redacted_color}]{is_redacted}[/{is_redacted_color}]")
        
        console.print(info_table)
        
        # عرض تحذير إذا كانت البيانات مخفية
        if result.is_redacted():
            warning_panel = Panel(
                "ملاحظة: هذا الملف يحتوي على بيانات حساسة (مثل كلمات المرور).\n"
                "في الحساب التجريبي، يتم إخفاء المحتوى الفعلي ويظهر كرموز █████.\n"
                "لرؤية المحتوى الكامل، ستحتاج إلى الترقية إلى حساب مدفوع.\n"
                "https://intelx.io/account?tab=developer",
                title="تحذير مهم",
                border_style="yellow"
            )
            console.print(warning_panel)
        
        # عرض خيارات للمستخدم
        console.print("\n[bold]اختر إجراء:[/bold]")
        console.print("1. عرض المعاينة")
        if result.can_download():
            console.print("2. تنزيل الملف")
        else:
            console.print("[dim]2. تنزيل الملف (غير متاح مع الحساب التجريبي)[/dim]")
        console.print("3. العودة إلى نتائج البحث")
        
        action = Prompt.ask(
            "أدخل رقم الإجراء",
            choices=["1", "2", "3"],
            default="3"
        )
        
        if action == "1":
            self.preview_selected_result(result)
        elif action == "2" and result.can_download():
            self.download_selected_result(result)
        # إذا كان الخيار 2 غير متاح، فسيعود تلقائياً
    
    def preview_selected_result(self, result):
        """عرض معاينة للنتيجة المحددة"""
        console.clear()
        console.print(Panel.fit(
            f"[bold]معاينة: {result.name}[/bold]",
            title="عرض المعاينة",
            border_style="blue"
        ))
        
        # تحديد عدد الأسطر
        lines = Prompt.ask(
            "عدد الأسطر المراد عرضها",
            default="20",
            choices=["10", "20", "50", "100"],
            show_choices=False
        )
        
        preview = self.preview_file(result.systemid, result.bucket, int(lines))
        
        if preview:
            # تحديد ما إذا كانت المعاينة تحتوي على رموز █████
            is_redacted = "████" in preview
            
            if is_redacted:
                console.print(Panel(
                    "ملاحظة: يظهر المحتوى كرموز █████ لأن حسابك التجريبي لا يسمح برؤية المحتوى الكامل.\n"
                    "السبب: هذه البيانات تقع في فئة 'Leaks » Logs' التي تقتصر على معاينة فقط في الحساب التجريبي.\n"
                    "لرؤية المحتوى الفعلي، ستحتاج إلى الترقية إلى حساب مدفوع.",
                    title="معلومات مهمة",
                    border_style="yellow"
                ))
            
            console.print("\n[bold]معاينة الملف:[/bold]")
            console.print(Syntax(preview, "text", theme="monokai", line_numbers=True))
            
            # إذا كانت المعاينة تحتوي على رموز █████
            if is_redacted:
                console.print("\n[yellow]ملاحظة: الرموز (████) تمثل محتوى مخفياً بسبب محدوديات الحساب التجريبي.[/yellow]")
                console.print("[yellow]للحصول على المحتوى الكامل، قم بالترقية إلى حساب مدفوع.[/yellow]")
        else:
            console.print("[yellow]لم يتم العثور على معاينة لهذا الملف.[/yellow]")
        
        # العودة إلى تفاصيل النتيجة
        Prompt.ask("\nاضغط Enter للعودة")
        self.display_result_details(result)
    
    def download_selected_result(self, result):
        """تنزيل النتيجة المحددة"""
        console.clear()
        console.print(Panel.fit(
            f"[bold]تنزيل: {result.name}[/bold]",
            title="تنزيل الملف",
            border_style="blue"
        ))
        
        # تحديد اسم الملف
        filename = Prompt.ask(
            "اسم الملف للحفظ",
            default=os.path.basename(result.name) if result.name else f"{result.systemid}.bin"
        )
        
        # تنزيل الملف
        download_path = self.download_file(
            result.systemid,
            result.bucket,
            result.storageid,
            filename
        )
        
        if download_path:
            success_panel = Panel(
                f"تم تنزيل الملف بنجاح إلى:\n{download_path}\n\n"
                "ملاحظة: إذا كان الملف فارغاً، فهذا لأن الحساب التجريبي لا يسمح بتنزيل المحتوى الكامل "
                "للفئات المخفية مثل 'Leaks » Logs'.",
                title="تنزيل ناجح",
                border_style="green"
            )
            console.print(success_panel)
        else:
            console.print("[yellow]فشل تنزيل الملف.[/yellow]")
        
        # العودة إلى تفاصيل النتيجة
        Prompt.ask("\nاضغط Enter للعودة")
        self.display_result_details(result)
    
    def main_menu(self):
        """القائمة الرئيسية"""
        while True:
            console.clear()
            
            # عرض معلومات الحساب في الأعلى
            self.display_account_info()
            
            console.print("\n[bold]القائمة الرئيسية:[/bold]")
            console.print("1. بحث جديد")
            console.print("2. عرض معلومات الحساب")
            console.print("3. مساعدة")
            console.print("4. الخروج")
            
            choice = Prompt.ask(
                "\nاختر إجراء",
                choices=["1", "2", "3", "4"],
                default="1"
            )
            
            if choice == "1":
                self.interactive_search()
            elif choice == "2":
                console.clear()
                self.display_account_info()
                Prompt.ask("\nاضغط Enter للعودة إلى القائمة الرئيسية")
            elif choice == "3":
                self.display_help()
                Prompt.ask("\nاضغط Enter للعودة إلى القائمة الرئيسية")
            elif choice == "4":
                console.print("[green]تم الخروج من البرنامج.[/green]")
                break
    
    def display_help(self):
        """عرض مساعدة البرنامج"""
        console.clear()
        
        console.print(Panel.fit(
            "[bold]مساعدة Intelligence X CLI[/bold]",
            title="المساعدة",
            border_style="blue"
        ))
        
        # شرح مصطلحات البحث المدعومة
        console.print("\n[bold]مصطلحات البحث المدعومة:[/bold]")
        terms_table = Table(box=box.SIMPLE)
        terms_table.add_column("المصطلح", style="cyan")
        terms_table.add_column("مثال", style="green")
        
        terms_table.add_row("العناوين البريدية", "example@example.com")
        terms_table.add_row("النطاقات", "example.com")
        terms_table.add_row("عناوين IP", "192.168.1.1")
        terms_table.add_row("CIDR", "192.168.1.0/24")
        terms_table.add_row("أرقام الهواتف", "+1234567890")
        terms_table.add_row("عناوين البيتكوين", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        
        console.print(terms_table)
        
        # شرح محدوديات الحساب التجريبي
        console.print("\n[bold]محدوديات الحساب التجريبي (Trial):[/bold]")
        limitations_table = Table(box=box.SIMPLE)
        limitations_table.add_column("المحدودية", style="yellow")
        limitations_table.add_column("التأثير", style="red")
        
        limitations_table.add_row(
            "فئات مخفية (مثل Leaks » Logs)",
            "المحتوى يظهر كرموز █████ (معاينة فقط)"
        )
        limitations_table.add_row(
            "التنزيل الكامل",
            "غير متاح للفئات المخفية (سيكون الملف فارغاً)"
        )
        limitations_table.add_row(
            "الائتمانات المحدودة",
            "حدود يومية على عمليات البحث والمعاينة"
        )
        
        console.print(limitations_table)
        
        # شرح كيفية الترقية
        console.print("\n[bold]للحصول على ميزات إضافية:[/bold]")
        console.print("- توجه إلى [blue]https://intelx.io/account?tab=developer[/blue] للترقية إلى حساب مدفوع")
        console.print("- الحساب المدفوع يسمح بعرض المحتوى الكامل وتنزيله")
        
        # شرح استخدام المعاينة
        console.print("\n[bold]كيفية عرض المعاينة بشكل صحيح:[/bold]")
        console.print("- عند البحث، ستظهر النتائج مع إشارة '✎ معاينة' للبيانات المخفية")
        console.print("- اختر النتيجة ثم اضغط '1' لعرض المعاينة")
        console.print("- ستظهر المعاينة مع الرموز █████ التي تمثل المحتوى المخفي")
        console.print("- هذا ليس خطأ، بل هو سياسة مقصودة في الحساب التجريبي")

# الدالة الرئيسية
def main():
    console.clear()
    console.print(Panel.fit(
        "[bold green]Intelligence X CLI[/bold green]\n[bold]أداة بحث احترافية لـ Intelligence X API[/bold]\n"
        "[italic]الإصدار 1.0 - مصممة خصيصاً لحسابات التجربة (Trial)[/italic]",
        title="مرحباً",
        border_style="green"
    ))
    
    # إنشاء نسخة من الواجهة
    cli = IntelligenceXCLI(API_KEY, API_URL)
    
    # عرض القائمة الرئيسية
    cli.main_menu()

if __name__ == "__main__":
    main()
