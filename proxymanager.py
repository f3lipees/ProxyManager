#!/usr/bin/env python3

import os
import sys
import threading
import tempfile
import requests
import hashlib
import hmac
import secrets
import time
import logging
import json
import re
import ssl
import urllib3
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
import queue
import socket
from urllib.parse import urlparse

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
from ttkbootstrap.scrolled import ScrolledText

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class SecurityConfig:
    max_file_size: int = 10 * 1024 * 1024
    max_proxies: int = 50000
    request_timeout: int = 15
    max_retries: int = 3
    rate_limit_delay: float = 0.1
    session_timeout: int = 3600
    allowed_domains: List[str] = field(default_factory=lambda: ['api.proxyscrape.com', 'www.proxy-list.download'])
    cipher_suite: str = 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS'

@dataclass
class ProxyEntry:
    host: str
    port: int
    protocol: str = 'socks5'
    validated: bool = False
    last_check: Optional[datetime] = None
    response_time: Optional[float] = None

class SecurityManager:
    def __init__(self, config: SecurityConfig):
        self.config = config
        self._session_key = secrets.token_hex(32)
        self._rate_limiter = {}
        self._setup_logging()
    
    def _setup_logging(self):
        log_dir = Path.home() / '.proxy_manager' / 'logs'
        log_dir.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / f'proxy_manager_{datetime.now().strftime("%Y%m%d")}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def validate_domain(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            return any(allowed in domain for allowed in self.config.allowed_domains)
        except Exception as e:
            self.logger.error(f"Domain validation error: {e}")
            return False
    
    def sanitize_proxy_data(self, data: str) -> str:
        if len(data) > self.config.max_file_size:
            raise ValueError("Proxy data exceeds maximum allowed size")
        
        sanitized = re.sub(r'[^\w\.\:\n\r\-]', '', data)
        lines = sanitized.split('\n')
        
        if len(lines) > self.config.max_proxies:
            raise ValueError("Too many proxy entries")
        
        validated_lines = []
        for line in lines[:self.config.max_proxies]:
            line = line.strip()
            if self._validate_proxy_format(line):
                validated_lines.append(line)
        
        return '\n'.join(validated_lines)
    
    def _validate_proxy_format(self, proxy: str) -> bool:
        if not proxy:
            return False
        
        try:
            parts = proxy.split(':')
            if len(parts) != 2:
                return False
            
            host, port = parts
            
            if not re.match(r'^[a-zA-Z0-9\.\-]+$', host):
                return False
            
            port_num = int(port)
            if not (1 <= port_num <= 65535):
                return False
            
            return True
        except (ValueError, AttributeError):
            return False
    
    def rate_limit_check(self, identifier: str) -> bool:
        current_time = time.time()
        
        if identifier in self._rate_limiter:
            last_request = self._rate_limiter[identifier]
            if current_time - last_request < self.config.rate_limit_delay:
                return False
        
        self._rate_limiter[identifier] = current_time
        return True
    
    def create_secure_session(self) -> requests.Session:
        session = requests.Session()
        
        session.headers.update({
            'User-Agent': 'ProxyManager/2.0 (Security-Hardened)',
            'Accept': 'text/plain,application/json',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Cache-Control': 'no-cache'
        })
        
        adapter = requests.adapters.HTTPAdapter(
            max_retries=urllib3.util.Retry(
                total=self.config.max_retries,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504]
            )
        )
        
        session.mount('https://', adapter)
        session.mount('http://', adapter)
        
        return session

class ProxyValidator:
    def __init__(self, security_manager: SecurityManager):
        self.security_manager = security_manager
        self.logger = security_manager.logger
    
    def validate_proxy_connectivity(self, proxy: ProxyEntry) -> Tuple[bool, Optional[float]]:
        try:
            start_time = time.time()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            result = sock.connect_ex((proxy.host, proxy.port))
            sock.close()
            
            if result == 0:
                response_time = time.time() - start_time
                return True, response_time
            else:
                return False, None
                
        except Exception as e:
            self.logger.debug(f"Proxy validation failed for {proxy.host}:{proxy.port} - {e}")
            return False, None
    
    def batch_validate_proxies(self, proxies: List[ProxyEntry], max_workers: int = 20) -> List[ProxyEntry]:
        validated_proxies = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_proxy = {
                executor.submit(self.validate_proxy_connectivity, proxy): proxy 
                for proxy in proxies
            }
            
            for future in as_completed(future_to_proxy):
                proxy = future_to_proxy[future]
                try:
                    is_valid, response_time = future.result()
                    proxy.validated = is_valid
                    proxy.response_time = response_time
                    proxy.last_check = datetime.now()
                    
                    if is_valid:
                        validated_proxies.append(proxy)
                        
                except Exception as e:
                    self.logger.error(f"Validation error for {proxy.host}:{proxy.port} - {e}")
        
        return sorted(validated_proxies, key=lambda x: x.response_time or float('inf'))

class SecureFileManager:
    def __init__(self, security_manager: SecurityManager):
        self.security_manager = security_manager
        self.logger = security_manager.logger
        self.app_dir = Path.home() / '.proxy_manager'
        self.app_dir.mkdir(parents=True, exist_ok=True)
    
    def get_secure_temp_path(self) -> Path:
        temp_name = f"proxies_{secrets.token_hex(8)}.txt"
        return self.app_dir / temp_name
    
    def write_proxies_secure(self, proxies: str, file_path: Path) -> bool:
        try:
            sanitized_data = self.security_manager.sanitize_proxy_data(proxies)
            
            with open(file_path, 'w', encoding='utf-8', newline='\n') as f:
                f.write(sanitized_data)
            
            os.chmod(file_path, 0o600)
            
            self.logger.info(f"Proxies written securely to {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to write proxies securely: {e}")
            return False
    
    def read_proxies_secure(self, file_path: Path) -> Optional[str]:
        try:
            if not file_path.exists():
                return None
            
            stat_info = file_path.stat()
            if stat_info.st_size > self.security_manager.config.max_file_size:
                raise ValueError("File too large")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            return self.security_manager.sanitize_proxy_data(content)
            
        except Exception as e:
            self.logger.error(f"Failed to read proxies securely: {e}")
            return None

class ProxyFetcher:
    def __init__(self, security_manager: SecurityManager):
        self.security_manager = security_manager
        self.logger = security_manager.logger
        self.session = security_manager.create_secure_session()
    
    def fetch_proxies_from_api(self, url: str) -> Optional[str]:
        if not self.security_manager.validate_domain(url):
            raise ValueError("Unauthorized domain")
        
        if not self.security_manager.rate_limit_check(url):
            raise ValueError("Rate limit exceeded")
        
        try:
            response = self.session.get(
                url,
                timeout=self.security_manager.config.request_timeout,
                verify=True,
                allow_redirects=False
            )
            
            if response.status_code == 200:
                content_length = len(response.content)
                if content_length > self.security_manager.config.max_file_size:
                    raise ValueError("Response too large")
                
                return response.text.strip()
            else:
                self.logger.warning(f"HTTP {response.status_code} from {url}")
                return None
                
        except requests.RequestException as e:
            self.logger.error(f"Request failed for {url}: {e}")
            return None
    
    def close_session(self):
        if self.session:
            self.session.close()

class ProxyManagerApp(ttk.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        
        self.title("Proxy Manager v1.0")
        self.geometry("900x600")
        self.resizable(True, True)
        
        self.security_config = SecurityConfig()
        self.security_manager = SecurityManager(self.security_config)
        self.file_manager = SecureFileManager(self.security_manager)
        self.proxy_fetcher = ProxyFetcher(self.security_manager)
        self.proxy_validator = ProxyValidator(self.security_manager)
        
        self.proxies_data = []
        self.current_proxies_file = None
        
        self._build_ui()
        self._setup_window_security()
        
        self.protocol("WM_DELETE_WINDOW", self._on_closing)
    
    def _setup_window_security(self):
        try:
            self.attributes('-topmost', False)
            self.focus_force()
        except:
            pass
    
    def _build_ui(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=BOTH, expand=YES, padx=10, pady=10)
        
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=X, pady=(0, 10))
        
        title_label = ttk.Label(
            header_frame, 
            text="Proxy Manager", 
            font=("Segoe UI", 16, "bold")
        )
        title_label.pack(side=LEFT)
        
        status_frame = ttk.Frame(header_frame)
        status_frame.pack(side=RIGHT, fill=X, expand=YES)
        
        self.status_label = ttk.Label(
            status_frame, 
            text="Ready - Click 'Fetch Proxies' to begin", 
            font=("Segoe UI", 10),
            anchor="e"
        )
        self.status_label.pack(fill=X)
        
        self.progress_var = ttk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            status_frame, 
            variable=self.progress_var, 
            mode='determinate'
        )
        
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=X, pady=(0, 10))
        
        source_label = ttk.Label(control_frame, text="Proxy Source:")
        source_label.pack(side=LEFT, padx=(0, 5))
        
        self.source_var = ttk.StringVar(value="proxyscrape")
        source_combo = ttk.Combobox(
            control_frame,
            textvariable=self.source_var,
            values=["proxyscrape", "proxy-list"],
            state="readonly",
            width=15
        )
        source_combo.pack(side=LEFT, padx=(0, 10))
        
        self.validate_var = ttk.BooleanVar(value=True)
        validate_check = ttk.Checkbutton(
            control_frame,
            text="Validate Proxies",
            variable=self.validate_var
        )
        validate_check.pack(side=LEFT, padx=(0, 10))
        
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(side=RIGHT)
        
        self.fetch_button = ttk.Button(
            button_frame,
            text="Fetch Proxies",
            bootstyle=SUCCESS,
            command=self._fetch_proxies_threaded
        )
        self.fetch_button.pack(side=LEFT, padx=(0, 5))
        
        self.validate_button = ttk.Button(
            button_frame,
            text="Validate All",
            bootstyle=WARNING,
            command=self._validate_proxies_threaded,
            state=DISABLED
        )
        self.validate_button.pack(side=LEFT, padx=(0, 5))
        
        self.save_button = ttk.Button(
            button_frame,
            text="Save Proxies",
            bootstyle=PRIMARY,
            command=self._save_proxies,
            state=DISABLED
        )
        self.save_button.pack(side=LEFT, padx=(0, 5))
        
        self.export_button = ttk.Button(
            button_frame,
            text="Export JSON",
            bootstyle=INFO,
            command=self._export_json,
            state=DISABLED
        )
        self.export_button.pack(side=LEFT)
        
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=BOTH, expand=YES)
        
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(fill=BOTH, expand=YES)
        
        proxy_frame = ttk.Frame(self.notebook)
        self.notebook.add(proxy_frame, text="Proxy List")
        
        self.text_area = ScrolledText(
            proxy_frame,
            height=20,
            autohide=True,
            font=("Consolas", 9),
            state=DISABLED
        )
        self.text_area.pack(fill=BOTH, expand=YES, padx=5, pady=5)
        
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="Statistics")
        
        self.stats_text = ScrolledText(
            stats_frame,
            height=20,
            autohide=True,
            font=("Consolas", 9),
            state=DISABLED
        )
        self.stats_text.pack(fill=BOTH, expand=YES, padx=5, pady=5)
        
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="Security Log")
        
        self.log_text = ScrolledText(
            log_frame,
            height=20,
            autohide=True,
            font=("Consolas", 8),
            state=DISABLED
        )
        self.log_text.pack(fill=BOTH, expand=YES, padx=5, pady=5)
        
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill=X, pady=(10, 0))
        
        self.count_label = ttk.Label(
            footer_frame,
            text="Proxies: 0 | Validated: 0",
            font=("Segoe UI", 9)
        )
        self.count_label.pack(side=LEFT)
        
        security_label = ttk.Label(
            footer_frame,
            text="ðŸ”’ Security: Active",
            font=("Segoe UI", 9),
            foreground="green"
        )
        security_label.pack(side=RIGHT)
    
    def _get_api_url(self) -> str:
        source = self.source_var.get()
        if source == "proxyscrape":
            return "https://api.proxyscrape.com/?request=displayproxies&proxytype=socks5&country=all"
        elif source == "proxy-list":
            return "https://www.proxy-list.download/api/v1/get?type=socks5"
        else:
            raise ValueError("Invalid proxy source")
    
    def _fetch_proxies_threaded(self):
        self._set_buttons_state(False)
        self._update_status("Fetching proxies from secure API...")
        self._show_progress()
        
        threading.Thread(target=self._fetch_proxies_worker, daemon=True).start()
    
    def _fetch_proxies_worker(self):
        try:
            url = self._get_api_url()
            
            self.after(0, lambda: self._update_progress(25))
            
            raw_data = self.proxy_fetcher.fetch_proxies_from_api(url)
            
            if not raw_data:
                self.after(0, lambda: self._on_fetch_error("No data received from API"))
                return
            
            self.after(0, lambda: self._update_progress(50))
            
            sanitized_data = self.security_manager.sanitize_proxy_data(raw_data)
            
            self.after(0, lambda: self._update_progress(75))
            
            proxy_lines = [line.strip() for line in sanitized_data.split('\n') if line.strip()]
            self.proxies_data = []
            
            for line in proxy_lines:
                if ':' in line:
                    host, port = line.split(':', 1)
                    try:
                        self.proxies_data.append(ProxyEntry(host.strip(), int(port.strip())))
                    except ValueError:
                        continue
            
            self.after(0, lambda: self._update_progress(100))
            
            if self.validate_var.get():
                self.after(0, lambda: self._on_fetch_success_with_validation(sanitized_data))
            else:
                self.after(0, lambda: self._on_fetch_success(sanitized_data))
                
        except Exception as e:
            self.security_manager.logger.error(f"Fetch error: {e}")
            self.after(0, lambda: self._on_fetch_error(str(e)))
    
    def _validate_proxies_threaded(self):
        if not self.proxies_data:
            Messagebox.show_warning("Warning", "No proxies to validate")
            return
        
        self._set_buttons_state(False)
        self._update_status("Validating proxy connectivity...")
        self._show_progress()
        
        threading.Thread(target=self._validate_proxies_worker, daemon=True).start()
    
    def _validate_proxies_worker(self):
        try:
            self.after(0, lambda: self._update_progress(10))
            
            validated_proxies = self.proxy_validator.batch_validate_proxies(self.proxies_data)
            
            self.after(0, lambda: self._update_progress(90))
            
            working_proxies = [f"{p.host}:{p.port}" for p in validated_proxies if p.validated]
            
            self.after(0, lambda: self._update_progress(100))
            self.after(0, lambda: self._on_validation_complete(working_proxies, validated_proxies))
            
        except Exception as e:
            self.security_manager.logger.error(f"Validation error: {e}")
            self.after(0, lambda: self._on_fetch_error(f"Validation failed: {e}"))
    
    def _on_fetch_success(self, data: str):
        self._set_text_content(self.text_area, data)
        count = len(self.proxies_data)
        self._update_status(f"Successfully fetched {count} proxies")
        self._update_counts(count, 0)
        self._update_stats()
        self._hide_progress()
        self._set_buttons_state(True)
    
    def _on_fetch_success_with_validation(self, data: str):
        self._update_status("Fetched proxies, starting validation...")
        self._validate_proxies_worker()
    
    def _on_validation_complete(self, working_proxies: List[str], validated_proxies: List[ProxyEntry]):
        proxy_text = '\n'.join(working_proxies)
        self._set_text_content(self.text_area, proxy_text)
        
        total_count = len(self.proxies_data)
        validated_count = len(working_proxies)
        
        self._update_status(f"Validation complete: {validated_count}/{total_count} proxies working")
        self._update_counts(total_count, validated_count)
        self._update_stats(validated_proxies)
        self._hide_progress()
        self._set_buttons_state(True)
    
    def _on_fetch_error(self, message: str):
        self._update_status("Error occurred during operation")
        self._hide_progress()
        self._set_buttons_state(True)
        Messagebox.show_error("Error", f"Operation failed: {message}")
    
    def _save_proxies(self):
        content = self._get_text_content(self.text_area)
        if not content.strip():
            Messagebox.show_warning("Warning", "No proxies to save")
            return
        
        try:
            self.current_proxies_file = self.file_manager.get_secure_temp_path()
            
            if self.file_manager.write_proxies_secure(content, self.current_proxies_file):
                Messagebox.show_info(
                    "Success", 
                    f"Proxies saved securely to:\n{self.current_proxies_file}"
                )
                self._log_security_event(f"Proxies saved to {self.current_proxies_file}")
            else:
                Messagebox.show_error("Error", "Failed to save proxies securely")
                
        except Exception as e:
            self.security_manager.logger.error(f"Save error: {e}")
            Messagebox.show_error("Error", f"Save operation failed: {e}")
    
    def _export_json(self):
        if not self.proxies_data:
            Messagebox.show_warning("Warning", "No proxy data to export")
            return
        
        try:
            export_data = {
                "timestamp": datetime.now().isoformat(),
                "total_proxies": len(self.proxies_data),
                "validated_proxies": sum(1 for p in self.proxies_data if p.validated),
                "proxies": [
                    {
                        "host": p.host,
                        "port": p.port,
                        "protocol": p.protocol,
                        "validated": p.validated,
                        "response_time": p.response_time,
                        "last_check": p.last_check.isoformat() if p.last_check else None
                    }
                    for p in self.proxies_data
                ]
            }
            
            export_file = self.file_manager.app_dir / f"proxies_export_{int(time.time())}.json"
            
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            os.chmod(export_file, 0o600)
            
            Messagebox.show_info("Success", f"Data exported to:\n{export_file}")
            self._log_security_event(f"Data exported to {export_file}")
            
        except Exception as e:
            self.security_manager.logger.error(f"Export error: {e}")
            Messagebox.show_error("Error", f"Export failed: {e}")
    
    def _update_stats(self, validated_proxies: Optional[List[ProxyEntry]] = None):
        stats = []
        stats.append("=== PROXY STATISTICS ===\n")
        stats.append(f"Total Proxies Fetched: {len(self.proxies_data)}")
        
        if validated_proxies:
            working = [p for p in validated_proxies if p.validated]
            stats.append(f"Working Proxies: {len(working)}")
            stats.append(f"Success Rate: {len(working)/len(self.proxies_data)*100:.1f}%")
            
            if working:
                response_times = [p.response_time for p in working if p.response_time]
                if response_times:
                    stats.append(f"Average Response Time: {sum(response_times)/len(response_times):.3f}s")
                    stats.append(f"Fastest Response: {min(response_times):.3f}s")
                    stats.append(f"Slowest Response: {max(response_times):.3f}s")
        
        stats.append(f"\nLast Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        stats.append(f"Security Manager: Active")
        stats.append(f"Rate Limiting: Enabled")
        stats.append(f"Input Validation: Enabled")
        
        self._set_text_content(self.stats_text, '\n'.join(stats))
    
    def _log_security_event(self, event: str):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] SECURITY: {event}"
        
        current_log = self._get_text_content(self.log_text)
        if current_log:
            new_log = f"{log_entry}\n{current_log}"
        else:
            new_log = log_entry
        
        self._set_text_content(self.log_text, new_log)
        self.security_manager.logger.info(event)
    
    def _set_text_content(self, widget: ScrolledText, content: str):
        widget.text.configure(state=NORMAL)
        widget.text.delete("1.0", "end")
        widget.text.insert("1.0", content)
        widget.text.configure(state=DISABLED)
    
    def _get_text_content(self, widget: ScrolledText) -> str:
        return widget.text.get("1.0", "end-1c")
    
    def _update_status(self, message: str):
        self.status_label.configure(text=message)
        self._log_security_event(f"Status: {message}")
    
    def _update_counts(self, total: int, validated: int):
        self.count_label.configure(text=f"Proxies: {total} | Validated: {validated}")
    
    def _show_progress(self):
        self.progress_bar.pack(fill=X, pady=(5, 0))
        self.progress_var.set(0)
    
    def _hide_progress(self):
        self.progress_bar.pack_forget()
    
    def _update_progress(self, value: float):
        self.progress_var.set(value)
    
    def _set_buttons_state(self, enabled: bool):
        state = NORMAL if enabled else DISABLED
        self.fetch_button.configure(state=state)
        self.save_button.configure(state=state if self.proxies_data else DISABLED)
        self.validate_button.configure(state=state if self.proxies_data else DISABLED)
        self.export_button.configure(state=state if self.proxies_data else DISABLED)
    
    def _on_closing(self):
        try:
            self.proxy_fetcher.close_session()
            self._log_security_event("Application shutdown initiated")
            self.security_manager.logger.info("Application closed securely")
        except Exception as e:
            self.security_manager.logger.error(f"Shutdown error: {e}")
        finally:
            self.destroy()

def main():
    try:
        app = ProxyManagerApp()
        app.mainloop()
    except Exception as e:
        logging.error(f"Application startup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
