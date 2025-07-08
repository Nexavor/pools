# -*- coding: utf-8 -*-

# --- Windows 7 相容性說明 ---
# 1. Python 版本: 此腳本建議使用 Python 3.8.x 版本運行，因為這是官方支援 Windows 7 的最後一個主要 Python 版本。
# 2. 安裝依賴庫: 為了確保在 Windows 7 上能成功發起 HTTPS 網路請求 (因其內建安全憑證可能過舊)，
#    強烈建議安裝 'certifi' 庫。請使用以下指令安裝所有必要的函式庫：
#    pip install requests pysocks certifi futures
# -----------------------------------

import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
import base64
import random
import time
import threading
import requests
import sys
import certifi
import json
import re
import os
import traceback
import urllib.parse
import urllib.request
from collections import defaultdict
import itertools
import ssl
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed

# 為了支援SOCKS代理，需要安裝 PySocks
try:
    import socks
except ImportError:
    class FakeSocks:
        def set_default_proxy(self, *args, **kwargs):
            pass
    sys.modules['socks'] = FakeSocks()


# --- 通用右鍵菜單功能 ---
class TextWidgetContextMenu:
    def __init__(self, widget):
        self.widget = widget
        self.menu = tk.Menu(widget, tearoff=0)
        self.menu.add_command(label="剪下", command=self.cut)
        self.menu.add_command(label="複製", command=self.copy)
        self.menu.add_command(label="貼上", command=self.paste)
        self.menu.add_separator()
        self.menu.add_command(label="全選", command=self.select_all)
        widget.bind("<Button-3>", self.show_menu)

    def show_menu(self, event):
        try:
            if self.widget.selection_get():
                self.menu.entryconfig("剪下", state=tk.NORMAL); self.menu.entryconfig("複製", state=tk.NORMAL)
            else:
                self.menu.entryconfig("剪下", state=tk.DISABLED); self.menu.entryconfig("複製", state=tk.DISABLED)
        except tk.TclError:
            self.menu.entryconfig("剪下", state=tk.DISABLED); self.menu.entryconfig("複製", state=tk.DISABLED)
        try:
            if self.widget.clipboard_get(): self.menu.entryconfig("貼上", state=tk.NORMAL)
        except tk.TclError:
            self.menu.entryconfig("貼上", state=tk.DISABLED)
        self.menu.tk_popup(event.x_root, event.y_root)

    def cut(self): self.widget.event_generate("<<Cut>>")
    def copy(self): self.widget.event_generate("<<Copy>>")
    def paste(self): self.widget.event_generate("<<Paste>>")
    def select_all(self):
        if isinstance(self.widget, (ttk.Entry, tk.Entry)): self.widget.select_range(0, tk.END)
        elif isinstance(self.widget, (tk.Text, scrolledtext.ScrolledText)): self.widget.tag_add("sel", "1.0", "end")


# --- 從 nexavor/aggregator 專案移植的輔助函式 ---
class NexavorUtils:
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    DEFAULT_HTTP_HEADERS = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"}
    CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
    @staticmethod
    def isurl(url): return url.startswith('http://') or url.startswith('https://')
    @staticmethod
    def trim(text: str) -> str:
        if not text or not isinstance(text, str): return ""
        return text.strip()
    @staticmethod
    def http_get(url, headers=None, params=None, retry=3, proxy=None, timeout=15, trace=False):
        if not NexavorUtils.isurl(url): return ""
        if retry <= 0: return ""
        headers = headers if headers else NexavorUtils.DEFAULT_HTTP_HEADERS
        proxies = {'http': proxy, 'https': proxy} if proxy else None
        try:
            full_url = url
            if params: full_url += '?' + urllib.parse.urlencode(params)
            response = requests.get(full_url, headers=headers, proxies=proxies, timeout=timeout, verify=certifi.where())
            response.raise_for_status()
            return response.text
        except Exception as e:
            if trace: print(f"請求失敗: {url}, 原因: {e}")
            time.sleep(1)
            return NexavorUtils.http_get(url, headers, params, retry - 1, proxy, timeout, trace)

# --- 整合後的並發搜索核心 ---
class DynamicSubscriptionFinder:
    def __init__(self, status_callback=None, proxy_address=None, stop_event=None, lock=None):
        self.status_callback = status_callback
        self.proxy_address = proxy_address
        self.utils = NexavorUtils()
        self.stop_event = stop_event or threading.Event()
        self.lock = lock or threading.Lock()

    def _log_status(self, message):
        if self.status_callback: self.status_callback(message)

    def search_github_for_keyword(self, token, search_query, pages=2):
        if self.stop_event.is_set(): return []
        self._log_status(f"[並發搜索] 開始處理關鍵字: '{search_query}'...")
        links = set()
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": self.utils.USER_AGENT}
        if token: headers["Authorization"] = f"Bearer {token}"
        
        for page in range(1, pages + 1):
            if self.stop_event.is_set(): self._log_status(f"[並發搜索] 關鍵字 '{search_query}' 的任務已中止。"); break
            
            api_url = f"https://api.github.com/search/code?q={urllib.parse.quote(search_query)}&sort=indexed&order=desc&per_page=100&page={page}"
            try:
                content = self.utils.http_get(api_url, headers=headers, proxy=self.proxy_address)
                if not content: continue
                data = json.loads(content)
                items = data.get("items", [])
                if not items: break
                
                for item in items:
                    if self.stop_event.is_set(): break
                    html_url = item.get("html_url")
                    if html_url: links.add(html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/"))
                time.sleep(2)
            except Exception as e:
                self._log_status(f"[並發搜索] 處理關鍵字 '{search_query}' 第 {page} 頁時出錯: {e}"); break
        
        self._log_status(f"[並發搜索] 關鍵字 '{search_query}' 完成，找到 {len(links)} 個潛在連結。")
        return list(links)

    def fetch_and_extract_from_url(self, file_url):
        if self.stop_event.is_set(): return []
        
        content = self.utils.http_get(file_url, proxy=self.proxy_address)
        if not content: return []

        subscriptions = self.extract_subscriptions_from_content(content)
        if subscriptions:
            # 使用鎖確保線程安全地更新日誌
            with self.lock:
                self._log_status(f"  => 從 {file_url} 找到 {len(subscriptions)} 個連結。")
        return subscriptions

    # --- 關鍵改動 ---
    def extract_subscriptions_from_content(self, content):
        """
        修正了從文本內容中提取訂閱鏈接的邏輯。
        之前的版本錯誤地處理 re.findall 的結果，導致只提取到鏈接的第一個字符。
        此版本參考了原始專案的邏輯，直接使用 findall 返回的完整鏈接列表。
        """
        if not content: return []
        
        # 1. 標準訂閱格式 (v2board, sspanel 等)
        sub_regex = r"https?://(?:[a-zA-Z0-9\u4e00-\u9fa5\-]+\.)+[a-zA-Z0-9\u4e00-\u9fa5\-]+(?:(?:(?:/index.php)?/api/v1/client/subscribe\?token=[a-zA-Z0-9]{16,32})|(?:/link/[a-zA-Z0-9]+\?(?:sub|mu|clash)=\d)|(?:/(?:s|sub)/[a-zA-Z0-9]{32}))"
        
        # 2. 其他常見的轉換 API 格式
        extra_regex = r"https?://(?:[a-zA-Z0-9\u4e00-\u9fa5\-]+\.)+[a-zA-Z0-9\u4e00-\u9fa5\-]+/sub\?(?:\S+)?target=\S+"
        
        # 3. 節點本身協議的格式 (ss, vmess, etc.)
        protocol_regex = r"(?:vmess|trojan|ss|ssr|vless|hysteria|tuic)://[a-zA-Z0-9:.?+=@%&#_\-/]{10,}"
        
        # 將所有模式組合在一起，不使用外部捕獲組
        all_patterns = f"{sub_regex}|{extra_regex}|{protocol_regex}"
        
        # re.findall 在沒有捕獲組時，會返回一個包含所有匹配字符串的列表，這正是我們需要的。
        # 例如: ['http://....', 'vmess://....']
        # 舊代碼的問題在於 post-processing a list of strings as a list of tuples.
        found_links = re.findall(all_patterns, content, re.I)
        
        # 使用集合(set)來自動去重，然後轉換回列表
        cleaned_links = {link.strip() for link in found_links if link}
        
        return list(cleaned_links)

    def find(self, executor, github_token, queries, pages):
        all_found_subscriptions = set()
        potential_files = set()

        # --- 第一階段: 並發搜索關鍵字 ---
        self._log_status(f"=== 第一階段: 開始並發搜索 {len(queries)} 個關鍵字 ===")
        if not github_token: self._log_status("[GitHub搜索] 警告：未提供 GitHub Token，搜索請求受到嚴格限制，可能很快失敗。")

        future_to_query = {executor.submit(self.search_github_for_keyword, github_token, f'"{query}" in:file', pages): query for query in queries}
        for future in as_completed(future_to_query):
            if self.stop_event.is_set(): break
            try:
                urls = future.result()
                potential_files.update(urls)
            except Exception as e:
                self._log_status(f"一個關鍵字搜索任務失敗: {e}")
        
        if self.stop_event.is_set(): self._log_status("搜索已中止。"); return []

        # --- 第二階段: 並發獲取文件並提取 ---
        self._log_status(f"\n=== 第二階段: 從 {len(potential_files)} 個文件中並發提取訂閱連結... ===")
        if not potential_files:
            self._log_status("未找到任何可能的文件，任務結束。")
            return []
            
        future_to_url = {executor.submit(self.fetch_and_extract_from_url, url): url for url in potential_files}
        for i, future in enumerate(as_completed(future_to_url)):
            if self.stop_event.is_set(): break
            # 為了避免日誌刷屏太快，可以考慮有條件地打印進度
            if (i+1) % 10 == 0 or i+1 == len(potential_files):
                self._log_status(f"提取進度: {i+1}/{len(potential_files)}")
            try:
                subscriptions = future.result()
                if subscriptions:
                    with self.lock:
                        all_found_subscriptions.update(subscriptions)
            except Exception as e:
                self._log_status(f"一個文件提取任務失敗: {e}")

        if self.stop_event.is_set(): self._log_status("提取已中止。")
        
        self._log_status(f"\n搜索完成！總共找到 {len(all_found_subscriptions)} 個不重複的訂閱連結。"); return list(all_found_subscriptions)

# --- 後端處理核心 ---
class RealProxyAggregator:
    def __init__(self, status_callback=None):
        self.status_callback = status_callback
    def _log_status(self, message):
        if self.status_callback: self.status_callback(message)
    def fetch_and_parse_url(self, url, proxy_address=None):
        self._log_status(f"正在從 {url} 獲取內容...")
        headers = {'User-Agent': 'Clash/1.11.0'}
        proxies = {'http': proxy_address, 'https': proxy_address} if proxy_address else None
        if proxy_address: self._log_status(f"  (使用代理: {proxy_address})")
        else: self._log_status("  (未使用代理)")
        try:
            response = requests.get(url, headers=headers, proxies=proxies, timeout=15, verify=certifi.where())
            response.raise_for_status()
            raw_content = response.text
            self._log_status("內容下載成功，正在嘗試解析...")
            try: decoded_content = base64.b64decode(raw_content.strip()).decode('utf-8'); self._log_status("Base64 解碼成功。")
            except (base64.binascii.Error, UnicodeDecodeError): self._log_status("非 Base64 編碼，視為純文字格式。"); decoded_content = raw_content
            nodes = [node.strip() for node in decoded_content.splitlines() if node.strip()]
            self._log_status(f"成功解析出 {len(nodes)} 個節點。"); return nodes
        except requests.exceptions.ProxyError as e: self._log_status(f"錯誤：代理連線失敗。\n原因: {e}"); return[]
        except requests.exceptions.SSLError as e: self._log_status(f"錯誤：SSL 連線失敗。\n原因: {e}"); return []
        except requests.exceptions.RequestException as e: self._log_status(f"錯誤：無法從 {url} 獲取內容。\n原因: {e}"); return []
        except Exception as e: self._log_status(f"處理 {url} 時發生未知錯誤: {e}"); return []
    
    def filter_and_sort_nodes(self, nodes):
        self._log_status("\n正在對節點進行去重...")
        if not nodes: self._log_status("沒有節點可供處理。"); return []
        original_count = len(nodes)
        unique_nodes = list(dict.fromkeys(nodes))
        new_count = len(unique_nodes)
        self._log_status(f"去重完成。從 {original_count} 個節點中，保留了 {new_count} 個唯一節點。")
        return unique_nodes

    def generate_final_subscription(self, nodes, chunk_size=256):
        self._log_status("\n正在生成最終的通用訂閱檔案...")
        if not nodes: self._log_status("沒有節點可供生成訂閱。"); return
        full_content = "\n".join(nodes)
        encoded_content = base64.b64encode(full_content.encode('utf-8')).decode('utf-8')
        self._log_status("訂閱檔案生成完畢！開始以流式輸出...")
        for i in range(0, len(encoded_content), chunk_size):
            yield encoded_content[i:i + chunk_size]
            time.sleep(0.005)

# --- 圖形化介面 (GUI) ---
class AggregatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("代理聚合器 v1.9.1 (並發修正版)")
        self.root.geometry("850x850")
        
        self.result_queue = queue.Queue()
        self.stop_search_event = threading.Event()
        self.thread_lock = threading.Lock()
        self.executor = None
        
        self.aggregator = RealProxyAggregator(status_callback=self.log_to_gui)
        
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill="both", expand=True)
        main_frame.columnconfigure(0, weight=1); main_frame.rowconfigure(4, weight=1); main_frame.rowconfigure(5, weight=1)

        search_frame = ttk.LabelFrame(main_frame, text="線上搜索訂閱", padding="10")
        search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        search_frame.columnconfigure(1, weight=1)

        ttk.Label(search_frame, text="GitHub Token:").grid(row=0, column=0, padx=(0, 10), pady=(0, 5), sticky='w')
        self.github_token_entry = ttk.Entry(search_frame)
        self.github_token_entry.grid(row=0, column=1, columnspan=2, sticky="ew", pady=(0, 5))
        self.github_token_entry.insert(tk.END, "（可選，但強烈建議填寫以提高成功率）")

        ttk.Label(search_frame, text="搜索關鍵字 (,):").grid(row=1, column=0, padx=(0, 10), pady=(5, 5), sticky='w')
        self.search_query_entry = ttk.Entry(search_frame)
        self.search_query_entry.grid(row=1, column=1, columnspan=2, sticky="ew", pady=(5, 5))
        self.search_query_entry.insert(tk.END, "clash, quantumultx,v2ray,sub,SSR,vmess,trojan,vless")

        ttk.Label(search_frame, text="搜索頁數 (1-10):").grid(row=2, column=0, padx=(0, 10), pady=(5, 0), sticky='w')
        self.pages_spinbox = ttk.Spinbox(search_frame, from_=1, to=10, width=5)
        self.pages_spinbox.set(2)
        self.pages_spinbox.grid(row=2, column=1, sticky='w', pady=(5, 0))
        
        search_buttons_frame = ttk.Frame(search_frame)
        search_buttons_frame.grid(row=0, column=3, rowspan=3, padx=(15, 0), sticky='ns')
        self.search_button = ttk.Button(search_buttons_frame, text="開始並發搜索", command=self.run_search_thread)
        self.search_button.pack(fill='x', expand=True, ipady=5)
        self.stop_search_button = ttk.Button(search_buttons_frame, text="中止搜索", command=self.stop_search, state='disabled')
        self.stop_search_button.pack(fill='x', expand=True, ipady=5, pady=(5,0))
        
        sub_frame = ttk.LabelFrame(main_frame, text="訂閱連結 (一行一個)", padding="5")
        sub_frame.grid(row=1, column=0, sticky="ew", pady=(0, 5))
        self.sub_links_text = scrolledtext.ScrolledText(sub_frame, height=8, width=100, relief='solid', bd=1)
        self.sub_links_text.pack(fill='x', expand=True)

        proxy_frame = ttk.LabelFrame(main_frame, text="代理伺服器 (用於訪問訂閱和搜索)", padding="5")
        proxy_frame.grid(row=2, column=0, sticky="ew", pady=5)
        proxy_line_frame = ttk.Frame(proxy_frame); proxy_line_frame.pack(fill='x', expand=True, pady=2)
        self.proxy_enabled = tk.BooleanVar(value=False)
        self.proxy_checkbox = ttk.Checkbutton(proxy_line_frame, text="啟用代理", variable=self.proxy_enabled); self.proxy_checkbox.pack(side='left', padx=(0, 10))
        ttk.Label(proxy_line_frame, text="地址:").pack(side='left', padx=(0, 5))
        self.proxy_entry = ttk.Entry(proxy_line_frame); self.proxy_entry.pack(side='left', fill='x', expand=True); self.proxy_entry.insert(tk.END, "http://127.0.0.1:10809")

        control_frame = ttk.Frame(main_frame); control_frame.grid(row=3, column=0, pady=10)
        self.run_button = ttk.Button(control_frame, text="執行聚合處理", command=self.run_processing_thread); self.run_button.pack()

        log_frame = ttk.LabelFrame(main_frame, text="處理日誌", padding="5"); log_frame.grid(row=4, column=0, sticky="nsew", pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, state='disabled', wrap=tk.WORD); self.log_text.pack(fill='both', expand=True)
        
        result_frame = ttk.LabelFrame(main_frame, text="結果", padding="5"); result_frame.grid(row=5, column=0, sticky="nsew", pady=5)
        result_header = ttk.Frame(result_frame); result_header.pack(fill='x', anchor='n', pady=(0, 5))
        self.save_button = ttk.Button(result_header, text="儲存為檔案...", command=self.save_result_to_file); self.save_button.pack(side='right', anchor='ne')
        ttk.Label(result_header, text="通用訂閱格式 (Base64)").pack(side='left', anchor='nw')
        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD); self.result_text.pack(fill='both', expand=True)

        self.setup_context_menus()

    def setup_context_menus(self):
        TextWidgetContextMenu(self.github_token_entry); TextWidgetContextMenu(self.search_query_entry)
        TextWidgetContextMenu(self.sub_links_text); TextWidgetContextMenu(self.proxy_entry); TextWidgetContextMenu(self.result_text)

    def log_to_gui(self, message):
        self.root.after(0, self._append_log, message)

    def _append_log(self, message):
        self.log_text.config(state='normal'); self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state='disabled'); self.log_text.see(tk.END)

    def set_buttons_state(self, is_searching):
        if is_searching:
            self.search_button.config(state='disabled')
            self.stop_search_button.config(state='normal')
            self.run_button.config(state='disabled')
        else:
            self.search_button.config(state='normal')
            self.stop_search_button.config(state='disabled')
            self.run_button.config(state='normal')

    def process_result_queue(self):
        try:
            for _ in range(5):
                chunk = self.result_queue.get_nowait()
                if chunk is None:
                    self.log_to_gui("\n=== 處理完成 ===")
                    self.run_button.config(state='normal')
                    return
                else:
                    self.result_text.insert(tk.END, chunk)
            self.result_text.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(20, self.process_result_queue)

    def run_search_thread(self):
        self.stop_search_event.clear()
        self.set_buttons_state(is_searching=True)
        self.log_text.config(state='normal'); self.log_text.delete('1.0', tk.END); self.log_text.config(state='disabled')
        self.result_text.delete('1.0', tk.END)
        self.sub_links_text.delete('1.0', tk.END)
        thread = threading.Thread(target=self.search_and_populate, daemon=True)
        thread.start()
        
    def stop_search(self):
        self.log_to_gui("\n正在發送中止信號... 請等待當前任務完成。")
        self.stop_search_event.set()
        if self.executor:
            # This is a good-faith attempt to stop threads.
            self.executor.shutdown(wait=False, cancel_futures=True if sys.version_info >= (3, 9) else False)
        self.stop_search_button.config(state='disabled')

    def search_and_populate(self):
        self.executor = ThreadPoolExecutor(max_workers=20)
        try:
            github_token = self.github_token_entry.get().strip()
            if "（" in github_token: github_token = ""
            
            queries_str = self.search_query_entry.get().strip()
            queries = [q.strip() for q in queries_str.split(',') if q.strip()]
            
            try: pages = int(self.pages_spinbox.get())
            except ValueError: self.log_to_gui("錯誤：搜索頁數必須是有效整數。"); return
                
            if not queries: self.log_to_gui("錯誤：請至少輸入一個搜索關鍵字。"); return
            
            proxy_address = self.proxy_entry.get().strip() if self.proxy_enabled.get() else None
            
            finder = DynamicSubscriptionFinder(
                status_callback=self.log_to_gui, 
                proxy_address=proxy_address, 
                stop_event=self.stop_search_event,
                lock=self.thread_lock
            )
            found_links = finder.find(self.executor, github_token, queries, pages)
            
            if self.stop_search_event.is_set():
                self.log_to_gui("\n搜索任務已由用戶手動中止。")
            elif found_links:
                self.log_to_gui(f"\n將 {len(found_links)} 個連結填入訂閱連結欄...")
                unique_links = sorted(list(set(found_links)))
                def update_text(): self.sub_links_text.delete('1.0', tk.END); self.sub_links_text.insert('1.0', "\n".join(unique_links))
                self.root.after(0, update_text)
            else:
                self.log_to_gui("\n未找到任何可用的訂閱連結。")
            self.log_to_gui("\n=== 搜索結束 ===")
        except Exception as e:
            self.log_to_gui(f"搜索過程中發生嚴重錯誤: {e}\n{traceback.format_exc()}")
        finally:
            if self.executor:
                self.executor.shutdown(wait=False)
            self.executor = None
            self.root.after(0, self.set_buttons_state, False)

    def run_processing_thread(self):
        self.set_buttons_state(is_searching=True)
        self.log_text.config(state='normal'); self.log_text.delete('1.0', tk.END); self.log_text.config(state='disabled')
        self.result_text.delete('1.0', tk.END)
        thread = threading.Thread(target=self.process_subscriptions, daemon=True)
        thread.start()
        self.process_result_queue()

    def process_subscriptions(self):
        try:
            urls = self.sub_links_text.get('1.0', tk.END).strip().split('\n')
            urls = [url.strip() for url in urls if url.strip()]
            proxy_address = self.proxy_entry.get().strip() if self.proxy_enabled.get() else None
            if not urls: self.log_to_gui("錯誤：請至少輸入一個訂閱連結。"); self.result_queue.put(None); return

            self.log_to_gui("=== 開始聚合處理 ===")
            all_nodes = []
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_url = {executor.submit(self.aggregator.fetch_and_parse_url, url, proxy_address): url for url in urls}
                for future in as_completed(future_to_url):
                    try:
                        nodes_from_url = future.result()
                        if nodes_from_url:
                            all_nodes.extend(nodes_from_url)
                    except Exception as e:
                        self.log_to_gui(f"聚合一個連結時失敗: {e}")

            self.log_to_gui(f"\n總共獲取 {len(all_nodes)} 個初始節點。")
            unique_nodes = self.aggregator.filter_and_sort_nodes(all_nodes)
            
            for chunk in self.aggregator.generate_final_subscription(unique_nodes):
                self.result_queue.put(chunk)
            
        except Exception as e:
            self.log_to_gui(f"聚合過程中發生嚴重錯誤: {e}")
        finally:
            self.result_queue.put(None)

    def save_result_to_file(self):
        content = self.result_text.get('1.0', tk.END).strip()
        if not content: messagebox.showwarning("內容為空", "沒有可以儲存的內容。"); return
        file_path = filedialog.asksaveasfilename(title="儲存訂閱檔案", defaultextension=".txt", filetypes=[("文字檔案", "*.txt"), ("所有檔案", "*.*")])
        if not file_path: return
        try:
            with open(file_path, 'w', encoding='utf-8') as f: f.write(content)
            messagebox.showinfo("儲存成功", f"訂閱檔案已成功儲存至：\n{file_path}")
        except Exception as e:
            messagebox.showerror("儲存失敗", f"儲存檔案時發生錯誤：\n{e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AggregatorApp(root)
    root.mainloop()
