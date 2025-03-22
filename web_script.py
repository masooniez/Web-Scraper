import requests
import tkinter as tk
import threading
import re
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox  

# Global variable for cancellation
cancel_event = threading.Event()

# --------------------------
# Utility Functions
# --------------------------
def update_status(message):
    status_var.set(message)

def log_message(text):
    """Append text to the log text area."""
    log_text.config(state=tk.NORMAL)
    log_text.insert(tk.END, text)
    log_text.see(tk.END)
    log_text.config(state=tk.DISABLED)

def add_tree_result(test, method, payload, result):
    """Insert a vulnerability result into the treeview."""
    tree.insert("", tk.END, values=(test, method, payload, result))

def explain_vulnerability(vuln_type):
    """Return an explanation text for the vulnerability type."""
    explanations = {
        "SQL Injection": (
            "This may indicate that user inputs are not properly sanitized and an attacker could manipulate the backend SQL queries. "
            "However, similar errors can occur in non-vulnerable applications; further testing is advised.\n\n"
        ),
        "XSS": (
            "This suggests that unsanitized input may be reflected back to the browser, potentially allowing script execution. "
            "Sometimes benign behavior or error messages can trigger a false positive; manual verification is recommended.\n\n"
        ),
        "Command Injection": (
            "This may indicate that the application is vulnerable to shell command injection, posing a serious security risk. "
            "In some cases, benign responses might appear similar, so additional validation is required.\n\n"
        ),
    }
    return explanations.get(vuln_type, "")

# --------------------------
# Scanning Functions
# --------------------------
def scan_url(target_url, param):
    update_status(f"Scanning {target_url} ...")
    
    # Define payloads
    sql_payloads = [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "';--", "\";--",
        " OR 1=1--", " OR 'a'='a", " OR 1=1#"
    ]
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "\"/><script>alert('XSS')</script>",
        "'/><script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>"
    ]
    cmd_payloads = [
        "; ls", "|| ls", "& ls", "`ls`",
        "; cat /etc/passwd", "|| cat /etc/passwd", "& cat /etc/passwd", "`cat /etc/passwd`"
    ]
    
    # Compile regex patterns
    sql_error_pattern = re.compile(
        r"(SQL syntax|mysql_fetch|Warning|error in your SQL syntax|Unclosed quotation mark|Microsoft OLE DB Provider for SQL Server)",
        re.IGNORECASE
    )
    cmd_pattern = re.compile(r"root:.*:0:0", re.IGNORECASE)
    
    root.after(0, lambda: log_message(f"Scanning {target_url} using parameter '{param}'...\n\n"))
    
    # Calculate total tests: 2 methods per payload.
    total_tests = (len(sql_payloads) + len(xss_payloads) + len(cmd_payloads)) * 2
    progress_count = 0

    def update_progress():
        nonlocal progress_count
        progress_count += 1
        progress_percent = (progress_count / total_tests) * 100
        root.after(0, lambda: progress_bar.config(value=progress_percent))

    vulnerable_sql = False
    vulnerable_xss = False
    vulnerable_cmd = False

    # --- SQL Injection Test ---
    root.after(0, lambda: log_message("Testing for SQL Injection vulnerabilities (GET and POST):\n"))
    for method in ["GET", "POST"]:
        for payload in sql_payloads:
            if cancel_event.is_set():
                root.after(0, lambda: log_message("Scan canceled by user.\n"))
                root.after(0, scanning_complete)
                return
            try:
                response = (requests.get(target_url, params={param: payload}, timeout=5)
                            if method == "GET" else
                            requests.post(target_url, data={param: payload}, timeout=5))
                update_progress()
                content = response.text
                if re.search(sql_error_pattern, content):
                    msg = f"[!] Possible SQL Injection detected with {method} payload: {payload}\n"
                    msg += explain_vulnerability("SQL Injection")
                    root.after(0, lambda: log_message(msg))
                    root.after(0, lambda: add_tree_result("SQL Injection", method, payload, "Vulnerable"))
                    vulnerable_sql = True
                    break
            except Exception as e:
                update_progress()
                root.after(0, lambda: log_message(f"Error during {method} request with payload {payload}: {e}\n"))
    if not vulnerable_sql:
        root.after(0, lambda: log_message("[-] No SQL Injection vulnerabilities detected.\n\n"))
    
    # --- XSS Test ---
    root.after(0, lambda: log_message("Testing for XSS vulnerabilities (GET and POST):\n"))
    for method in ["GET", "POST"]:
        for payload in xss_payloads:
            if cancel_event.is_set():
                root.after(0, lambda: log_message("Scan canceled by user.\n"))
                root.after(0, scanning_complete)
                return
            try:
                response = (requests.get(target_url, params={param: payload}, timeout=5)
                            if method == "GET" else
                            requests.post(target_url, data={param: payload}, timeout=5))
                update_progress()
                content = response.text
                if payload in content:
                    msg = f"[!] Possible XSS detected with {method} payload: {payload}\n"
                    msg += explain_vulnerability("XSS")
                    root.after(0, lambda: log_message(msg))
                    root.after(0, lambda: add_tree_result("XSS", method, payload, "Vulnerable"))
                    vulnerable_xss = True
                    break
            except Exception as e:
                update_progress()
                root.after(0, lambda: log_message(f"Error during {method} request with payload {payload}: {e}\n"))
    if not vulnerable_xss:
        root.after(0, lambda: log_message("[-] No XSS vulnerabilities detected.\n\n"))
    
    # --- Command Injection Test ---
    root.after(0, lambda: log_message("Testing for Command Injection vulnerabilities (GET and POST):\n"))
    for method in ["GET", "POST"]:
        for payload in cmd_payloads:
            if cancel_event.is_set():
                root.after(0, lambda: log_message("Scan canceled by user.\n"))
                root.after(0, scanning_complete)
                return
            try:
                response = (requests.get(target_url, params={param: payload}, timeout=5)
                            if method == "GET" else
                            requests.post(target_url, data={param: payload}, timeout=5))
                update_progress()
                content = response.text
                if re.search(cmd_pattern, content):
                    msg = f"[!] Possible Command Injection detected with {method} payload: {payload}\n"
                    msg += explain_vulnerability("Command Injection")
                    root.after(0, lambda: log_message(msg))
                    root.after(0, lambda: add_tree_result("Command Injection", method, payload, "Vulnerable"))
                    vulnerable_cmd = True
                    break
            except Exception as e:
                update_progress()
                root.after(0, lambda: log_message(f"Error during {method} request with payload {payload}: {e}\n"))
    if not vulnerable_cmd:
        root.after(0, lambda: log_message("[-] No Command Injection vulnerabilities detected.\n\n"))
    
    root.after(0, lambda: log_message("Scanning complete.\n"))
    update_status("Scan complete")
    root.after(0, scanning_complete)

def scanning_complete():
    progress_bar.config(value=100)
    scan_button.config(state=NORMAL)
    cancel_button.config(state=DISABLED)
    update_status("Scan canceled" if cancel_event.is_set() else "Scan complete")

def start_scan():
    protocol = protocol_var.get().strip()
    target_url = url_entry.get().strip()
    param = param_entry.get().strip()
    
    # Validate inputs with centered error pop-ups using parent=root.
    if not protocol:
        Messagebox.show_error("Input Error", "Please select a protocol (http:// or https://).", parent=root)
        return
    if not target_url:
        Messagebox.show_error("Input Error", "Please enter a target URL.", parent=root)
        return
    if not param:
        Messagebox.show_error("Input Error", "Please enter a parameter.", parent=root)
        return
    
    # Auto-prepend protocol if missing
    if not (target_url.startswith("http://") or target_url.startswith("https://")):
        target_url = protocol + target_url

    # Clear previous logs and results
    for item in tree.get_children():
        tree.delete(item)
    log_text.config(state=NORMAL)
    log_text.delete("1.0", tk.END)
    log_text.config(state=DISABLED)
    
    progress_bar.config(mode="determinate", maximum=100, value=0)
    
    scan_button.config(state=DISABLED)
    cancel_button.config(state=NORMAL)
    cancel_event.clear()
    update_status("Scanning started...")
    
    threading.Thread(target=scan_url, args=(target_url, param), daemon=True).start()

def cancel_scan():
    cancel_event.set()
    update_status("Canceling scan...")
    cancel_button.config(state=DISABLED)

def toggle_fullscreen(event=None):
    root.attributes('-fullscreen', not root.attributes('-fullscreen'))

# --------------------------
# GUI Setup with ttkbootstrap
# --------------------------
style = ttk.Style("flatly")

root = style.master
root.title("Web Vulnerability Scanner")
root.geometry("900x600")

# --- Input Frame ---
input_frame = ttk.Frame(root, padding=10)
input_frame.pack(fill=X, padx=20, pady=10)

protocol_var = tk.StringVar(value="https://")
protocol_label = ttk.Label(input_frame, text="Protocol:")
protocol_label.grid(row=0, column=0, padx=5, pady=5, sticky=W)
protocol_menu = ttk.OptionMenu(input_frame, protocol_var, "https://", "https://", "http://")
protocol_menu.grid(row=0, column=1, padx=5, pady=5)

url_label = ttk.Label(input_frame, text="Target URL (e.g., youtube.com):")
url_label.grid(row=0, column=2, padx=5, pady=5, sticky=W)
url_entry = ttk.Entry(input_frame, width=40)
url_entry.grid(row=0, column=3, padx=5, pady=5, sticky=EW)

param_label = ttk.Label(input_frame, text="Parameter (e.g., q):")
param_label.grid(row=1, column=0, padx=5, pady=5, sticky=W)
param_entry = ttk.Entry(input_frame, width=40)
param_entry.grid(row=1, column=1, columnspan=3, padx=5, pady=5, sticky=EW)

input_frame.columnconfigure(3, weight=1)

# Bind the Enter key to start scan for URL and parameter entries.
url_entry.bind("<Return>", lambda event: start_scan())
param_entry.bind("<Return>", lambda event: start_scan())

# --- Control Frame ---
control_frame = ttk.Frame(root, padding=10)
control_frame.pack(fill=X, padx=20, pady=10)

scan_button = ttk.Button(control_frame, text="Scan", style="success.TButton", command=start_scan)
scan_button.grid(row=0, column=0, padx=5, pady=5, sticky=EW)

cancel_button = ttk.Button(control_frame, text="Cancel", style="danger.TButton", command=cancel_scan, state=DISABLED)
cancel_button.grid(row=0, column=1, padx=5, pady=5, sticky=EW)

progress_bar = ttk.Progressbar(control_frame, mode="determinate", maximum=100, value=0)
progress_bar.grid(row=0, column=2, padx=5, pady=5, sticky=EW)

control_frame.columnconfigure(0, weight=1)
control_frame.columnconfigure(1, weight=1)
control_frame.columnconfigure(2, weight=2)

# --- Output Frame ---
output_frame = ttk.Frame(root, padding=10)
output_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)

tree = ttk.Treeview(output_frame, columns=("Test", "Method", "Payload", "Result"), show="headings")
tree.heading("Test", text="Test")
tree.heading("Method", text="Method")
tree.heading("Payload", text="Payload")
tree.heading("Result", text="Result")
tree.pack(fill=BOTH, expand=True, side=TOP)

tree_scroll = ttk.Scrollbar(output_frame, orient=VERTICAL, command=tree.yview)
tree.configure(yscrollcommand=tree_scroll.set)
tree_scroll.pack(side=RIGHT, fill=Y)

log_text = tk.Text(output_frame, height=10, wrap=WORD, font=("Helvetica", 10))
log_text.pack(fill=X, pady=(10, 0))
log_text.config(state=DISABLED)

log_scroll = ttk.Scrollbar(output_frame, orient=VERTICAL, command=log_text.yview)
log_text.configure(yscrollcommand=log_scroll.set)
log_scroll.pack(side=RIGHT, fill=Y)

# --- Status Bar ---
status_var = tk.StringVar(value="Ready")
status_bar = ttk.Label(root, textvariable=status_var, relief="sunken", anchor=W, padding=10)
status_bar.pack(fill=X, side=BOTTOM)

root.mainloop()
