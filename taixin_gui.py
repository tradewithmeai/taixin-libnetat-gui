#!/usr/bin/env python3
"""
Taixin LibNetat GUI - Cross-platform graphical interface

A tkinter-based GUI wrapper for the Taixin LibNetat network analysis tool by aliosa27.
This GUI provides a user-friendly interface to the powerful command-line tools.

Original Taixin LibNetat Tool: https://github.com/aliosa27/taixin_tools
Author of original tool: aliosa27 (aliosa27@aliosa27.me)
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import time
import sys
import os
import platform
import json
import subprocess
from datetime import datetime

# Import from the original Taixin LibNetat Tool
try:
    # Try importing from installed package first
    import taixin_tools.libnetat as libnetat
    from taixin_tools.libnetat import ScapyNetAtMgr, WnbNetatCmd, get_network_interfaces
    from taixin_tools.libnetat import WNB_NETAT_CMD_SCAN_REQ, WNB_NETAT_CMD_SCAN_RESP, WNB_NETAT_CMD_AT_REQ, WNB_NETAT_CMD_AT_RESP
    from scapy.layers.inet import UDP, IP
    
    # Get the constants if available
    PRODUCTION_SET_COMMANDS = getattr(libnetat, 'PRODUCTION_SET_COMMANDS', [])
    PRODUCTION_GET_COMMANDS = getattr(libnetat, 'PRODUCTION_GET_COMMANDS', [])
    HAS_LIBNETAT = True
    
except ImportError:
    try:
        # Fallback: try to import directly (if taixin_tools is in path)
        import libnetat
        from libnetat import ScapyNetAtMgr, WnbNetatCmd, PRODUCTION_SET_COMMANDS, PRODUCTION_GET_COMMANDS, get_network_interfaces
        from libnetat import WNB_NETAT_CMD_SCAN_REQ, WNB_NETAT_CMD_SCAN_RESP, WNB_NETAT_CMD_AT_REQ, WNB_NETAT_CMD_AT_RESP
        from scapy.layers.inet import UDP, IP
        HAS_LIBNETAT = True
        
    except ImportError:
        try:
            # Last fallback: try subprocess approach
            result = subprocess.run([sys.executable, '-c', 'import libnetat'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                HAS_LIBNETAT = "subprocess"  # Use subprocess mode
            else:
                HAS_LIBNETAT = False
        except:
            HAS_LIBNETAT = False
            
# Fallback constants in case imports fail
if not HAS_LIBNETAT or HAS_LIBNETAT == "subprocess":
    WNB_NETAT_CMD_SCAN_REQ = 1
    WNB_NETAT_CMD_SCAN_RESP = 2  
    WNB_NETAT_CMD_AT_REQ = 3
    WNB_NETAT_CMD_AT_RESP = 4

class TaixinGUI:
    """
    Cross-platform GUI for the Taixin LibNetat Tool
    
    This GUI provides a user-friendly interface to interact with Taixin wireless devices
    using the excellent libnetat tool created by aliosa27.
    """
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Taixin LibNetat GUI - Powered by aliosa27's libnetat tool")
        self.root.geometry("1200x800")
        
        # Add attribution in window
        self.root.bind('<F1>', self.show_about)  # F1 for about dialog
        
        # Cross-platform styling
        self.setup_styles()
        
        # Initialize variables
        self.netat_mgr = None
        self.discovered_devices = {}
        self.selected_device = None
        self.scan_thread = None
        self.is_scanning = False
        self.auto_configuring = False
        
        # Message queue for thread communication
        self.message_queue = queue.Queue()
        
        # Create GUI
        self.create_widgets()
        self.setup_layout()
        
        # Start message processing
        self.process_messages()
        
        # Check dependency and show status
        self.check_dependencies()
        
        # Initialize with interface detection
        if HAS_LIBNETAT and HAS_LIBNETAT is not False:
            self.detect_interfaces()
        
    def show_about(self, event=None):
        """Show attribution dialog"""
        about_text = """Taixin LibNetat GUI

A cross-platform graphical interface for the Taixin LibNetat Tool.

Original Tool: https://github.com/aliosa27/taixin_tools
Original Author: aliosa27 (aliosa27@aliosa27.me)

This GUI is a wrapper that provides easy access to the powerful 
command-line tools created by aliosa27. All device communication 
and protocol handling is provided by the original project.

Press F1 to show this dialog anytime."""
        
        messagebox.showinfo("About Taixin LibNetat GUI", about_text)
        
    def check_dependencies(self):
        """Check if the original libnetat tool is available"""
        self.log_message(f"Checking dependencies - HAS_LIBNETAT: {HAS_LIBNETAT}")
        
        if not HAS_LIBNETAT:
            self.status_var.set("Missing dependency: Original libnetat tool not found")
            self.connection_var.set("Dependency Error")
            self.log_message("Original libnetat tool is not available")
            
            error_msg = """The original Taixin LibNetat Tool is not installed.

Please install it using:
pip install git+https://github.com/aliosa27/taixin_tools.git

Or manually:
1. git clone https://github.com/aliosa27/taixin_tools.git
2. cd taixin_tools
3. pip install -r requirements.txt (if available)

Then restart this GUI."""
            
            messagebox.showerror("Dependency Missing", error_msg)
        else:
            self.status_var.set("Ready - Original libnetat tool available")
            self.connection_var.set("Ready")
            self.log_message(f"Original libnetat tool is available (mode: {HAS_LIBNETAT})")
            
            # Test if we can import the functions we need
            try:
                # Test the imports
                if 'get_network_interfaces' in globals():
                    self.log_message("get_network_interfaces function is available")
                else:
                    self.log_message("WARNING: get_network_interfaces function not found in globals")
                    
                if 'ScapyNetAtMgr' in globals():
                    self.log_message("ScapyNetAtMgr class is available") 
                else:
                    self.log_message("WARNING: ScapyNetAtMgr class not found in globals")
                    
            except Exception as e:
                self.log_message(f"Error testing imports: {e}")
            
    def setup_styles(self):
        """Configure cross-platform compatible styles"""
        style = ttk.Style()
        
        # Use native look on each platform
        if platform.system() == "Windows":
            style.theme_use('winnative')
        elif platform.system() == "Darwin":  # macOS
            style.theme_use('aqua')
        else:  # Linux
            style.theme_use('clam')
            
        # Custom button styles
        style.configure('Scan.TButton', foreground='blue')
        style.configure('Send.TButton', foreground='green')
        style.configure('Stop.TButton', foreground='red')
        
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        
        # Tab 1: Device Discovery
        self.create_discovery_tab()
        
        # Tab 2: AT Commands
        self.create_at_commands_tab()
        
        # Tab 3: Configuration
        self.create_config_tab()
        
        # Tab 4: Logging
        self.create_logging_tab()
        
        # Status bar
        self.create_status_bar()
        
    def create_discovery_tab(self):
        """Create the device discovery tab"""
        self.discovery_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.discovery_frame, text="Device Discovery")
        
        # Attribution banner
        attr_frame = ttk.Frame(self.discovery_frame)
        attr_frame.pack(fill="x", padx=10, pady=5)
        attr_label = ttk.Label(attr_frame, 
                             text="Powered by the Taixin LibNetat Tool by aliosa27 • Press F1 for more info",
                             font=('TkDefaultFont', 8), foreground='gray')
        attr_label.pack()
        
        # Interface selection
        interface_frame = ttk.LabelFrame(self.discovery_frame, text="Network Interface", padding="10")
        interface_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(interface_frame, text="Interface:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.interface_var = tk.StringVar(value="auto")
        self.interface_combo = ttk.Combobox(interface_frame, textvariable=self.interface_var, width=50)
        self.interface_combo.grid(row=0, column=1, sticky="ew", padx=(0, 5))
        
        self.refresh_interfaces_btn = ttk.Button(interface_frame, text="Refresh", 
                                               command=self.refresh_interfaces)
        self.refresh_interfaces_btn.grid(row=0, column=2, padx=5)
        
        interface_frame.columnconfigure(1, weight=1)
        
        # Scan controls
        scan_frame = ttk.LabelFrame(self.discovery_frame, text="Device Scanning", padding="10")
        scan_frame.pack(fill="x", padx=10, pady=5)
        
        self.scan_btn = ttk.Button(scan_frame, text="Scan for Devices", 
                                 command=self.start_scan, style='Scan.TButton')
        self.scan_btn.pack(side="left", padx=(0, 10))
        
        self.stop_scan_btn = ttk.Button(scan_frame, text="Stop Scan", 
                                      command=self.stop_scan, style='Stop.TButton', state="disabled")
        self.stop_scan_btn.pack(side="left", padx=(0, 10))
        
        # Scan timeout
        ttk.Label(scan_frame, text="Timeout:").pack(side="left", padx=(20, 5))
        self.scan_timeout_var = tk.StringVar(value="8")
        scan_timeout_spin = ttk.Spinbox(scan_frame, from_=1, to=60, width=5, 
                                       textvariable=self.scan_timeout_var)
        scan_timeout_spin.pack(side="left", padx=(0, 5))
        ttk.Label(scan_frame, text="sec").pack(side="left")
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(scan_frame, variable=self.progress_var, mode='indeterminate')
        self.progress_bar.pack(side="right", fill="x", expand=True, padx=(20, 0))
        
        # Discovered devices
        devices_frame = ttk.LabelFrame(self.discovery_frame, text="Discovered Devices", padding="10")
        devices_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Device list
        columns = ("MAC Address", "Device Name", "Signal", "Channel")
        self.device_tree = ttk.Treeview(devices_frame, columns=columns, show="headings", height=10)
        
        for col in columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=150)
            
        # Scrollbar for device list
        device_scrollbar = ttk.Scrollbar(devices_frame, orient="vertical", command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=device_scrollbar.set)
        
        self.device_tree.pack(side="left", fill="both", expand=True)
        device_scrollbar.pack(side="right", fill="y")
        
        # Bind selection event
        self.device_tree.bind("<<TreeviewSelect>>", self.on_device_select)
        
    def create_at_commands_tab(self):
        """Create the AT commands tab"""
        self.at_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.at_frame, text="AT Commands")
        
        # Selected device info
        device_info_frame = ttk.LabelFrame(self.at_frame, text="Selected Device", padding="10")
        device_info_frame.pack(fill="x", padx=10, pady=5)
        
        self.selected_device_label = ttk.Label(device_info_frame, text="No device selected")
        self.selected_device_label.pack()
        
        # Command input
        command_frame = ttk.LabelFrame(self.at_frame, text="AT Command", padding="10")
        command_frame.pack(fill="x", padx=10, pady=5)
        
        # Quick commands
        quick_frame = ttk.Frame(command_frame)
        quick_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(quick_frame, text="Quick Commands:").pack(side="left")
        
        quick_commands = ["at+wnbcfg", "at+fwinfo?", "at+mode?", "at+ssid?", "at+channel?", "at+txpower?"]
        for cmd in quick_commands:
            btn = ttk.Button(quick_frame, text=cmd, command=lambda c=cmd: self.set_command(c))
            btn.pack(side="left", padx=2)
            
        # Command entry
        entry_frame = ttk.Frame(command_frame)
        entry_frame.pack(fill="x")
        
        ttk.Label(entry_frame, text="Command:").pack(side="left")
        self.command_var = tk.StringVar()
        self.command_entry = ttk.Entry(entry_frame, textvariable=self.command_var)
        self.command_entry.pack(side="left", fill="x", expand=True, padx=(5, 5))
        
        self.send_btn = ttk.Button(entry_frame, text="Send", command=self.send_command, 
                                 style='Send.TButton')
        self.send_btn.pack(side="right")
        
        # Bind Enter key to send command
        self.command_entry.bind("<Return>", lambda e: self.send_command())
        
        # Response display
        response_frame = ttk.LabelFrame(self.at_frame, text="Response", padding="10")
        response_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.response_text = scrolledtext.ScrolledText(response_frame, height=15, wrap=tk.WORD)
        self.response_text.pack(fill="both", expand=True)
        
    def create_config_tab(self):
        """Create the configuration tab"""
        self.config_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.config_frame, text="Configuration")
        
        # Create a scrollable frame for configuration options
        canvas = tk.Canvas(self.config_frame)
        scrollbar = ttk.Scrollbar(self.config_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # WiFi Configuration
        wifi_frame = ttk.LabelFrame(scrollable_frame, text="WiFi Configuration", padding="10")
        wifi_frame.pack(fill="x", padx=10, pady=5)
        
        # SSID
        ttk.Label(wifi_frame, text="SSID:").grid(row=0, column=0, sticky="w", padx=(0, 5), pady=2)
        self.ssid_var = tk.StringVar()
        ttk.Entry(wifi_frame, textvariable=self.ssid_var, width=30).grid(row=0, column=1, sticky="w", padx=5, pady=2)
        ttk.Button(wifi_frame, text="Get", command=lambda: self.get_config("ssid")).grid(row=0, column=2, padx=2, pady=2)
        ttk.Button(wifi_frame, text="Set", command=lambda: self.set_config("ssid", self.ssid_var.get())).grid(row=0, column=3, padx=2, pady=2)
        
        # Mode (Device uses 'role' parameter in WNBCFG)
        ttk.Label(wifi_frame, text="Mode:").grid(row=1, column=0, sticky="w", padx=(0, 5), pady=2)
        self.mode_var = tk.StringVar()
        # Use device's actual WIFIMODE values from AT command documentation
        mode_combo = ttk.Combobox(wifi_frame, textvariable=self.mode_var, values=["ap", "sta", "apsta"], width=27)
        mode_combo.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Button(wifi_frame, text="Get", command=lambda: self.get_config("mode")).grid(row=1, column=2, padx=2, pady=2)
        ttk.Button(wifi_frame, text="Set", command=lambda: self.set_config("mode", self.mode_var.get())).grid(row=1, column=3, padx=2, pady=2)
        
        # Channel (Index based on AT+CHAN_LIST)
        ttk.Label(wifi_frame, text="Channel:").grid(row=2, column=0, sticky="w", padx=(0, 5), pady=2)
        self.channel_var = tk.StringVar()
        # Channel indices that correspond to entries in AT+CHAN_LIST
        channel_indices = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16"]
        channel_combo = ttk.Combobox(wifi_frame, textvariable=self.channel_var, values=channel_indices, width=27)
        channel_combo.grid(row=2, column=1, sticky="w", padx=5, pady=2)
        ttk.Button(wifi_frame, text="Get", command=lambda: self.get_config("channel")).grid(row=2, column=2, padx=2, pady=2)
        ttk.Button(wifi_frame, text="Set", command=lambda: self.set_config("channel", self.channel_var.get())).grid(row=2, column=3, padx=2, pady=2)
        
        # TX Power
        ttk.Label(wifi_frame, text="TX Power:").grid(row=3, column=0, sticky="w", padx=(0, 5), pady=2)
        self.txpower_var = tk.StringVar()
        ttk.Spinbox(wifi_frame, from_=0, to=20, textvariable=self.txpower_var, width=28).grid(row=3, column=1, sticky="w", padx=5, pady=2)
        ttk.Button(wifi_frame, text="Get", command=lambda: self.get_config("txpower")).grid(row=3, column=2, padx=2, pady=2)
        ttk.Button(wifi_frame, text="Set", command=lambda: self.set_config("txpower", self.txpower_var.get())).grid(row=3, column=3, padx=2, pady=2)
        
        # Security Configuration
        security_frame = ttk.LabelFrame(scrollable_frame, text="Security Configuration", padding="10")
        security_frame.pack(fill="x", padx=10, pady=5)
        
        # Encryption (Device actually uses 'encrypt' parameter) 
        ttk.Label(security_frame, text="Encrypt:").grid(row=0, column=0, sticky="w", padx=(0, 5), pady=2)
        self.encrypt_var = tk.StringVar()
        encrypt_combo = ttk.Combobox(security_frame, textvariable=self.encrypt_var, 
                                   values=["0", "1"], width=27)
        encrypt_combo.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        ttk.Button(security_frame, text="Get", command=lambda: self.get_config("encrypt")).grid(row=0, column=2, padx=2, pady=2)
        ttk.Button(security_frame, text="Set", command=lambda: self.set_config("encrypt", self.encrypt_var.get())).grid(row=0, column=3, padx=2, pady=2)
        
        # Key (Device uses 'key' parameter, not 'psk')
        ttk.Label(security_frame, text="Key:").grid(row=1, column=0, sticky="w", padx=(0, 5), pady=2)
        self.key_var = tk.StringVar()
        key_entry = ttk.Entry(security_frame, textvariable=self.key_var, show="*", width=30)
        key_entry.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Button(security_frame, text="Get", command=lambda: self.get_config("key")).grid(row=1, column=2, padx=2, pady=2)
        ttk.Button(security_frame, text="Set", command=lambda: self.set_config("key", self.key_var.get())).grid(row=1, column=3, padx=2, pady=2)
        
        # BSS Bandwidth (Important HaLow parameter)
        ttk.Label(security_frame, text="BSS BW:").grid(row=2, column=0, sticky="w", padx=(0, 5), pady=2)
        self.bss_bw_var = tk.StringVar()
        bss_bw_combo = ttk.Combobox(security_frame, textvariable=self.bss_bw_var, 
                                   values=["1", "2", "4"], width=27)  # 1=1MHz, 2=2MHz, 4=4MHz
        bss_bw_combo.grid(row=2, column=1, sticky="w", padx=5, pady=2)
        ttk.Button(security_frame, text="Get", command=lambda: self.get_config("bss_bw")).grid(row=2, column=2, padx=2, pady=2)
        ttk.Button(security_frame, text="Set", command=lambda: self.set_config("bss_bw", self.bss_bw_var.get())).grid(row=2, column=3, padx=2, pady=2)
        
        # Advanced Configuration
        advanced_frame = ttk.LabelFrame(scrollable_frame, text="Advanced Configuration", padding="10")
        advanced_frame.pack(fill="x", padx=10, pady=5)
        
        # PAIR control (AT+PAIR)
        ttk.Label(advanced_frame, text="Pairing:").grid(row=0, column=0, sticky="w", padx=(0, 5), pady=2)
        self.pair_var = tk.StringVar()
        pair_combo = ttk.Combobox(advanced_frame, textvariable=self.pair_var, values=["0", "1", "2"], width=27)
        pair_combo.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(advanced_frame, text="(0=stop, 1=start, 2=group 2)", font=('TkDefaultFont', 8)).grid(row=0, column=2, columnspan=2, sticky="w", padx=5)
        
        ttk.Button(advanced_frame, text="Set", command=lambda: self.set_config("pair", self.pair_var.get())).grid(row=1, column=1, padx=2, pady=2)
        
        # AP Hide control (AT+APHIDE)  
        ttk.Label(advanced_frame, text="AP Hide:").grid(row=2, column=0, sticky="w", padx=(0, 5), pady=2)
        self.aphide_var = tk.StringVar()
        aphide_combo = ttk.Combobox(advanced_frame, textvariable=self.aphide_var, values=["0", "1"], width=27)
        aphide_combo.grid(row=2, column=1, sticky="w", padx=5, pady=2)
        ttk.Button(advanced_frame, text="Get", command=lambda: self.get_config("aphide")).grid(row=2, column=2, padx=2, pady=2)
        ttk.Button(advanced_frame, text="Set", command=lambda: self.set_config("aphide", self.aphide_var.get())).grid(row=2, column=3, padx=2, pady=2)
        
        # ACK Timeout (AT+ACK_TO)
        ttk.Label(advanced_frame, text="ACK Timeout:").grid(row=3, column=0, sticky="w", padx=(0, 5), pady=2)
        self.ack_to_var = tk.StringVar()
        ttk.Entry(advanced_frame, textvariable=self.ack_to_var, width=30).grid(row=3, column=1, sticky="w", padx=5, pady=2)
        ttk.Button(advanced_frame, text="Get", command=lambda: self.get_config("ack_to")).grid(row=3, column=2, padx=2, pady=2)
        ttk.Button(advanced_frame, text="Set", command=lambda: self.set_config("ack_to", self.ack_to_var.get())).grid(row=3, column=3, padx=2, pady=2)
        
        # Auto-configuration from device
        auto_frame = ttk.LabelFrame(scrollable_frame, text="Auto Configuration", padding="10")
        auto_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(auto_frame, text="Get current device configuration:").pack(side="left")
        ttk.Button(auto_frame, text="Auto Configure from Device", 
                 command=self.auto_configure_device, style='Scan.TButton').pack(side="left", padx=10)
        
        # Configuration file operations
        file_frame = ttk.LabelFrame(scrollable_frame, text="Configuration Files", padding="10")
        file_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(file_frame, text="Save Configuration", command=self.save_config_file).pack(side="left", padx=5)
        ttk.Button(file_frame, text="Load Configuration", command=self.load_config_file).pack(side="left", padx=5)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    def create_logging_tab(self):
        """Create the logging tab"""
        self.logging_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.logging_frame, text="Logging")
        
        # Logging controls
        control_frame = ttk.LabelFrame(self.logging_frame, text="Logging Controls", padding="10")
        control_frame.pack(fill="x", padx=10, pady=5)
        
        self.logging_enabled_var = tk.BooleanVar(value=True)  # Enable by default
        ttk.Checkbutton(control_frame, text="Enable Logging", 
                       variable=self.logging_enabled_var).pack(side="left")
        
        ttk.Button(control_frame, text="Clear Log", command=self.clear_log).pack(side="left", padx=10)
        ttk.Button(control_frame, text="Save Log", command=self.save_log).pack(side="left", padx=5)
        
        # Log display
        log_frame = ttk.LabelFrame(self.logging_frame, text="Log Output", padding="10")
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, wrap=tk.WORD)
        self.log_text.pack(fill="both", expand=True)
        
        # Add initial log message about attribution
        self.log_message("Taixin LibNetat GUI started")
        self.log_message("Powered by the original Taixin LibNetat Tool by aliosa27")
        self.log_message("Original project: https://github.com/aliosa27/taixin_tools")
        self.log_message(f"Python version: {sys.version}")
        self.log_message(f"Platform: {platform.system()} {platform.release()}")
        
        # Log import status
        try:
            import scapy
            self.log_message(f"Scapy version: {scapy.VERSION}")
        except:
            self.log_message("Scapy version: Unknown")
            
        self.log_message(f"LibNetat integration status: {HAS_LIBNETAT}")
        
    def create_status_bar(self):
        """Create the status bar"""
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(fill="x", side="bottom")
        
        self.status_var = tk.StringVar(value="Initializing...")
        self.status_label = ttk.Label(self.status_frame, textvariable=self.status_var, relief="sunken")
        self.status_label.pack(side="left", fill="x", expand=True, padx=2, pady=1)
        
        # Connection status
        self.connection_var = tk.StringVar(value="Checking dependencies...")
        self.connection_label = ttk.Label(self.status_frame, textvariable=self.connection_var, relief="sunken")
        self.connection_label.pack(side="right", padx=2, pady=1)
        
    def setup_layout(self):
        """Setup the main window layout"""
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
    def detect_interfaces(self):
        """Detect available network interfaces using the original tool"""
        try:
            if HAS_LIBNETAT and HAS_LIBNETAT is not False and HAS_LIBNETAT != "subprocess":
                # Use the get_network_interfaces function from libnetat
                try:
                    # Call the standalone function (not a method on ScapyNetAtMgr)
                    interfaces = get_network_interfaces()
                    self.log_message(f"Found {len(interfaces)} network interfaces")
                except NameError as ne:
                    self.log_message(f"get_network_interfaces not available: {ne}")
                    # Fallback to scapy directly
                    try:
                        from scapy.arch import get_if_list
                        interfaces = get_if_list()
                        self.log_message(f"Using scapy get_if_list: found {len(interfaces)} interfaces")
                    except Exception as se:
                        self.log_message(f"Scapy fallback failed: {se}")
                        interfaces = ["auto"]
                except Exception as ge:
                    self.log_message(f"get_network_interfaces failed: {ge}")
                    # Fallback to scapy directly
                    try:
                        from scapy.arch import get_if_list
                        interfaces = get_if_list()
                        self.log_message(f"Using scapy get_if_list fallback: found {len(interfaces)} interfaces")
                    except Exception as se:
                        self.log_message(f"All interface detection failed: {se}")
                        interfaces = ["auto"]
                
                interface_list = ["auto"]
                for iface in interfaces:
                    if iface != "auto":  # Don't duplicate auto
                        # Add interface name, try to get IP info if possible
                        try:
                            from scapy.arch import get_if_addr
                            ip = get_if_addr(iface)
                            if ip and ip != '0.0.0.0' and ip != '127.0.0.1':
                                interface_list.append(f"{iface} - {ip}")
                            else:
                                interface_list.append(iface)
                        except:
                            interface_list.append(iface)
                
                self.interface_combo['values'] = interface_list
                self.log_message(f"Network interfaces loaded: {len(interface_list)} total (including auto)")
                
            elif HAS_LIBNETAT == "subprocess":
                # Use subprocess to call the original tool
                self.log_message("Using subprocess mode to access libnetat")
                self.interface_combo['values'] = ["auto", "eth0", "wlan0", "en0", "wlan1"]
                
            else:
                self.log_message("Original libnetat tool not available - using fallback interfaces")
                # Try to get basic interface list from scapy if available
                try:
                    from scapy.arch import get_if_list
                    scapy_interfaces = get_if_list()
                    interface_list = ["auto"] + scapy_interfaces[:5]  # Limit to first 5
                    self.interface_combo['values'] = interface_list
                    self.log_message(f"Using scapy-only interface detection: {len(interface_list)} interfaces")
                except:
                    self.interface_combo['values'] = ["auto", "eth0", "wlan0", "en0", "wlan1"]
                    self.log_message("Using hardcoded fallback interfaces")
                
        except Exception as e:
            self.log_message(f"Error detecting interfaces: {e}")
            self.log_message(f"Exception type: {type(e).__name__}")
            import traceback
            self.log_message(f"Stack trace: {traceback.format_exc()}")
            self.interface_combo['values'] = ["auto"]
            
    def refresh_interfaces(self):
        """Refresh the interface list and provide user feedback"""
        self.log_message("Refreshing network interfaces...")
        self.status_var.set("Refreshing interfaces...")
        
        # Save current selection
        current_selection = self.interface_var.get()
        
        try:
            # Temporarily disable the button and change text
            self.refresh_interfaces_btn.config(state="disabled", text="Refreshing...")
            self.root.update()  # Force GUI update
            
            # Call the detection method
            self.detect_interfaces()
            
            # Try to restore the previous selection if it still exists
            new_values = self.interface_combo['values']
            if current_selection in new_values:
                self.interface_var.set(current_selection)
                self.log_message(f"Restored previous selection: {current_selection}")
            else:
                # If previous selection no longer exists, try to find a similar one
                for value in new_values:
                    if current_selection != "auto" and current_selection.split(" - ")[0] in value:
                        self.interface_var.set(value)
                        self.log_message(f"Updated selection to: {value}")
                        break
                else:
                    # Fall back to auto
                    self.interface_var.set("auto")
                    self.log_message("Fell back to 'auto' selection")
            
            self.log_message(f"Interface refresh completed - found {len(new_values)} interfaces")
            self.status_var.set("Interface refresh completed")
            
        except Exception as e:
            self.log_message(f"Error during interface refresh: {e}")
            self.status_var.set("Interface refresh failed")
            messagebox.showerror("Refresh Error", f"Failed to refresh interfaces:\n{e}")
            
        finally:
            # Always re-enable the button and restore text
            self.refresh_interfaces_btn.config(state="normal", text="Refresh")
            
    def start_scan(self):
        """Start device scanning using the original tool"""
        if not HAS_LIBNETAT:
            messagebox.showerror("Dependency Missing", 
                               "Cannot scan: Original libnetat tool is not installed.\n\n" +
                               "Please install it using:\n" +
                               "pip install git+https://github.com/aliosa27/taixin_tools.git")
            return
            
        if self.is_scanning:
            return
            
        interface = self.interface_var.get()
        clean_interface = self._extract_interface_name(interface)
        timeout = int(self.scan_timeout_var.get())
        
        self.is_scanning = True
        self.scan_btn.config(state="disabled")
        self.stop_scan_btn.config(state="normal")
        self.progress_bar.start()
        
        self.log_message(f"Starting device scan using original libnetat tool")
        self.log_message(f"Selected interface: '{interface}' -> Clean interface: '{clean_interface}'")
        self.log_message(f"Scan timeout: {timeout} seconds")
        self.status_var.set("Scanning for devices...")
        
        # Clear previous results
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        self.discovered_devices.clear()
        
        # Start scan in background thread with clean interface name
        self.scan_thread = threading.Thread(target=self._scan_worker, 
                                          args=(clean_interface, timeout), daemon=True)
        self.scan_thread.start()
        
    def _scan_worker(self, interface, timeout):
        """Background worker for device scanning"""
        try:
            if HAS_LIBNETAT and HAS_LIBNETAT is not False and HAS_LIBNETAT != "subprocess":
                # Extract just the interface name (remove IP info if present)
                clean_interface = self._extract_interface_name(interface)
                self.log_message(f"Using interface '{clean_interface}' (extracted from '{interface}')")
                
                # Use the original libnetat tool directly
                self.netat_mgr = ScapyNetAtMgr(clean_interface, debug=True, scan_timeout=timeout)
                
                # Start packet capture before scanning
                self.log_message("Starting packet capture...")
                try:
                    self.netat_mgr.start_packet_capture()
                    self.log_message("Packet capture started successfully")
                except Exception as e:
                    self.log_message(f"Failed to start packet capture: {e}")
                    self.message_queue.put(("scan_error", f"Failed to start packet capture: {e}"))
                    return
                
                # Clear any previous packets
                self.netat_mgr.captured_packets.clear()
                self.log_message("Cleared previous captured packets")
                
                # Send scan packets
                self.log_message("Sending NETAT scan packets...")
                try:
                    scan_success = self.netat_mgr.netat_scan(retries=3, retry_delay=0.5)
                    self.log_message(f"Scan packet sending result: {scan_success}")
                except Exception as e:
                    self.log_message(f"Exception during netat_scan: {e}")
                    self.message_queue.put(("scan_error", f"Failed to send scan packets: {e}"))
                    return
                
                if not scan_success:
                    self.message_queue.put(("scan_error", "Failed to send scan packets - check interface name and network permissions"))
                    return
                
                # Wait for responses with periodic checks
                start_time = time.time()
                devices_found = []
                packet_count = 0
                
                self.log_message(f"Waiting for scan responses for {timeout} seconds...")
                
                while time.time() - start_time < timeout:
                    current_packet_count = len(self.netat_mgr.captured_packets)
                    if current_packet_count != packet_count:
                        self.log_message(f"Captured packets: {current_packet_count} (new: {current_packet_count - packet_count})")
                        packet_count = current_packet_count
                    
                    # Process captured packets for NETAT scan responses
                    for packet in self.netat_mgr.captured_packets[:]:
                        try:
                            # Check if this is a UDP packet on our NETAT port
                            if packet.haslayer(UDP) and packet[UDP].dport == self.netat_mgr.port:
                                payload = bytes(packet[UDP].payload)
                                
                                # Add comprehensive debugging
                                src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
                                self.log_message(f"=== Processing NETAT packet ===")
                                self.log_message(f"Source IP: {src_ip}")
                                self.log_message(f"Payload size: {len(payload)} bytes")
                                self.log_message(f"Payload hex: {payload.hex()}")
                                
                                # Must be at least 15 bytes for valid NETAT packet (header)
                                if len(payload) >= 15:
                                    try:
                                        # Parse using original NETAT protocol
                                        cmd = WnbNetatCmd.from_bytes(payload)
                                        
                                        self.log_message(f"Parsed NETAT command:")
                                        self.log_message(f"  Command: {cmd.cmd} (expecting {WNB_NETAT_CMD_SCAN_RESP})")
                                        self.log_message(f"  Dest: {cmd.dest.hex()} (our cookie: {self.netat_mgr.cookie.hex()})")
                                        self.log_message(f"  Src: {cmd.src.hex()}")
                                        self.log_message(f"  Data length: {len(cmd.data)} bytes")
                                        
                                        # Check if this is a scan response to our request
                                        if (cmd.cmd == WNB_NETAT_CMD_SCAN_RESP and 
                                            cmd.dest == self.netat_mgr.cookie):
                                            
                                            # Extract device MAC address from packet source field
                                            device_mac_bytes = cmd.src
                                            device_mac = ':'.join(f'{b:02x}' for b in device_mac_bytes)
                                            
                                            self.log_message(f"*** FOUND TAIXIN DEVICE ***")
                                            self.log_message(f"Device MAC: {device_mac}")
                                            
                                            # Create device info
                                            device_info = {
                                                'mac': device_mac,
                                                'name': f'Taixin-{device_mac.replace(":", "")[-6:]}',
                                                'signal': 'Strong',
                                                'channel': 'Unknown'
                                            }
                                            
                                            # Add to discovered devices if not already present
                                            if device_mac not in [d['mac'] for d in devices_found]:
                                                devices_found.append(device_info)
                                                self.message_queue.put(("device_found", device_info))
                                                self.log_message(f"Added device to list: {device_info['name']} ({device_mac})")
                                            else:
                                                self.log_message(f"Device {device_mac} already discovered")
                                        else:
                                            if cmd.cmd != WNB_NETAT_CMD_SCAN_RESP:
                                                self.log_message(f"Not a scan response (cmd={cmd.cmd})")
                                            if cmd.dest != self.netat_mgr.cookie:
                                                self.log_message(f"Not our cookie (got {cmd.dest.hex()})")
                                                
                                    except Exception as e:
                                        self.log_message(f"Failed to parse as NETAT packet: {e}")
                                        self.log_message(f"Raw payload: {payload[:20].hex()}...")
                                else:
                                    self.log_message(f"Packet too short ({len(payload)} bytes, need >=15)")
                                
                                # Remove processed packet
                                self.netat_mgr.captured_packets.remove(packet)
                                
                            else:
                                # Not a NETAT packet, log for debugging
                                if hasattr(packet, 'load') and len(packet.load) > 0:
                                    self.log_message(f"Non-NETAT packet: {len(packet.load)} bytes")
                                    
                        except Exception as e:
                            # Log problematic packets for debugging
                            self.log_message(f"Error processing packet: {e}")
                            continue
                    
                    # Short sleep to prevent busy waiting
                    time.sleep(0.2)  # Slightly longer for better logging
                
                self.log_message(f"Scan completed. Total devices found: {len(devices_found)}")
                self.log_message(f"Final captured packet count: {len(self.netat_mgr.captured_packets)}")
                
                self.message_queue.put(("scan_complete", len(devices_found)))
                
                # Stop packet capture to clean up
                try:
                    if hasattr(self.netat_mgr, 'stop_packet_capture'):
                        self.netat_mgr.stop_packet_capture()
                        self.log_message("Packet capture stopped")
                except Exception as e:
                    self.log_message(f"Error stopping packet capture: {e}")
                
            else:
                # Mock scanning for testing
                self.log_message("Running in demo mode - original tool not available")
                time.sleep(2)
                
                mock_devices = [
                    {'mac': '02:40:49:7c:a7:40', 'ip': '192.168.1.100', 'info': 'Demo Taixin Device 1', 'signal': '-45 dBm'},
                    {'mac': '02:40:49:83:4c:58', 'ip': '192.168.1.101', 'info': 'Demo Taixin Device 2', 'signal': '-52 dBm'}
                ]
                
                for device in mock_devices:
                    self.message_queue.put(("device_found", device))
                    time.sleep(0.5)
                    
                self.message_queue.put(("scan_complete", len(mock_devices)))
                
        except Exception as e:
            import traceback
            error_details = f"{str(e)}\n\nFull traceback:\n{traceback.format_exc()}"
            self.message_queue.put(("scan_error", error_details))
            
    def stop_scan(self):
        """Stop device scanning"""
        self.is_scanning = False
        self.scan_btn.config(state="normal")
        self.stop_scan_btn.config(state="disabled")
        self.progress_bar.stop()
        self.status_var.set("Scan stopped")
        self.log_message("Device scan stopped by user")
        
    def on_device_select(self, event):
        """Handle device selection and auto-configure"""
        selection = self.device_tree.selection()
        if selection:
            item = self.device_tree.item(selection[0])
            values = item['values']
            
            if values:
                # Use correct data structure: ("MAC Address", "Device Name", "Signal", "Channel")
                self.selected_device = {
                    'mac': values[0],
                    'name': values[1] if len(values) > 1 else 'Unknown',
                    'signal': values[2] if len(values) > 2 else 'Unknown',
                    'channel': values[3] if len(values) > 3 else 'Unknown'
                }
                
                device_text = f"Selected: {self.selected_device['mac']} - {self.selected_device['name']}"
                self.selected_device_label.config(text=device_text + " (Auto-configuring...)")
                self.log_message(f"Selected device: {self.selected_device['mac']}")
                
                # Automatically fetch device configuration
                self.auto_configure_device()
                
    def set_command(self, command):
        """Set a command in the command entry"""
        self.command_var.set(command)
        
    def send_command(self):
        """Send AT command to selected device using the original tool"""
        if not self.selected_device:
            messagebox.showwarning("No Device", "Please select a device first")
            return
            
        command = self.command_var.get().strip()
        if not command:
            messagebox.showwarning("No Command", "Please enter a command")
            return
            
        if not HAS_LIBNETAT or HAS_LIBNETAT is False:
            messagebox.showerror("Dependency Missing", 
                               "Cannot send command: Original libnetat tool is not installed.")
            return
            
        self.log_message(f"Sending '{command}' to {self.selected_device['mac']} using original libnetat")
        self.status_var.set("Sending command...")
        
        # Send command in background thread
        threading.Thread(target=self._send_command_worker, 
                        args=(command, self.selected_device['mac']), daemon=True).start()
        
    def _extract_interface_name(self, interface_string):
        """Extract just the interface name from formatted string like 'en7 - 10.10.1.2'"""
        if interface_string == "auto":
            return "auto"
        
        # If it contains " - ", split and take the first part
        if " - " in interface_string:
            return interface_string.split(" - ")[0].strip()
        
        # Otherwise return as-is
        return interface_string
    
    def _send_command_worker(self, command, dest_mac):
        """Background worker for sending commands"""
        try:
            if HAS_LIBNETAT and HAS_LIBNETAT != "subprocess" and self.netat_mgr:
                self.log_message(f"Sending command '{command}' to device {dest_mac}")
                # Convert MAC address string to bytes if needed
                if isinstance(dest_mac, str):
                    if ':' in dest_mac:
                        # Convert "aa:bb:cc:dd:ee:ff" to bytes
                        dest_bytes = bytes.fromhex(dest_mac.replace(':', ''))
                    else:
                        # Assume it's already in the right format
                        dest_bytes = dest_mac.encode()
                else:
                    dest_bytes = dest_mac
                
                # Set the destination MAC
                self.log_message(f"Setting destination MAC: {dest_mac} -> {dest_bytes.hex()}")
                self.netat_mgr.dest = dest_bytes
                
                # Use increased timeout for complex commands
                timeout = 10 if command.lower() == "at+wnbcfg" else 8
                self.log_message(f"Using timeout: {timeout} seconds for command: {command}")
                
                # Add debugging for packet capture status
                self.log_message(f"Packet capture active: {hasattr(self.netat_mgr, 'capture_thread') and self.netat_mgr.capture_thread and self.netat_mgr.capture_thread.is_alive()}")
                self.log_message(f"Captured packets before: {len(self.netat_mgr.captured_packets)}")
                
                # Start packet capture if not already running
                if not (hasattr(self.netat_mgr, 'capture_thread') and self.netat_mgr.capture_thread and self.netat_mgr.capture_thread.is_alive()):
                    self.log_message("Starting packet capture for AT command")
                    self.netat_mgr.start_packet_capture()
                    time.sleep(0.2)  # Small delay to ensure capture is running
                
                # Send AT command using original tool's method
                self.log_message(f"Sending AT command: {command}")
                self.netat_mgr.netat_send(command, retries=2, retry_delay=0.3)
                
                # Use the original proven wait_for_responses method
                self.log_message("Waiting for AT command responses using original method...")
                devices, responses = self.netat_mgr.wait_for_responses(
                    timeout_seconds=timeout, 
                    early_exit_for_commands=True, 
                    selected_device_only=True
                )
                
                self.log_message(f"Response collection completed. Devices: {len(devices)}, Responses: {len(responses)}")
                
                # Process responses
                if responses:
                    # Combine multiple response parts if any
                    combined_response = "".join(responses)
                    self.log_message(f"*** GOT AT RESPONSES ***")
                    self.log_message(f"Combined response: {combined_response[:200]}...")
                    self.message_queue.put(("command_response", combined_response))
                else:
                    self.log_message("No responses received within timeout period")
                    self.message_queue.put(("command_response", f"No response received (timeout after {timeout}s)"))
                
            else:
                # Mock response with realistic WNBCFG example
                time.sleep(1)
                if command.upper() == "AT+WNBCFG":
                    mock_response = "+WNBCFG\n" + \
                                  "role:ap, bss_bw:2, encrypt:1, forward:1, key_set:1, mkey_set:0, join_group:0, bssid_set:0\n" + \
                                  "freq_range:0~0\n" + \
                                  "chan_list: 8640, 8660,\n" + \
                                  "ssid:0240497ca740, r_ssid:, addr:02:40:49:7c:a7:40\n" + \
                                  "max_sta:8, tx_mcs:255, acs_enable:1, acs_tmo:0, tx_bw:2\n" + \
                                  "tx_power:0, pri_chan:3\n" + \
                                  "psconnect_period:60, psconnect_roundup:4\n" + \
                                  "wkio_mode:0, psmode:0, auto_chsw:0, acktmo:0\n" + \
                                  "bss_max_idle:300, beacon_int:500, dtim_period:2\n" + \
                                  "group_aid:0, agg_cnt:0, aplost_time:10, roam_rssi_th:-65, roam_int:10\n" + \
                                  "dhcpc_en:0, dhcp_host:, ack_tmo:0, reassoc_wkhost:0, mcast_filter:0\n" + \
                                  "STA0:[02:40:49:83:4c:58, pair:1, encrypt:1, connect:0]\n" + \
                                  "psk:40a77c4902    auto_role:1, roaming:0, dupfilter:0, pa_pwrctrl_dis:0, pair_autostop:0, supper_pwr_dis:0\n" + \
                                  "not_auto_save:0, dcdc13:0, auto_pair:0, heartbeat_int:500, auto_sleep_time:10000, wkup_io:0, wkio_edge:0\n" + \
                                  "\n(Demo mode - install original tool for real functionality)"
                else:
                    mock_response = f"Demo response for '{command}' from {dest_mac}\n" + \
                                  f"Status: OK (using demo mode - install original tool for real functionality)"
                self.message_queue.put(("command_response", mock_response))
                
        except Exception as e:
            import traceback
            error_details = f"{str(e)}\n\nFull traceback:\n{traceback.format_exc()}"
            self.message_queue.put(("command_error", error_details))
            
    def get_config(self, param):
        """Get configuration parameter with proper AT command mapping"""
        # Map GUI parameter names to actual AT command names
        param_mapping = {
            'mode': 'wifimode',  # Use AT+WIFIMODE based on documentation
            'channel': 'chan_list',  # Device uses 'chan_list' AT command, not 'channel'
            'ssid': 'ssid',
            'txpower': 'txpower',
            'encrypt': 'encrypt',  # Device uses 'encrypt' parameter
            'key': 'key',  # Device uses 'key' parameter  
            'bss_bw': 'bss_bw',  # Important HaLow bandwidth parameter
            'pair': 'pair',  # AT+PAIR pairing control
            'aphide': 'aphide',  # AT+APHIDE hide AP
            'ack_to': 'ack_to'  # AT+ACK_TO timeout setting
        }
        
        actual_param = param_mapping.get(param, param)
        
        # Validate that this is a supported GET command
        if actual_param not in PRODUCTION_GET_COMMANDS:
            self.log_message(f"Warning: {actual_param} not in supported GET commands")
            self.log_message(f"Supported GET commands: {', '.join(PRODUCTION_GET_COMMANDS[:10])}...")
        
        command = f"at+{actual_param}?"
        self.log_message(f"Getting {param} -> {command}")
        self.command_var.set(command)
        self.send_command()
        
    def set_config(self, param, value):
        """Set configuration parameter with validation and mapping"""
        if not value:
            messagebox.showwarning("No Value", f"Please enter a value for {param}")
            return
        
        # Map GUI parameter names to actual AT command names
        param_mapping = {
            'mode': 'wifimode',  # Use AT+WIFIMODE based on documentation
            'channel': 'chan_list',  # Device uses 'chan_list' AT command, not 'channel'
            'ssid': 'ssid',
            'txpower': 'txpower', 
            'encrypt': 'encrypt',  # Device uses 'encrypt' parameter
            'key': 'key',  # Device uses 'key' parameter
            'bss_bw': 'bss_bw',  # Important HaLow bandwidth parameter
            'pair': 'pair',  # AT+PAIR pairing control  
            'aphide': 'aphide',  # AT+APHIDE hide AP
            'ack_to': 'ack_to'  # AT+ACK_TO timeout setting
        }
        
        actual_param = param_mapping.get(param, param)
        
        # Special handling for channel - we need to handle chan_list differently
        if param == 'channel':
            # For channel setting, we need to set both chan_list and channel index
            self.set_channel_config(value)
            return
        
        # Validate that this is a supported SET command
        if actual_param not in PRODUCTION_SET_COMMANDS:
            messagebox.showerror("Unsupported Command", 
                               f"Parameter '{actual_param}' is not supported by the device.\n"
                               f"Supported SET commands: {', '.join(PRODUCTION_SET_COMMANDS[:15])}...")
            return
        
        
        # Validate mode values based on AT+WIFIMODE documentation
        if param == 'mode':
            valid_modes = ["ap", "sta", "apsta"]  # Valid AT+WIFIMODE values
            if value not in valid_modes:
                messagebox.showerror("Invalid Mode", f"Mode must be one of: {', '.join(valid_modes)}")
                return
            
        command = f"at+{actual_param}={value}"
        self.log_message(f"Setting {param} = {value} -> {command}")
        self.command_var.set(command)
        self.send_command()
        
    def set_channel_config(self, channel_index):
        """Set channel using AT+CHANNEL command with index from chan_list"""
        try:
            # Validate channel index
            channel_idx = int(channel_index)
            if channel_idx < 1 or channel_idx > 16:
                messagebox.showerror("Invalid Channel", "Channel index must be between 1-16")
                return
                
            # Use AT+CHANNEL command per documentation
            command = f"at+channel={channel_idx}"
            self.log_message(f"Setting channel index {channel_idx} -> {command}")
            self.command_var.set(command)
            self.send_command()
            
        except ValueError:
            messagebox.showerror("Invalid Channel", "Channel must be a number (1-16)")
            
    def save_config_file(self):
        """Save configuration to file"""
        filename = filedialog.asksaveasfilename(
            title="Save Configuration",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            command = f"saveconfig {filename}"
            self.command_var.set(command)
            self.send_command()
            
    def load_config_file(self):
        """Load configuration from file"""
        filename = filedialog.askopenfilename(
            title="Load Configuration",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            command = f"loadconfig {filename}"
            self.command_var.set(command)
            self.send_command()
            
    def log_message(self, message):
        """Add message to log"""
        if self.logging_enabled_var.get():
            timestamp = datetime.now().strftime("%H:%M:%S")
            log_entry = f"[{timestamp}] {message}\n"
            self.log_text.insert(tk.END, log_entry)
            self.log_text.see(tk.END)
            
    def clear_log(self):
        """Clear the log display"""
        self.log_text.delete(1.0, tk.END)
        self.log_message("Log cleared")
        self.log_message("Powered by the original Taixin LibNetat Tool by aliosa27")
        
    def save_log(self):
        """Save log to file"""
        filename = filedialog.asksaveasfilename(
            title="Save Log",
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Log saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save log: {e}")
                
    def process_messages(self):
        """Process messages from background threads"""
        try:
            while True:
                msg_type, data = self.message_queue.get_nowait()
                
                if msg_type == "device_found":
                    # Add device to tree
                    self.device_tree.insert("", "end", values=(
                        data['mac'], data.get('name', 'Unknown'), data['signal'], data.get('channel', 'Unknown')
                    ))
                    self.discovered_devices[data['mac']] = data
                    self.log_message(f"Found device: {data['mac']} - {data.get('name', 'Unknown')}")
                    
                elif msg_type == "scan_complete":
                    self.is_scanning = False
                    self.scan_btn.config(state="normal")
                    self.stop_scan_btn.config(state="disabled")
                    self.progress_bar.stop()
                    self.status_var.set(f"Scan complete - Found {data} devices")
                    self.log_message(f"Scan completed using original libnetat tool. Found {data} devices.")
                    
                elif msg_type == "scan_error":
                    self.is_scanning = False
                    self.scan_btn.config(state="normal")
                    self.stop_scan_btn.config(state="disabled")
                    self.progress_bar.stop()
                    self.status_var.set("Scan failed")
                    self.log_message(f"Scan error: {data}")
                    messagebox.showerror("Scan Error", f"Scan failed: {data}")
                    
                elif msg_type == "command_response":
                    # Process SSID responses to convert hex to ASCII
                    processed_data = self.process_ssid_response(data)
                    self.response_text.insert(tk.END, f"\n--- Response (via original libnetat) ---\n{processed_data}\n")
                    self.response_text.see(tk.END)
                    
                    # Handle auto-configuration responses differently
                    if self.auto_configuring:
                        self.status_var.set("Configuration loaded")
                        self.log_message("Device auto-configuration completed")
                        self.auto_configuring = False
                        
                        # Update device label to show configuration loaded
                        if self.selected_device:
                            device_text = f"Selected: {self.selected_device['mac']} - {self.selected_device['name']} ✓"
                            self.selected_device_label.config(text=device_text)
                    else:
                        self.status_var.set("Command completed")
                        self.log_message("Command executed successfully using original tool")
                    
                    # Check if this is a WNBCFG response and parse it
                    if "+WNBCFG" in data:
                        self.parse_wnbcfg_response(data)
                    
                elif msg_type == "command_error":
                    self.response_text.insert(tk.END, f"\n--- Error ---\n{data}\n")
                    self.response_text.see(tk.END)
                    
                    # Handle auto-configuration errors
                    if self.auto_configuring:
                        self.status_var.set("Auto-configuration failed")
                        self.log_message("Device auto-configuration failed")
                        self.auto_configuring = False
                        
                        # Update device label to show error
                        if self.selected_device:
                            device_text = f"Selected: {self.selected_device['mac']} - {self.selected_device['name']} (error)"
                            self.selected_device_label.config(text=device_text)
                    else:
                        self.status_var.set("Command failed")
                        self.log_message(f"Command error: {data}")
                    
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_messages)
        
    def convert_hex_to_ascii_ssid(self, hex_string):
        """Convert hex-encoded SSID to ASCII text"""
        try:
            # Check if this looks like a hex string
            if len(hex_string) > 0 and len(hex_string) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in hex_string):
                # Convert hex to bytes, then to ASCII
                ascii_text = bytes.fromhex(hex_string).decode('utf-8', errors='ignore')
                # Filter out non-printable characters
                ascii_text = ''.join(c for c in ascii_text if c.isprintable())
                return ascii_text if ascii_text else hex_string
            return hex_string
        except Exception:
            return hex_string
    
    def parse_wnbcfg_response(self, response_data):
        """Parse AT+WNBCFG response and populate configuration fields"""
        try:
            self.log_message("Parsing WNBCFG response to populate configuration fields")
            
            # Extract configuration values from the response
            config = {}
            
            lines = response_data.split('\n')
            for line in lines:
                line = line.strip()
                if not line or line.startswith('+') or line.startswith('(Demo'):
                    continue
                    
                # Parse key:value pairs
                if ':' in line:
                    # Handle multiple key:value pairs in one line
                    parts = line.split(', ')
                    for part in parts:
                        if ':' in part:
                            key, value = part.split(':', 1)
                            config[key.strip()] = value.strip()
                
                # Parse special formats like "ssid:value, r_ssid:value, addr:value"
                if 'ssid:' in line:
                    # Extract SSID (convert hex to ASCII if needed)
                    ssid_match = line.split('ssid:')[1].split(',')[0].strip()
                    config['ssid'] = self.convert_hex_to_ascii_ssid(ssid_match)
            
            # Populate GUI fields with parsed values
            if 'ssid' in config and config['ssid']:
                self.ssid_var.set(config['ssid'])
                self.log_message(f"Set SSID: {config['ssid']}")
            
            if 'role' in config:
                role_map = {'ap': 'ap', 'sta': 'sta', 'apsta': 'apsta'}
                if config['role'] in role_map:
                    self.mode_var.set(role_map[config['role']])
                    self.log_message(f"Set Mode: {config['role']}")
            
            # Handle channel list response (e.g., "+ CHAN_LIST:9080,9160,9240")
            if 'chan_list' in config:
                self.log_message(f"Channel list: {config['chan_list']}")
                # Extract channel list and set first channel as default
                chan_list = config['chan_list'].split(',')
                if chan_list:
                    self.channel_var.set('1')  # Default to first channel
                    self.log_message(f"Set Channel: 1 (from chan_list)")
                    
            # Handle primary channel index from WNBCFG or AT+CHANNEL response
            if 'pri_chan' in config:
                try:
                    channel = int(config['pri_chan'])
                    if 1 <= channel <= 16:
                        self.channel_var.set(str(channel))
                        self.log_message(f"Set Channel: {channel}")
                except ValueError:
                    pass
            
            if 'tx_power' in config:
                try:
                    tx_power = int(config['tx_power'])
                    if 0 <= tx_power <= 20:
                        self.txpower_var.set(str(tx_power))
                        self.log_message(f"Set TX Power: {tx_power}")
                except ValueError:
                    pass
            
            if 'encrypt' in config:
                self.encrypt_var.set(config['encrypt'])
                self.log_message(f"Set Encrypt: {config['encrypt']}")
            
            if 'key' in config or 'psk' in config:
                key_value = config.get('key', config.get('psk', ''))
                if key_value:
                    self.key_var.set(key_value)
                    self.log_message(f"Set Key: [hidden]")
            
        except Exception as e:
            self.log_message(f"Error parsing WNBCFG response: {e}")
            
    def process_ssid_response(self, response_data):
        """Process AT command responses to convert hex-encoded SSID values to ASCII"""
        try:
            lines = response_data.split('\n')
            processed_lines = []
            
            for line in lines:
                # Check for SSID responses like '+SSID:0240497ca740'
                if '+SSID:' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        ssid_hex = parts[1].strip()
                        ssid_ascii = self.convert_hex_to_ascii_ssid(ssid_hex)
                        processed_line = f"{parts[0]}:{ssid_ascii}" + (f" (hex: {ssid_hex})" if ssid_ascii != ssid_hex else "")
                        processed_lines.append(processed_line)
                        continue
                        
                # Check for channel list responses like '+ CHAN_LIST:9080,9160,9240'
                if '+CHAN_LIST:' in line or '+ CHANNEL:' in line:
                    processed_lines.append(line + " (use channel index 1-N to select)")
                    continue
                        
                processed_lines.append(line)
                
            return '\n'.join(processed_lines)
        except Exception as e:
            self.log_message(f"Error processing SSID response: {e}")
            return response_data
            
            if 'bss_bw' in config:
                self.bss_bw_var.set(config['bss_bw'])
                self.log_message(f"Set BSS BW: {config['bss_bw']}")
            
            # Legacy encrypt handling for old field
            if 'encrypt' in config:
                encrypt_map = {'0': 'NONE', '1': 'WPA-PSK', '2': 'WPA2-PSK'}
                if config['encrypt'] in encrypt_map:
                    self.keymgmt_var.set(encrypt_map[config['encrypt']])
                    self.log_message(f"Set Security: {encrypt_map[config['encrypt']]}")
            
            if 'psk' in config and config['psk']:
                self.psk_var.set(config['psk'])
                self.log_message("Set PSK from device configuration")
            
            # Show success message
            messagebox.showinfo("Configuration Loaded", 
                              "Device configuration has been loaded into the GUI fields.\n\n" +
                              "You can now modify settings and use the Set buttons to update the device.")
            
        except Exception as e:
            self.log_message(f"Error parsing WNBCFG response: {e}")
            # Don't show error to user as this is optional functionality
    
    def auto_configure_device(self):
        """Automatically get device configuration using AT+WNBCFG"""
        if not self.selected_device:
            messagebox.showwarning("No Device", "Please select a device first")
            return
        
        # Set auto-config flag so we know this is automatic
        self.auto_configuring = True
        self.log_message("Requesting device configuration with AT+WNBCFG")
        self.status_var.set("Fetching device configuration...")
        
        # Send AT+WNBCFG command directly without showing in the command field
        threading.Thread(target=self._send_command_worker, 
                        args=("at+wnbcfg", self.selected_device['mac']), daemon=True).start()
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

def main():
    """Main entry point"""
    print("Taixin LibNetat GUI")
    print("A graphical interface for the Taixin LibNetat Tool by aliosa27")
    print("Original tool: https://github.com/aliosa27/taixin_tools")
    print("=" * 60)
    
    if not HAS_LIBNETAT or HAS_LIBNETAT is False:
        print("Warning: Original libnetat tool not found.")
        print("GUI will run in demo mode with limited functionality.")
        print("\nTo install the original tool:")
        print("pip install git+https://github.com/aliosa27/taixin_tools.git")
        print("=" * 60)
        
    app = TaixinGUI()
    app.run()

if __name__ == "__main__":
    main()