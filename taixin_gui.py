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
    
    # Get the constants if available
    PRODUCTION_SET_COMMANDS = getattr(libnetat, 'PRODUCTION_SET_COMMANDS', [])
    PRODUCTION_GET_COMMANDS = getattr(libnetat, 'PRODUCTION_GET_COMMANDS', [])
    HAS_LIBNETAT = True
    
except ImportError:
    try:
        # Fallback: try to import directly (if taixin_tools is in path)
        import libnetat
        from libnetat import ScapyNetAtMgr, WnbNetatCmd, PRODUCTION_SET_COMMANDS, PRODUCTION_GET_COMMANDS, get_network_interfaces
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
                                               command=self.detect_interfaces)
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
        columns = ("MAC Address", "IP Address", "Device Info", "Signal")
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
        
        # Mode
        ttk.Label(wifi_frame, text="Mode:").grid(row=1, column=0, sticky="w", padx=(0, 5), pady=2)
        self.mode_var = tk.StringVar()
        mode_combo = ttk.Combobox(wifi_frame, textvariable=self.mode_var, values=["sta", "ap", "apsta"], width=27)
        mode_combo.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Button(wifi_frame, text="Get", command=lambda: self.get_config("mode")).grid(row=1, column=2, padx=2, pady=2)
        ttk.Button(wifi_frame, text="Set", command=lambda: self.set_config("mode", self.mode_var.get())).grid(row=1, column=3, padx=2, pady=2)
        
        # Channel
        ttk.Label(wifi_frame, text="Channel:").grid(row=2, column=0, sticky="w", padx=(0, 5), pady=2)
        self.channel_var = tk.StringVar()
        ttk.Spinbox(wifi_frame, from_=1, to=14, textvariable=self.channel_var, width=28).grid(row=2, column=1, sticky="w", padx=5, pady=2)
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
        
        # Key Management
        ttk.Label(security_frame, text="Key Mgmt:").grid(row=0, column=0, sticky="w", padx=(0, 5), pady=2)
        self.keymgmt_var = tk.StringVar()
        keymgmt_combo = ttk.Combobox(security_frame, textvariable=self.keymgmt_var, 
                                   values=["NONE", "WPA-PSK", "WPA2-PSK"], width=27)
        keymgmt_combo.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        ttk.Button(security_frame, text="Get", command=lambda: self.get_config("keymgmt")).grid(row=0, column=2, padx=2, pady=2)
        ttk.Button(security_frame, text="Set", command=lambda: self.set_config("keymgmt", self.keymgmt_var.get())).grid(row=0, column=3, padx=2, pady=2)
        
        # PSK
        ttk.Label(security_frame, text="PSK:").grid(row=1, column=0, sticky="w", padx=(0, 5), pady=2)
        self.psk_var = tk.StringVar()
        psk_entry = ttk.Entry(security_frame, textvariable=self.psk_var, show="*", width=30)
        psk_entry.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Button(security_frame, text="Get", command=lambda: self.get_config("psk")).grid(row=1, column=2, padx=2, pady=2)
        ttk.Button(security_frame, text="Set", command=lambda: self.set_config("psk", self.psk_var.get())).grid(row=1, column=3, padx=2, pady=2)
        
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
                            # Look for NETAT scan response packets
                            if hasattr(packet, 'load') and len(packet.load) >= 19:
                                # NETAT packet structure analysis
                                data = packet.load
                                self.log_message(f"Processing packet with {len(data)} bytes, command type: {data[16] if len(data) > 16 else 'N/A'}")
                                
                                if len(data) >= 19 and data[16] == 2:  # WNB_NETAT_CMD_SCAN_RESP
                                    self.log_message("Found NETAT scan response packet!")
                                    
                                    # Extract source MAC from packet
                                    if hasattr(packet, 'src'):
                                        src_mac = packet.src
                                        src_ip = packet[0].src if hasattr(packet, '__getitem__') else "Unknown"
                                    else:
                                        src_mac = "Unknown"
                                        src_ip = "Unknown"
                                    
                                    self.log_message(f"Device found - MAC: {src_mac}, IP: {src_ip}")
                                    
                                    # Check if we already found this device
                                    device_exists = False
                                    for existing in devices_found:
                                        if existing['mac'] == src_mac:
                                            device_exists = True
                                            break
                                    
                                    if not device_exists:
                                        device_info = {
                                            'mac': src_mac,
                                            'ip': src_ip,
                                            'info': 'Taixin Device',
                                            'signal': 'N/A'
                                        }
                                        devices_found.append(device_info)
                                        self.message_queue.put(("device_found", device_info))
                                        self.log_message(f"Added new device to list: {src_mac}")
                                    else:
                                        self.log_message(f"Device {src_mac} already in list, skipping")
                                    
                                    # Remove processed packet
                                    self.netat_mgr.captured_packets.remove(packet)
                            else:
                                # Log other packet types for debugging
                                if hasattr(packet, 'load') and len(packet.load) > 0:
                                    data = packet.load
                                    if len(data) > 16:
                                        self.log_message(f"Non-NETAT packet: {len(data)} bytes, type: {data[16] if len(data) > 16 else 'N/A'}")
                                    
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
        """Handle device selection"""
        selection = self.device_tree.selection()
        if selection:
            item = self.device_tree.item(selection[0])
            values = item['values']
            
            if values:
                self.selected_device = {
                    'mac': values[0],
                    'ip': values[1],
                    'info': values[2],
                    'signal': values[3]
                }
                
                device_text = f"Selected: {self.selected_device['mac']} - {self.selected_device['info']}"
                self.selected_device_label.config(text=device_text)
                self.log_message(f"Selected device: {self.selected_device['mac']}")
                
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
                self.netat_mgr.dest = dest_bytes
                
                # Clear previous packets
                self.netat_mgr.captured_packets.clear()
                
                # Send AT command using original tool's method
                self.netat_mgr.netat_send(command, retries=2, retry_delay=0.3)
                
                # Wait for response
                start_time = time.time()
                response_data = ""
                
                while time.time() - start_time < self.netat_mgr.response_timeout:
                    for packet in self.netat_mgr.captured_packets[:]:
                        try:
                            # Look for NETAT AT response packets
                            if hasattr(packet, 'load') and len(packet.load) >= 19:
                                data = packet.load
                                if len(data) >= 19 and data[16] == 4:  # WNB_NETAT_CMD_AT_RESP
                                    # Extract response payload
                                    if len(data) > 19:
                                        response_payload = data[19:].decode('utf-8', errors='ignore')
                                        response_data += response_payload
                                    
                                    # Remove processed packet
                                    self.netat_mgr.captured_packets.remove(packet)
                                    
                        except Exception as e:
                            continue
                    
                    if response_data:
                        break
                        
                    time.sleep(0.1)
                
                if response_data:
                    self.message_queue.put(("command_response", response_data.strip()))
                else:
                    self.message_queue.put(("command_response", "No response received (timeout)"))
                
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
        """Get configuration parameter"""
        command = f"at+{param}?"
        self.command_var.set(command)
        self.send_command()
        
    def set_config(self, param, value):
        """Set configuration parameter"""
        if not value:
            messagebox.showwarning("No Value", f"Please enter a value for {param}")
            return
            
        command = f"at+{param}={value}"
        self.command_var.set(command)
        self.send_command()
        
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
                        data['mac'], data['ip'], data['info'], data['signal']
                    ))
                    self.discovered_devices[data['mac']] = data
                    self.log_message(f"Found device: {data['mac']} - {data['info']}")
                    
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
                    self.response_text.insert(tk.END, f"\n--- Response (via original libnetat) ---\n{data}\n")
                    self.response_text.see(tk.END)
                    self.status_var.set("Command completed")
                    self.log_message("Command executed successfully using original tool")
                    
                    # Check if this is a WNBCFG response and parse it
                    if "+WNBCFG" in data:
                        self.parse_wnbcfg_response(data)
                    
                elif msg_type == "command_error":
                    self.response_text.insert(tk.END, f"\n--- Error ---\n{data}\n")
                    self.response_text.see(tk.END)
                    self.status_var.set("Command failed")
                    self.log_message(f"Command error: {data}")
                    
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_messages)
        
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
                    if len(ssid_match) > 0 and all(c in '0123456789abcdefABCDEF' for c in ssid_match):
                        try:
                            # Convert hex SSID to ASCII
                            ssid_ascii = bytes.fromhex(ssid_match).decode('utf-8', errors='ignore')
                            config['ssid'] = ssid_ascii
                        except:
                            config['ssid'] = ssid_match
                    else:
                        config['ssid'] = ssid_match
            
            # Populate GUI fields with parsed values
            if 'ssid' in config and config['ssid']:
                self.ssid_var.set(config['ssid'])
                self.log_message(f"Set SSID: {config['ssid']}")
            
            if 'role' in config:
                role_map = {'ap': 'ap', 'sta': 'sta', 'apsta': 'apsta'}
                if config['role'] in role_map:
                    self.mode_var.set(role_map[config['role']])
                    self.log_message(f"Set Mode: {config['role']}")
            
            if 'pri_chan' in config:
                try:
                    channel = int(config['pri_chan'])
                    if 1 <= channel <= 14:
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
        
        self.command_var.set("at+wnbcfg")
        self.send_command()
        self.log_message("Requesting device configuration with AT+WNBCFG")
    
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