#!/usr/bin/env python3
"""
Launcher script for the Taixin LibNetat GUI
A cross-platform GUI wrapper for the Taixin LibNetat Tool by aliosa27

Original Tool: https://github.com/aliosa27/taixin_tools
Original Author: aliosa27 (aliosa27@aliosa27.me)
"""

import sys
import os
import subprocess
import tkinter as tk
from tkinter import messagebox

def check_python_version():
    """Check if Python version meets requirements"""
    if sys.version_info < (3, 6):
        print("Error: Python 3.6 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    return True

def check_tkinter():
    """Check if tkinter is available"""
    try:
        import tkinter
        return True
    except ImportError:
        return False

def check_original_tool():
    """Check if the original Taixin LibNetat Tool is available"""
    try:
        # Try different import methods
        import taixin_tools.libnetat
        return "installed_package"
    except ImportError:
        try:
            import libnetat
            return "direct_import"
        except ImportError:
            # Check if it can be found via subprocess
            try:
                result = subprocess.run([sys.executable, '-c', 'import libnetat'], 
                                      capture_output=True, text=True, timeout=5)
                return "subprocess" if result.returncode == 0 else False
            except:
                return False

def install_original_tool():
    """Attempt to install the original tool"""
    print("Attempting to install the original Taixin LibNetat Tool...")
    
    try:
        # Try installing from git
        result = subprocess.run([
            sys.executable, '-m', 'pip', 'install', 
            'git+https://github.com/aliosa27/taixin_tools.git'
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print("Successfully installed the original tool!")
            return True
        else:
            print(f"Installation failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("Installation timed out")
        return False
    except Exception as e:
        print(f"Installation error: {e}")
        return False

def show_dependency_error():
    """Show GUI error dialog about missing dependencies"""
    try:
        root = tk.Tk()
        root.withdraw()  # Hide main window
        
        error_msg = """The original Taixin LibNetat Tool by aliosa27 is required but not found.

This GUI is a wrapper that provides a user-friendly interface 
to the powerful command-line tools created by aliosa27.

To install the original tool, run:
pip install git+https://github.com/aliosa27/taixin_tools.git

Or manually:
1. git clone https://github.com/aliosa27/taixin_tools.git
2. cd taixin_tools  
3. pip install scapy (main dependency)

Original Project: https://github.com/aliosa27/taixin_tools
Original Author: aliosa27 (aliosa27@aliosa27.me)

Would you like to try automatic installation?"""
        
        result = messagebox.askyesno("Dependency Missing", error_msg)
        root.destroy()
        
        if result:
            return install_original_tool()
        return False
        
    except Exception:
        return False

def main():
    """Main launcher function"""
    print("Taixin LibNetat GUI Launcher")
    print("A cross-platform GUI for the Taixin LibNetat Tool by aliosa27")
    print("=" * 65)
    print(f"Original Tool: https://github.com/aliosa27/taixin_tools")
    print(f"Original Author: aliosa27 (aliosa27@aliosa27.me)")
    print("=" * 65)
    
    # Check Python version
    if not check_python_version():
        input("Press Enter to exit...")
        sys.exit(1)
    
    print(f"Python version: {sys.version}")
    print(f"Platform: {sys.platform}")
    
    # Check tkinter
    if not check_tkinter():
        error_msg = "tkinter is not available. Please install it for your platform:\n\n"
        error_msg += "Ubuntu/Debian: sudo apt install python3-tk\n"
        error_msg += "CentOS/RHEL: sudo yum install tkinter\n"  
        error_msg += "macOS (Homebrew): brew install python-tk\n"
        error_msg += "Windows: tkinter should be included with Python"
        
        print(f"Error: {error_msg}")
        input("Press Enter to exit...")
        sys.exit(1)
    
    print("tkinter available [OK]")
    
    # Check for the original tool
    tool_status = check_original_tool()
    
    if not tool_status:
        print("Original Taixin LibNetat Tool not found")
        print("GUI will run in demo mode with limited functionality")
        print("")
        print("To install the original tool:")
        print("pip install git+https://github.com/aliosa27/taixin_tools.git")
        print("")
        
        # Try to show GUI dialog for installation
        if show_dependency_error():
            # Re-check after installation
            tool_status = check_original_tool()
            if tool_status:
                print("Installation successful! Starting GUI...")
            else:
                print("Installation may have failed. Starting in demo mode...")
        else:
            print("Starting GUI in demo mode...")
    else:
        print(f"Original tool found ({tool_status}) [OK]")
    
    # Add current directory to path for GUI import
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    
    try:
        print("\nStarting Taixin LibNetat GUI...")
        print("Loading GUI components...")
        
        # Import and run the GUI
        from taixin_gui import TaixinGUI
        
        app = TaixinGUI()
        app.root.protocol("WM_DELETE_WINDOW", lambda: (print("GUI closed"), app.root.destroy()))
        
        print("GUI started successfully")
        print("Press F1 in the GUI for attribution and help information")
        print("=" * 65)
        
        app.run()
        
    except ImportError as e:
        error_msg = f"Failed to import GUI components: {e}"
        print(f"Error: {error_msg}")
        
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Import Error", 
                               f"Failed to start GUI:\n{error_msg}\n\n" +
                               "Please check that all files are in the correct location.")
            root.destroy()
        except:
            pass
        sys.exit(1)
        
    except Exception as e:
        error_msg = f"Failed to start GUI: {e}"
        print(f"Error: {error_msg}")
        
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Startup Error", f"GUI startup failed:\n{error_msg}")
            root.destroy()
        except:
            pass
        sys.exit(1)

if __name__ == "__main__":
    main()