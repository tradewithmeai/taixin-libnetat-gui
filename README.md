# Taixin LibNetat GUI

A cross-platform graphical user interface for the [Taixin LibNetat Tool](https://github.com/aliosa27/taixin_tools) by [aliosa27](https://github.com/aliosa27).

> **Attribution**: This GUI is a wrapper around the excellent Taixin LibNetat Tool created by aliosa27. All core functionality for device communication, AT commands, and network protocols is provided by the original project. This GUI simply provides a user-friendly interface to those powerful tools.

## What is this?

This project provides a modern, cross-platform GUI for managing Taixin wireless devices using the Taixin LibNetat Tool. Instead of using command-line interfaces, users can interact with their devices through an intuitive graphical interface.

### Key Features

🖥️ **Cross-Platform** - Works on Windows, macOS, and Linux  
📡 **Device Discovery** - Visual scanning and selection of Taixin devices  
⚙️ **Configuration Management** - GUI controls for WiFi settings and device parameters  
📝 **AT Command Interface** - Send commands with quick buttons or custom input  
📊 **Real-time Logging** - Monitor all operations with timestamped logs  
💾 **File Operations** - Save and load device configurations  

## Prerequisites

- **Python 3.6+**
- **Original Taixin LibNetat Tool** (automatically installed as dependency)

## Installation

### Option 1: Quick Install
```bash
# Clone this GUI project
git clone https://github.com/tradewithmeai/taixin-libnetat-gui.git
cd taixin-libnetat-gui

# Install dependencies (includes original taixin_tools)
pip install -r requirements.txt

# Run the GUI
python run_gui.py
```

### Option 2: Manual Install
```bash
# First install the original tool
git clone https://github.com/aliosa27/taixin_tools.git
cd taixin_tools
pip install -r requirements.txt  # if available, or: pip install scapy

# Then install this GUI
cd ..
git clone https://github.com/tradewithmeai/taixin-libnetat-gui.git
cd taixin-libnetat-gui
python run_gui.py
```

### Platform-Specific Notes

#### Windows
- Run `run_gui.bat` for a convenient launcher
- May require elevated privileges for network operations
- Install [Npcap](https://nmap.org/npcap/) for better network support

#### macOS  
- Run `./run_gui.sh` after making it executable
- May need: `brew install python-tk` if using Homebrew Python

#### Linux
- Run `./run_gui.sh` after making it executable  
- Install tkinter: `sudo apt install python3-tk` (Ubuntu/Debian)
- May need `sudo` for network scanning

## Usage

### 1. Launch the GUI
```bash
# Cross-platform launcher
python run_gui.py

# Platform-specific launchers
run_gui.bat        # Windows
./run_gui.sh       # Linux/macOS
```

### 2. Device Discovery
1. Select your network interface (or use "auto")
2. Click "Scan for Devices" 
3. Select a discovered device from the list

### 3. Send AT Commands
- Use quick command buttons for common operations
- Enter custom AT commands in the text field
- View responses in the scrollable output area

### 4. Configure Devices
- Use the Configuration tab for visual setting controls
- Get/Set buttons retrieve or update device parameters
- Save/Load configuration files for backup/restore

### 5. Monitor Operations  
- Enable logging to track all operations
- Save logs for troubleshooting or analysis
- Monitor connection status in the status bar

## Screenshots

*Coming soon - GUI screenshots showing the main interface*

## Original Project

This GUI is built on top of the excellent work by **aliosa27**:

- **Original Project**: https://github.com/aliosa27/taixin_tools
- **Author**: aliosa27 (aliosa27@aliosa27.me)
- **License**: As specified in the original project

### What the Original Tool Provides

The original Taixin LibNetat Tool provides all the core functionality:
- Cross-platform network device discovery
- AT command communication protocols  
- Support for both 1.x and 2.x firmware
- Network packet capture and analysis
- Configuration file management
- Web-based interface option
- Extensive device compatibility

Our GUI simply provides a more user-friendly way to access these powerful features.

## Contributing

### To This GUI Project
- Report GUI-specific issues in this repository
- Submit pull requests for GUI improvements
- Suggest new interface features

### To the Core Tool  
- Report device compatibility issues to the [original project](https://github.com/aliosa27/taixin_tools)
- Submit AT command improvements to the original repository
- Network protocol issues should go to the original project

## Support

- **GUI Issues**: Create an issue in this repository
- **Device/Protocol Issues**: Report to the [original project](https://github.com/aliosa27/taixin_tools/issues)
- **General Questions**: Check both repositories' documentation

## License

This GUI wrapper is provided under the same terms as the original project. Please refer to the [original Taixin LibNetat Tool repository](https://github.com/aliosa27/taixin_tools) for licensing information.

## Acknowledgments

- **aliosa27** - Creator of the original Taixin LibNetat Tool
- All contributors to the original project
- The Taixin device community for testing and feedback

---

*This project respectfully builds upon the Taixin LibNetat Tool by aliosa27. All device communication functionality is provided by the original project.*