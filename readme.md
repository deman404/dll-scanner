# DLL File Scanner & Manager

![Windows 11 Style Interface](https://img.shields.io/badge/Interface-Windows%2011%20Style-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![License](https://img.shields.io/badge/License-MIT-orange)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

A modern, feature-rich DLL file scanner and management tool with a Windows 11 style interface built using Python and CustomTkinter.

## ✨ Features

### 🔍 **Scanning Capabilities**
- **Multi-drive scanning**: Scan any drive or directory on your system
- **Quick scans**: Pre-configured scans for System32 and Windows directories
- **Custom filters**: Include/exclude system files, hidden files, and subdirectories
- **Progress tracking**: Real-time progress bar and statistics

### 📊 **File Management**
- **Detailed file information**: View size, modification date, attributes, and version info
- **Advanced filtering**: Filter by filename, size, and file attributes
- **Search functionality**: Quick search through scan results
- **Sorting options**: Sort by name, size, or date

### 🛠️ **Analysis Tools**
- **Duplicate detection**: Find duplicate DLL files across your system
- **Size analysis**: View file size distribution and statistics
- **Directory grouping**: Organize results by directory structure
- **File properties**: Detailed property viewer for selected files

### 💾 **Export Options**
- **Multiple formats**: Export to TXT, CSV, and JSON
- **Selective export**: Export only selected files
- **Batch operations**: Save complete scan results for later analysis

### 🎨 **Modern Interface**
- **Windows 11 style**: Rounded corners, modern widgets, dark/light themes
- **Responsive layout**: Adjustable panels and resizable windows
- **Intuitive controls**: Easy-to-use menus and toolbars
- **Status indicators**: Real-time file count and size statistics

## 📸 Screenshots

![Main Interface](screenshots/main_interface.png)
*Main scanning interface with results panel*

![File Details](screenshots/file_details.png)
*Detailed file information view*

![Duplicate Detection](screenshots/duplicates.png)
*Duplicate file detection tool*

## 🚀 Installation

### Option 1: Using the Pre-built Executable (Recommended)

1. **Download** the latest release from the [Releases page](https://github.com/yourusername/dll-scanner/releases)
2. **Run** `DLLScanner.exe`
3. No additional installation required!

### Option 2: Running from Source

#### Prerequisites
- Python 3.8 or higher
- Windows 7/8/10/11

#### Installation Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/dll-scanner.git
   cd dll-scanner
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python main.py
   ```

#### Required Python Packages
```
customtkinter>=5.2.0
psutil>=5.9.0
pywin32>=306
```

### Option 3: Building from Source

1. **Install build tools**:
   ```bash
   pip install pyinstaller
   ```

2. **Build the executable**:
   ```bash
   pyinstaller --onefile --windowed --name "DLLScanner" --icon=icon.ico --hidden-import=psutil --hidden-import=pywin32 --collect-all=customtkinter main.py
   ```

3. **Find the executable** in the `dist` folder

## 🎯 Quick Start Guide

### Basic Scanning
1. Launch the application
2. Select a drive or directory to scan
3. Click **"Start Scan"** or press **F5**
4. View results in the main panel

### Viewing File Details
1. Double-click any file in the results list
2. View detailed information in the bottom panel
3. Check file version, attributes, and timestamps

### Finding Duplicates
1. Go to **Tools → Find Duplicates**
2. Review the list of duplicate files
3. Export or analyze duplicate results

### Exporting Results
1. Select files (use Ctrl+Click for multiple)
2. Go to **File → Export as...**
3. Choose format (TXT, CSV, or JSON)
4. Save to your preferred location

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| **F5** | Start scan |
| **F6** | Stop scan |
| **Ctrl+N** | New scan |
| **Ctrl+S** | Save results |
| **Ctrl+E** | Export as CSV |
| **Ctrl+F** | Search results |
| **Double-click** | View file details |

## 🗂️ Project Structure

```
dll-scanner/
├── main.py              # Main application file
├── requirements.txt     # Python dependencies
├── build_exe.py        # Build script for executable
├── icon.ico            # Application icon
├── screenshots/        # Application screenshots
├── dist/               # Built executables (generated)
├── build/              # Build files (generated)
└── README.md           # This file
```

## 🔧 Advanced Usage

### Command Line Arguments
Run the executable with command line arguments for automation:

```bash
DLLScanner.exe --scan "C:\Windows\System32" --max-files 5000 --export csv
```

### Configuration File
Create a `config.ini` file in the same directory as the executable:

```ini
[Scan]
default_directory = C:\
max_files = 10000
include_system = true
scan_subdirectories = true

[UI]
theme = dark
font_size = 12
show_full_path = false
```

### Batch Processing
Use the Python API for automated scanning:

```python
from scanner import DLLScanner

scanner = DLLScanner()
results = scanner.scan_directory("C:\\Windows\\System32", max_files=1000)
scanner.export_to_csv(results, "scan_results.csv")
```

## ⚠️ System Requirements

### Minimum Requirements
- **OS**: Windows 7 or later
- **RAM**: 2 GB
- **Storage**: 100 MB free space
- **Permissions**: User account with read access to scanned directories

### Recommended Requirements
- **OS**: Windows 10/11
- **RAM**: 4 GB or more
- **CPU**: Multi-core processor
- **Permissions**: Administrator privileges for full system scan

## 🔒 Security Notes

### File Access
- The application only reads file information (metadata)
- No files are modified, deleted, or moved
- All operations are read-only

### Permissions
- For complete system scans, run as Administrator
- Some system directories require elevated privileges
- The application will skip files with permission errors

### Privacy
- No data is sent to external servers
- All scan results remain on your local machine
- Export files are saved to your chosen location only

## 🐛 Troubleshooting

### Common Issues

#### "DLL files not found"
- Ensure you're scanning the correct directory
- Check that file extensions are visible in Windows
- Verify you have read permissions for the directory

#### "Scan is very slow"
- Reduce the maximum file limit
- Exclude system directories if not needed
- Close other resource-intensive applications

#### "Application crashes"
- Ensure you have the latest Visual C++ Redistributable
- Run as Administrator for system scans
- Check Windows Event Viewer for detailed error logs

#### "Missing dependencies"
```bash
# Reinstall all dependencies
pip uninstall customtkinter psutil pywin32
pip install -r requirements.txt
```

### Debug Mode
Run the application in debug mode for detailed logging:

```bash
python main.py --debug
```

Or for the executable:
```bash
DLLScanner.exe --debug
```

## 📈 Performance Tips

1. **Limit scan scope**: Use specific directories instead of whole drives
2. **Increase max files**: For comprehensive scans, increase the limit
3. **Use filters**: Exclude system files when not needed
4. **Close other apps**: Free up system resources during large scans
5. **Regular cleanup**: Clear old results to free memory

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **Report bugs**: [Create an issue](https://github.com/yourusername/dll-scanner/issues)
2. **Suggest features**: Submit feature requests
3. **Submit PRs**: Fork and submit pull requests
4. **Improve documentation**: Help improve this README

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/yourusername/dll-scanner.git

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

### Code Style
- Follow PEP 8 guidelines
- Use descriptive variable names
- Add docstrings to functions
- Include type hints where possible

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **CustomTkinter**: For the amazing modern UI components
- **PyInstaller**: For making Python applications distributable
- **psutil**: For system and process utilities
- **pywin32**: For Windows API integration

## 📞 Support

- **Documentation**: [Wiki](https://github.com/yourusername/dll-scanner/wiki)
- **Issues**: [GitHub Issues](https://github.com/yourusername/dll-scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/dll-scanner/discussions)
- **Email**: support@example.com

## 🚀 Roadmap

### Planned Features
- [ ] **Network scanning**: Scan network drives and shares
- [ ] **Registry integration**: View DLL dependencies and registration
- [ ] **Hash verification**: Calculate and verify file hashes
- [ ] **Scheduled scans**: Automate scans at specified times
- [ ] **Cloud integration**: Save results to cloud storage
- [ ] **API access**: REST API for remote scanning
- [ ] **Plugins**: Extensible plugin system

### Version History
- **v2.0.0**: Modern Windows 11 interface, CustomTkinter migration
- **v1.0.0**: Initial release with basic scanning functionality

---

## 📋 Quick Reference Card

```yaml
App: DLL File Scanner & Manager
Purpose: Scan, analyze, and manage DLL files
Platform: Windows
Language: Python
UI: CustomTkinter (Windows 11 style)
Key Features:
  - Multi-drive scanning
  - Duplicate detection
  - File size analysis
  - Multiple export formats
  - Modern interface
Scan Types:
  - Full system scan
  - Quick scan (System32)
  - Custom directory scan
Export Formats: TXT, CSV, JSON
Shortcuts: F5=Scan, F6=Stop, Ctrl+S=Save
```

---

**⭐ If you find this tool useful, please give it a star on GitHub!**

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/dll-scanner&type=Date)](https://star-history.com/#yourusername/dll-scanner&Date)