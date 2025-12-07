import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
import os
import sys
import time
import threading
import json
import csv
from datetime import datetime
import psutil
import tk
import win32api
from typing import List, Dict, Any

# Set CustomTkinter theme
ctk.set_appearance_mode("dark")  # "dark", "light", "system"
ctk.set_default_color_theme("blue")  # "blue", "green", "dark-blue"


class DLLScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DLL File Scanner & Manager - by ayman azhar https://mraymanazhar.vercel.app/")
        self.root.geometry("1400x800")
        self.root.minsize(1200, 700)

        # Set window icon
        try:
            self.root.iconbitmap(default='icon.ico')
        except:
            pass

        # Variables
        self.scanning = False
        self.current_scan_thread = None
        self.stop_scan_flag = threading.Event()
        self.results = []
        self.total_files_found = 0
        self.scan_progress = 0
        self.filtered_results = []

        # Font settings
        self.title_font = ctk.CTkFont(family="Segoe UI", size=20, weight="bold")
        self.heading_font = ctk.CTkFont(family="Segoe UI", size=14, weight="bold")
        self.normal_font = ctk.CTkFont(family="Segoe UI", size=12)
        self.mono_font = ctk.CTkFont(family="Consolas", size=11)

        # Color settings
        self.primary_color = "#0078d7"
        self.success_color = "#107c10"
        self.error_color = "#d13438"
        self.warning_color = "#ffb900"

        # Setup GUI
        self.setup_menu()
        self.setup_main_layout()
        self.setup_status_bar()

        # Load settings
        self.load_settings()

        # Bind keyboard shortcuts
        self.bind_shortcuts()

    def setup_menu(self):
        """Setup the menu bar"""
        menubar = ctk.CTkFrame(self.root, height=30, corner_radius=0)
        menubar.pack(fill="x", padx=0, pady=0)

        # File menu button
        file_menu = ctk.CTkButton(menubar, text="File", width=60, height=25,
                                  font=self.normal_font, fg_color="transparent",
                                  hover_color=("gray70", "gray30"),
                                  command=self.show_file_menu)
        file_menu.pack(side="left", padx=(10, 0), pady=2)

        # Scan menu button
        scan_menu = ctk.CTkButton(menubar, text="Scan", width=60, height=25,
                                  font=self.normal_font, fg_color="transparent",
                                  hover_color=("gray70", "gray30"),
                                  command=self.show_scan_menu)
        scan_menu.pack(side="left", padx=(5, 0), pady=2)

        # Tools menu button
        tools_menu = ctk.CTkButton(menubar, text="Tools", width=60, height=25,
                                   font=self.normal_font, fg_color="transparent",
                                   hover_color=("gray70", "gray30"),
                                   command=self.show_tools_menu)
        tools_menu.pack(side="left", padx=(5, 0), pady=2)

        # View menu button
        view_menu = ctk.CTkButton(menubar, text="View", width=60, height=25,
                                  font=self.normal_font, fg_color="transparent",
                                  hover_color=("gray70", "gray30"),
                                  command=self.show_view_menu)
        view_menu.pack(side="left", padx=(5, 0), pady=2)

        # Help menu button
        help_menu = ctk.CTkButton(menubar, text="Help", width=60, height=25,
                                  font=self.normal_font, fg_color="transparent",
                                  hover_color=("gray70", "gray30"),
                                  command=self.show_help_menu)
        help_menu.pack(side="left", padx=(5, 0), pady=2)

    def setup_main_layout(self):
        """Setup the main layout"""
        # Create main frame
        main_frame = ctk.CTkFrame(self.root, corner_radius=10)
        main_frame.pack(fill="both", expand=True, padx=10, pady=(5, 0))

        # Create left and right panels
        self.left_panel = ctk.CTkFrame(main_frame, width=350, corner_radius=8)
        self.left_panel.pack(side="left", fill="y", padx=(0, 10), pady=10)
        self.left_panel.pack_propagate(False)

        self.right_panel = ctk.CTkFrame(main_frame, corner_radius=8)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=(0, 0), pady=10)

        # Setup left panel
        self.setup_controls_panel()

        # Setup right panel
        self.setup_results_panel()

    def setup_controls_panel(self):
        """Setup the controls panel"""
        # Title
        title_label = ctk.CTkLabel(self.left_panel, text="DLL File Scanner - by ayman azhar",
                                   font=self.title_font)
        title_label.pack(pady=(15, 20))

        # Scan options frame
        options_frame = ctk.CTkFrame(self.left_panel, corner_radius=8)
        options_frame.pack(fill="x", padx=15, pady=(0, 15))

        ctk.CTkLabel(options_frame, text="Scan Options", font=self.heading_font).pack(pady=(10, 15))

        # Drive selection
        drive_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        drive_frame.pack(fill="x", padx=15, pady=(0, 10))

        ctk.CTkLabel(drive_frame, text="Select Drive:", font=self.normal_font).pack(side="left")
        self.drive_var = ctk.StringVar(value="C:")
        self.drive_combo = ctk.CTkComboBox(drive_frame,
                                           values=self.get_available_drives(),
                                           variable=self.drive_var,
                                           width=120)
        self.drive_combo.pack(side="right")

        # Directory selection
        dir_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        dir_frame.pack(fill="x", padx=15, pady=(0, 10))

        ctk.CTkLabel(dir_frame, text="Directory:", font=self.normal_font).pack(anchor="w")

        dir_input_frame = ctk.CTkFrame(dir_frame, fg_color="transparent")
        dir_input_frame.pack(fill="x", pady=(5, 0))

        self.dir_var = ctk.StringVar(value="C:\\")
        self.dir_entry = ctk.CTkEntry(dir_input_frame, textvariable=self.dir_var)
        self.dir_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))

        browse_btn = ctk.CTkButton(dir_input_frame, text="...", width=40,
                                   command=self.browse_directory)
        browse_btn.pack(side="right")

        # Max files option
        max_files_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        max_files_frame.pack(fill="x", padx=15, pady=(0, 10))

        ctk.CTkLabel(max_files_frame, text="Max Files:", font=self.normal_font).pack(side="left")
        self.max_files_var = ctk.StringVar(value="10000")
        self.max_files_entry = ctk.CTkEntry(max_files_frame,
                                            textvariable=self.max_files_var,
                                            width=120)
        self.max_files_entry.pack(side="right")

        # Checkbox options
        checkbox_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        checkbox_frame.pack(fill="x", padx=15, pady=(0, 10))

        self.recursive_var = ctk.BooleanVar(value=True)
        recursive_cb = ctk.CTkCheckBox(checkbox_frame, text="Scan Subdirectories",
                                       variable=self.recursive_var)
        recursive_cb.pack(anchor="w", pady=(0, 5))

        self.include_system_var = ctk.BooleanVar(value=True)
        system_cb = ctk.CTkCheckBox(checkbox_frame, text="Include System Files",
                                    variable=self.include_system_var)
        system_cb.pack(anchor="w", pady=(0, 5))

        self.show_hidden_var = ctk.BooleanVar(value=False)
        hidden_cb = ctk.CTkCheckBox(checkbox_frame, text="Show Hidden Files",
                                    variable=self.show_hidden_var)
        hidden_cb.pack(anchor="w")

        # Scan buttons
        btn_frame = ctk.CTkFrame(self.left_panel, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=(0, 15))

        self.start_btn = ctk.CTkButton(btn_frame, text="Start Scan",
                                       command=self.start_scan,
                                       font=self.heading_font,
                                       height=35,
                                       fg_color=self.primary_color)
        self.start_btn.pack(side="left", fill="x", expand=True, padx=(0, 5))

        self.stop_btn = ctk.CTkButton(btn_frame, text="Stop Scan",
                                      command=self.stop_scan,
                                      font=self.normal_font,
                                      height=35,
                                      state="disabled",
                                      fg_color=self.error_color)
        self.stop_btn.pack(side="right", fill="x", expand=True)

        # Progress frame
        progress_frame = ctk.CTkFrame(self.left_panel, corner_radius=8)
        progress_frame.pack(fill="x", padx=15, pady=(0, 15))

        ctk.CTkLabel(progress_frame, text="Scan Progress", font=self.heading_font).pack(pady=(10, 5))

        self.progress_var = ctk.DoubleVar(value=0)
        self.progress_bar = ctk.CTkProgressBar(progress_frame,
                                               variable=self.progress_var,
                                               height=20)
        self.progress_bar.pack(fill="x", padx=15, pady=(0, 5))

        self.progress_label = ctk.CTkLabel(progress_frame,
                                           text="Ready to scan",
                                           font=self.normal_font)
        self.progress_label.pack(pady=(0, 10))

        # Statistics frame
        stats_frame = ctk.CTkFrame(self.left_panel, corner_radius=8)
        stats_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        ctk.CTkLabel(stats_frame, text="Statistics", font=self.heading_font).pack(pady=(10, 10))

        self.stats_text = ctk.CTkTextbox(stats_frame, font=self.mono_font,
                                         height=120)
        self.stats_text.pack(fill="both", expand=True, padx=15, pady=(0, 10))
        self.stats_text.configure(state="disabled")

        self.update_statistics()

    def setup_results_panel(self):
        """Setup the results panel"""
        # Toolbar
        toolbar = ctk.CTkFrame(self.right_panel, height=40, corner_radius=8)
        toolbar.pack(fill="x", padx=10, pady=(10, 5))

        # Toolbar buttons
        refresh_btn = ctk.CTkButton(toolbar, text="Refresh", width=80,
                                    command=self.refresh_list)
        refresh_btn.pack(side="left", padx=(10, 5), pady=5)

        clear_btn = ctk.CTkButton(toolbar, text="Clear", width=80,
                                  command=self.clear_results)
        clear_btn.pack(side="left", padx=5, pady=5)

        export_btn = ctk.CTkButton(toolbar, text="Export Selected", width=100,
                                   command=self.export_selected)
        export_btn.pack(side="left", padx=5, pady=5)

        # Search box
        search_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
        search_frame.pack(side="right", fill="x", expand=True, padx=10, pady=5)

        ctk.CTkLabel(search_frame, text="Search:").pack(side="left", padx=(0, 5))
        self.search_var = ctk.StringVar()
        search_entry = ctk.CTkEntry(search_frame,
                                    textvariable=self.search_var,
                                    placeholder_text="Enter keywords...")
        search_entry.pack(side="left", fill="x", expand=True)
        search_entry.bind('<KeyRelease>', lambda e: self.search_results())

        # Results tree frame
        tree_frame = ctk.CTkFrame(self.right_panel, corner_radius=8)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Create Treeview using ttk
        columns = ('filename', 'path', 'size', 'modified', 'attributes')
        self.tree = ttk.Treeview(tree_frame, columns=columns,
                                 selectmode='extended',
                                 height=20)

        # Configure columns
        self.tree.heading('#0', text='#')
        self.tree.heading('filename', text='Filename')
        self.tree.heading('path', text='Path')
        self.tree.heading('size', text='Size')
        self.tree.heading('modified', text='Modified')
        self.tree.heading('attributes', text='Attributes')

        self.tree.column('#0', width=50, stretch=False)
        self.tree.column('filename', width=200)
        self.tree.column('path', width=300)
        self.tree.column('size', width=100)
        self.tree.column('modified', width=150)
        self.tree.column('attributes', width=80)

        # Scrollbars
        tree_scroll_y = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

        # Layout
        self.tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll_y.grid(row=0, column=1, sticky="ns")
        tree_scroll_x.grid(row=1, column=0, sticky="ew", columnspan=2)

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Bind double-click event
        self.tree.bind('<Double-Button-1>', self.on_item_double_click)

        # Details panel
        details_frame = ctk.CTkFrame(self.right_panel, corner_radius=8)
        details_frame.pack(fill="x", padx=10, pady=(0, 10))

        ctk.CTkLabel(details_frame, text="File Details", font=self.heading_font).pack(pady=(10, 5))

        self.details_text = ctk.CTkTextbox(details_frame, font=self.mono_font,
                                           height=120)
        self.details_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def setup_status_bar(self):
        """Setup the status bar"""
        self.status_bar = ctk.CTkFrame(self.root, height=30, corner_radius=0)
        self.status_bar.pack(side="bottom", fill="x")

        self.status_label = ctk.CTkLabel(self.status_bar, text="Ready",
                                         font=self.normal_font)
        self.status_label.pack(side="left", padx=10, pady=5)

        self.file_count_label = ctk.CTkLabel(self.status_bar, text="Files: 0",
                                             font=self.normal_font)
        self.file_count_label.pack(side="right", padx=10, pady=5)

        self.size_label = ctk.CTkLabel(self.status_bar, text="Total Size: 0 MB",
                                       font=self.normal_font)
        self.size_label.pack(side="right", padx=10, pady=5)

    def get_available_drives(self):
        """Get list of available drives"""
        drives = []
        try:
            drives = win32api.GetLogicalDriveStrings()
            drives = drives.split('\x00')[:-1]
        except:
            import string
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    drives.append(drive)
        return drives

    def browse_directory(self):
        """Open directory browser dialog"""
        directory = filedialog.askdirectory(initialdir=self.dir_var.get())
        if directory:
            self.dir_var.set(directory)

    def start_scan(self):
        """Start the DLL scan"""
        if self.scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already in progress!")
            return

        self.scanning = True
        self.stop_scan_flag.clear()
        self.results = []
        self.filtered_results = []
        self.total_files_found = 0

        # Update UI
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress_label.configure(text="Starting scan...")
        self.progress_var.set(0)

        # Clear treeview
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Get scan parameters
        scan_dir = self.dir_var.get()
        max_files = int(self.max_files_var.get()) if self.max_files_var.get().isdigit() else 10000

        # Start scan in separate thread
        self.current_scan_thread = threading.Thread(
            target=self.perform_scan,
            args=(scan_dir, max_files),
            daemon=True
        )
        self.current_scan_thread.start()

        # Start progress monitor
        self.monitor_scan_progress()

    def perform_scan(self, scan_dir, max_files):
        """Perform the actual scan in a separate thread"""
        try:
            file_count = 0
            start_time = time.time()

            # Walk through directory
            for root, dirs, files in os.walk(scan_dir):
                if self.stop_scan_flag.is_set():
                    break

                # Filter hidden directories if needed
                if not self.show_hidden_var.get():
                    dirs[:] = [d for d in dirs if not d.startswith('.')]

                for file in files:
                    if file.lower().endswith('.dll'):
                        try:
                            full_path = os.path.join(root, file)

                            # Get file info
                            stat_info = os.stat(full_path)
                            file_size = stat_info.st_size
                            modified_time = datetime.fromtimestamp(stat_info.st_mtime)

                            # Check if it's a system file
                            is_system = self.is_system_file(full_path)
                            if is_system and not self.include_system_var.get():
                                continue

                            result = {
                                'filename': file,
                                'path': full_path,
                                'size': file_size,
                                'modified': modified_time,
                                'attributes': self.get_file_attributes(full_path),
                                'is_system': is_system,
                                'directory': root
                            }

                            self.results.append(result)
                            file_count += 1

                            # Update progress every 100 files
                            if file_count % 100 == 0:
                                self.scan_progress = file_count
                                self.root.after(0, lambda: self.update_status(f"Found {file_count} files..."))

                            # Check max files limit
                            if file_count >= max_files:
                                self.root.after(0,
                                                lambda: self.update_status(f"Reached maximum files limit: {max_files}"))
                                break

                        except (PermissionError, OSError) as e:
                            continue

                if file_count >= max_files:
                    break

            self.total_files_found = file_count
            elapsed_time = time.time() - start_time

            # Update UI in main thread
            self.root.after(0, lambda: self.on_scan_complete(file_count, elapsed_time))

        except Exception as e:
            self.root.after(0, lambda: self.on_scan_error(str(e)))

    def monitor_scan_progress(self):
        """Monitor scan progress and update UI"""
        if self.scanning:
            # Update progress bar based on found files
            if self.total_files_found > 0:
                progress = (len(self.results) / self.total_files_found) * 100
                self.progress_var.set(min(progress, 100))

            # Schedule next update
            self.root.after(100, self.monitor_scan_progress)

    def on_scan_complete(self, file_count, elapsed_time):
        """Handle scan completion"""
        self.scanning = False
        self.stop_scan_flag.set()

        # Update UI
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.progress_var.set(100)

        # Update results list
        self.filtered_results = self.results.copy()
        self.update_results_list()

        # Update statistics
        self.update_statistics()

        # Show completion message
        message = f"Scan complete! Found {file_count} DLL files in {elapsed_time:.1f} seconds."
        self.progress_label.configure(text=message)
        self.update_status(message)

        # Update status bar
        self.update_file_count()

    def on_scan_error(self, error_message):
        """Handle scan errors"""
        self.scanning = False
        self.stop_scan_flag.set()

        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

        messagebox.showerror("Scan Error", f"An error occurred during scan:\n{error_message}")
        self.update_status(f"Scan error: {error_message}")

    def stop_scan(self):
        """Stop the current scan"""
        if self.scanning:
            self.stop_scan_flag.set()
            self.scanning = False
            self.update_status("Scan stopped by user")

    def update_results_list(self):
        """Update the treeview with results"""
        # Clear current items
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Add filtered results
        for i, result in enumerate(self.filtered_results[:1000]):  # Limit display
            size_mb = result['size'] / (1024 * 1024)
            self.tree.insert('', 'end', iid=i, text=str(i + 1),
                             values=(result['filename'],
                                     result['path'],
                                     f"{size_mb:.2f} MB",
                                     result['modified'].strftime('%Y-%m-%d %H:%M:%S'),
                                     result['attributes']))

        # Update file count in status bar
        self.update_file_count()

    def update_statistics(self):
        """Update statistics display"""
        if not self.results:
            stats = "No scan results yet.\nStart a scan to see statistics."
        else:
            total_size = sum(r['size'] for r in self.results)
            avg_size = total_size / len(self.results) if self.results else 0
            largest = max(self.results, key=lambda x: x['size']) if self.results else None
            smallest = min(self.results, key=lambda x: x['size']) if self.results else None

            stats = f"Total Files: {len(self.results):,}\n"
            stats += f"Total Size: {total_size / (1024 ** 3):.2f} GB\n"
            stats += f"Average Size: {avg_size / (1024 ** 2):.2f} MB\n"
            if largest:
                stats += f"Largest: {largest['filename']}\n"
                stats += f"  Size: {largest['size'] / (1024 ** 2):.2f} MB\n"
            if smallest:
                stats += f"Smallest: {smallest['filename']}\n"
                stats += f"  Size: {smallest['size'] / 1024:.2f} KB\n"

            # Group by directory
            dir_stats = {}
            for result in self.results:
                dir_path = result['directory']
                dir_stats[dir_path] = dir_stats.get(dir_path, 0) + 1

            if dir_stats:
                top_dirs = sorted(dir_stats.items(), key=lambda x: x[1], reverse=True)[:3]
                stats += "\nTop Directories:\n"
                for dir_path, count in top_dirs:
                    dir_name = os.path.basename(dir_path)
                    stats += f"  {dir_name}: {count} files\n"

        self.stats_text.configure(state="normal")
        self.stats_text.delete("1.0", "end")
        self.stats_text.insert("1.0", stats)
        self.stats_text.configure(state="disabled")

    def update_file_count(self):
        """Update file count and size in status bar"""
        total_files = len(self.filtered_results) if self.filtered_results else len(self.results)
        total_size = sum(r['size'] for r in (self.filtered_results if self.filtered_results else self.results))

        self.file_count_label.configure(text=f"Files: {total_files:,}")
        self.size_label.configure(text=f"Total Size: {total_size / (1024 ** 2):.1f} MB")

    def update_status(self, message):
        """Update status bar message"""
        self.status_label.configure(text=message)
        self.root.update_idletasks()

    def search_results(self):
        """Search in current results"""
        search_text = self.search_var.get().lower()
        if not search_text:
            self.update_results_list()
            return

        # Highlight matching items
        for i, item in enumerate(self.tree.get_children()):
            values = self.tree.item(item)['values']
            if values and search_text in str(values).lower():
                self.tree.selection_set(item)
                self.tree.see(item)
                break

    def on_item_double_click(self, event):
        """Handle double-click on treeview item"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            values = item['values']
            if values and len(values) >= 2:
                self.show_file_details(values[1])  # values[1] is the path

    def show_file_details(self, filepath):
        """Show detailed information about a file"""
        try:
            details = f"File Details:\n"
            details += f"=" * 50 + "\n"
            details += f"Filename: {os.path.basename(filepath)}\n"
            details += f"Full Path: {filepath}\n"

            stat_info = os.stat(filepath)
            size = stat_info.st_size
            details += f"Size: {size:,} bytes ({size / (1024 ** 2):.2f} MB)\n"
            details += f"Created: {datetime.fromtimestamp(stat_info.st_ctime)}\n"
            details += f"Modified: {datetime.fromtimestamp(stat_info.st_mtime)}\n"
            details += f"Accessed: {datetime.fromtimestamp(stat_info.st_atime)}\n"

            # Try to get file version info
            try:
                info = win32api.GetFileVersionInfo(filepath, "\\")
                version = info.get('FileVersion', 'N/A')
                details += f"Version: {version}\n"
            except:
                details += f"Version: Not available\n"

            # Get attributes
            attrs = self.get_file_attributes(filepath)
            details += f"Attributes: {attrs}\n"

            self.details_text.delete("1.0", "end")
            self.details_text.insert("1.0", details)

        except Exception as e:
            self.details_text.delete("1.0", "end")
            self.details_text.insert("1.0", f"Error loading file details:\n{str(e)}")

    def get_file_attributes(self, filepath):
        """Get file attributes string"""
        try:
            import stat
            attrs = []
            mode = os.stat(filepath).st_mode

            if stat.S_ISDIR(mode):
                attrs.append('D')
            if mode & stat.S_IREAD:
                attrs.append('R')
            if mode & stat.S_IWRITE:
                attrs.append('W')
            if mode & stat.S_IEXEC:
                attrs.append('X')

            return ''.join(attrs)
        except:
            return "Unknown"

    def is_system_file(self, filepath):
        """Check if file is a system file"""
        system_dirs = ['C:\\Windows', 'C:\\System32', 'C:\\Program Files', 'C:\\Program Files (x86)']
        return any(filepath.lower().startswith(dir.lower()) for dir in system_dirs)

    def new_scan(self):
        """Start a new scan"""
        if self.scanning:
            if not messagebox.askyesno("Scan in Progress",
                                       "A scan is in progress. Stop it and start a new one?"):
                return
            self.stop_scan()

        # Clear results
        self.results = []
        self.filtered_results = []

        # Clear UI
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.details_text.delete("1.0", "end")
        self.update_statistics()
        self.update_file_count()
        self.update_status("Ready for new scan")

    def save_results(self):
        """Save results to file"""
        if not self.results:
            messagebox.showwarning("No Results", "No scan results to save!")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"DLL File Scan Results\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total files: {len(self.results)}\n")
                    f.write("=" * 80 + "\n\n")

                    for result in self.results:
                        size_mb = result['size'] / (1024 * 1024)
                        f.write(f"File: {result['filename']}\n")
                        f.write(f"Path: {result['path']}\n")
                        f.write(f"Size: {result['size']:,} bytes ({size_mb:.2f} MB)\n")
                        f.write(f"Modified: {result['modified']}\n")
                        f.write(f"Attributes: {result['attributes']}\n")
                        f.write("-" * 60 + "\n")

                messagebox.showinfo("Success", f"Results saved to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file:\n{str(e)}")

    def export_csv(self):
        """Export results as CSV"""
        if not self.results:
            messagebox.showwarning("No Results", "No scan results to export!")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Filename', 'Path', 'Size (bytes)', 'Modified', 'Attributes'])

                    for result in self.results:
                        writer.writerow([
                            result['filename'],
                            result['path'],
                            result['size'],
                            result['modified'].strftime('%Y-%m-%d %H:%M:%S'),
                            result['attributes']
                        ])

                messagebox.showinfo("Success", f"Results exported to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export file:\n{str(e)}")

    def export_json(self):
        """Export results as JSON"""
        if not self.results:
            messagebox.showwarning("No Results", "No scan results to export!")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if filename:
            try:
                # Convert datetime objects to strings
                export_data = []
                for result in self.results:
                    result_copy = result.copy()
                    result_copy['modified'] = result['modified'].isoformat()
                    export_data.append(result_copy)

                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)

                messagebox.showinfo("Success", f"Results exported to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export file:\n{str(e)}")

    def export_selected(self):
        """Export selected items"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select files to export!")
            return

        # Get selected items data
        selected_data = []
        for item_id in selection:
            item = self.tree.item(item_id)
            if item['values']:
                selected_data.append(item['values'])

        messagebox.showinfo("Export", f"Would export {len(selected_data)} selected files.")

    def quick_scan(self, scan_type):
        """Perform a quick scan of common locations"""
        if scan_type == "system32":
            self.dir_var.set("C:\\Windows\\System32")
        elif scan_type == "windows":
            self.dir_var.set("C:\\Windows")

        self.max_files_var.set("1000")
        self.start_scan()

    def scan_all_drives(self):
        """Scan all available drives"""
        drives = self.get_available_drives()
        if not drives:
            messagebox.showwarning("No Drives", "No drives found to scan!")
            return

        self.dir_var.set("C:\\")
        self.max_files_var.set("50000")
        self.start_scan()

    def show_dll_properties(self):
        """Show properties of selected DLL"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a DLL file!")
            return

        item = self.tree.item(selection[0])
        values = item['values']
        if values and len(values) >= 2:
            filepath = values[1]
            self.show_file_details(filepath)

    def find_duplicates(self):
        """Find duplicate DLL files"""
        if not self.results:
            messagebox.showwarning("No Results", "Scan for files first!")
            return

        duplicates = {}
        for result in self.results:
            filename = result['filename'].lower()
            if filename in duplicates:
                duplicates[filename].append(result)
            else:
                duplicates[filename] = [result]

        # Filter to only duplicates
        duplicates = {k: v for k, v in duplicates.items() if len(v) > 1}

        if not duplicates:
            messagebox.showinfo("No Duplicates", "No duplicate DLL files found!")
            return

        # Show duplicates in a new window
        self.show_duplicates_window(duplicates)

    def show_duplicates_window(self, duplicates):
        """Show duplicates in a new window"""
        window = ctk.CTkToplevel(self.root)
        window.title(f"Duplicate Files ({len(duplicates)} found)")
        window.geometry("800x500")

        # Create Treeview
        tree_frame = ctk.CTkFrame(window)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)

        tree = ttk.Treeview(tree_frame, columns=('filename', 'count', 'locations'))

        tree.heading('#0', text='#')
        tree.heading('filename', text='Filename')
        tree.heading('count', text='Count')
        tree.heading('locations', text='Locations')

        # Add scrollbars
        tree_scroll_y = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

        tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll_y.grid(row=0, column=1, sticky="ns")
        tree_scroll_x.grid(row=1, column=0, sticky="ew", columnspan=2)

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        for i, (filename, files) in enumerate(duplicates.items()):
            locations = '\n'.join([f['directory'] for f in files[:3]])  # Show first 3 locations
            if len(files) > 3:
                locations += f'\n... and {len(files) - 3} more'

            tree.insert('', 'end', text=str(i + 1),
                        values=(filename, len(files), locations))

    def analyze_sizes(self):
        """Analyze file size distribution"""
        if not self.results:
            messagebox.showwarning("No Results", "Scan for files first!")
            return

        # Create histogram of file sizes
        sizes = [r['size'] / (1024 * 1024) for r in self.results]  # Convert to MB

        # Show size analysis in a dialog
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Size Analysis")
        dialog.geometry("400x400")

        # Calculate statistics
        import statistics
        avg_size = statistics.mean(sizes) if sizes else 0
        median_size = statistics.median(sizes) if sizes else 0
        max_size = max(sizes) if sizes else 0
        min_size = min(sizes) if sizes else 0

        text = f"Size Analysis for {len(sizes)} files:\n\n"
        text += f"Average Size: {avg_size:.2f} MB\n"
        text += f"Median Size: {median_size:.2f} MB\n"
        text += f"Maximum Size: {max_size:.2f} MB\n"
        text += f"Minimum Size: {min_size:.2f} MB\n"
        text += f"Total Size: {sum(sizes):.2f} MB\n"

        # Size categories
        small = len([s for s in sizes if s < 1])
        medium = len([s for s in sizes if 1 <= s < 10])
        large = len([s for s in sizes if s >= 10])

        text += f"\nSize Categories:\n"
        text += f"Small (<1 MB): {small} files\n"
        text += f"Medium (1-10 MB): {medium} files\n"
        text += f"Large (>=10 MB): {large} files\n"

        label = ctk.CTkLabel(dialog, text=text, font=self.normal_font,
                             justify="left", padx=20, pady=20)
        label.pack(fill="both", expand=True)

    def refresh_list(self):
        """Refresh the results list"""
        self.update_results_list()

    def clear_results(self):
        """Clear all results"""
        if messagebox.askyesno("Clear Results", "Are you sure you want to clear all results?"):
            self.results = []
            self.filtered_results = []
            self.update_results_list()
            self.update_statistics()
            self.update_status("Results cleared")

    def group_by_directory(self):
        """Group results by directory"""
        if not self.results:
            return

        # Group by directory
        grouped = {}
        for result in self.results:
            directory = result['directory']
            if directory not in grouped:
                grouped[directory] = []
            grouped[directory].append(result)

        # Clear and display grouped
        for item in self.tree.get_children():
            self.tree.delete(item)

        i = 0
        for directory, files in sorted(grouped.items()):
            # Add directory node
            dir_node = self.tree.insert('', 'end', text=str(i + 1),
                                        values=(f"[DIR] {os.path.basename(directory)}",
                                                directory, f"{len(files)} files", "", ""))
            i += 1

            # Add files under directory
            for file in files[:10]:  # Limit files per directory for display
                size_mb = file['size'] / (1024 * 1024)
                self.tree.insert(dir_node, 'end', text="",
                                 values=(file['filename'],
                                         file['path'],
                                         f"{size_mb:.2f} MB",
                                         file['modified'].strftime('%Y-%m-%d %H:%M:%S'),
                                         file['attributes']))

    def sort_results(self, sort_by='size'):
        """Sort results"""
        if not self.results:
            return

        if sort_by == 'size':
            self.results.sort(key=lambda x: x['size'], reverse=True)
        elif sort_by == 'name':
            self.results.sort(key=lambda x: x['filename'].lower())
        elif sort_by == 'date':
            self.results.sort(key=lambda x: x['modified'], reverse=True)

        self.filtered_results = self.results.copy()
        self.update_results_list()

    def show_help(self):
        """Show help dialog"""
        help_text = """
        DLL File Scanner - User Guide

        1. Scan Options:
           - Select drive or directory to scan
           - Set maximum files limit
           - Choose whether to scan subdirectories

        2. Starting a Scan:
           - Click 'Start Scan' or press F5
           - Use 'Stop Scan' or F6 to stop

        3. Working with Results:
           - Double-click a file to see details
           - Use filters to narrow results
           - Export results to various formats

        4. Tools:
           - Find duplicate files
           - Analyze file sizes
           - Compare scan results

        Tips:
        - Run as Administrator for complete system scan
        - Large scans may take time
        - Use filters to manage large result sets
        """

        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Help - DLL File Scanner - by ayman azhar")
        dialog.geometry("500x400")

        text = ctk.CTkTextbox(dialog, font=self.normal_font, wrap="word")
        text.pack(fill="both", expand=True, padx=10, pady=10)
        text.insert("1.0", help_text)
        text.configure(state="disabled")

    def show_about(self):
        """Show about dialog"""
        about_text = f"""
        DLL File Scanner & Manager

        Version: 2.0.0
        Created with Python and CustomTkinter

        Features:
        - Scan for DLL files across your system
        - View detailed file information
        - Filter and search results
        - Export to multiple formats
        - Find duplicates and analyze files

        © 2024 DLL Scanner Tool by ayman azhar https://mraymanazhar.vercel.app/
        """

        messagebox.showinfo("About DLL File Scanner - by ayman azhar", about_text)

    def load_settings(self):
        """Load application settings"""
        # In a real app, you'd load from a config file
        pass

    def save_settings(self):
        """Save application settings"""
        # In a real app, you'd save to a config file
        pass

    def bind_shortcuts(self):
        """Bind keyboard shortcuts"""
        self.root.bind('<F5>', lambda e: self.start_scan())
        self.root.bind('<F6>', lambda e: self.stop_scan())
        self.root.bind('<Control-n>', lambda e: self.new_scan())
        self.root.bind('<Control-s>', lambda e: self.save_results())
        self.root.bind('<Control-e>', lambda e: self.export_csv())
        self.root.bind('<Control-f>', lambda e: self.search_results())

    def show_file_menu(self):
        """Show file menu"""
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="New Scan", command=self.new_scan)
        menu.add_command(label="Save Results", command=self.save_results)
        menu.add_command(label="Export as CSV", command=self.export_csv)
        menu.add_command(label="Export as JSON", command=self.export_json)
        menu.add_separator()
        menu.add_command(label="Exit", command=self.root.quit)

        menu.post(self.root.winfo_pointerx(), self.root.winfo_pointery())

    def show_scan_menu(self):
        """Show scan menu"""
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Start Scan", command=self.start_scan)
        menu.add_command(label="Stop Scan", command=self.stop_scan)
        menu.add_separator()
        menu.add_command(label="Quick Scan(System32)", command=lambda: self.quick_scan("system32"))
        menu.add_command(label="Quick Scan(Windows)", command=lambda: self.quick_scan("windows"))
        menu.add_command(label="Scan All Drives", command=self.scan_all_drives)

        menu.post(self.root.winfo_pointerx(), self.root.winfo_pointery())

    def show_tools_menu(self):
        """Show tools menu"""
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="DLL Properties", command=self.show_dll_properties)
        menu.add_command(label="Find Duplicates", command=self.find_duplicates)
        menu.add_command(label="Analyze File Sizes", command=self.analyze_sizes)

        menu.post(self.root.winfo_pointerx(), self.root.winfo_pointery())

    def show_view_menu(self):
        """Show view menu"""
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Refresh List", command=self.refresh_list)
        menu.add_command(label="Group by Directory", command=self.group_by_directory)
        menu.add_command(label="Sort by Size", command=lambda: self.sort_results('size'))
        menu.add_command(label="Sort by Name", command=lambda: self.sort_results('name'))

        menu.post(self.root.winfo_pointerx(), self.root.winfo_pointery())

    def show_help_menu(self):
        """Show help menu"""
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="User Guide", command=self.show_help)
        menu.add_command(label="About", command=self.show_about)

        menu.post(self.root.winfo_pointerx(), self.root.winfo_pointery())

    def on_closing(self):
        """Handle window closing"""
        if self.scanning:
            if messagebox.askyesno("Scan in Progress",
                                   "A scan is in progress. Stop it and exit?"):
                self.stop_scan()
            else:
                return

        self.save_settings()
        self.root.destroy()


def main():
    """Main function to run the application"""
    root = ctk.CTk()

    app = DLLScannerGUI(root)

    # Handle window closing
    root.protocol("WM_DELETE_WINDOW", app.on_closing)

    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')

    root.mainloop()


if __name__ == "__main__":
    # Check dependencies
    try:
        import psutil
        import customtkinter
    except ImportError:
        print("Installing required packages...")
        import subprocess

        subprocess.check_call([sys.executable, "-m", "pip", "install",
                               "customtkinter", "psutil", "pywin32"])

    main()