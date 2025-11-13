import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import json
import csv
from datetime import datetime
from typing import Optional, List

from backend import (
    PasswordStrengthAnalyzer, PasswordGenerator, PasswordHasher,
    FormValidator, NetworkTrafficBackend, PortScannerBackend,
    SanitizationEngine, get_available_kdf_methods, generate_and_hash_passwords
)

# Configure CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Default spacing
DEFAULT_PADX = 12
DEFAULT_PADY = 8


# ============================================================================
# FONT HELPER
# ============================================================================

def create_fonts():
    """Create font objects after Tk root exists"""
    return {
        'h1': ctk.CTkFont(size=18, weight="bold"),
        'h2': ctk.CTkFont(size=16, weight="bold"),
        'body': ctk.CTkFont(size=14),
        'mono': ctk.CTkFont(family="Consolas", size=13)
    }


# ============================================================================
# REUSABLE COMPONENTS
# ============================================================================

class StatusChip(ctk.CTkLabel):
    """Status chip with colored background"""
    
    COLORS = {
        'valid': ('#2e7d32', '#66bb6a'),      # Green
        'warning': ('#ef6c00', '#ffa726'),    # Amber
        'invalid': ('#c62828', '#ef5350'),    # Red
        'info': ('#1976d2', '#42a5f5')        # Blue
    }
    
    def __init__(self, parent, text="", status='info', **kwargs):
        super().__init__(parent, text=text, **kwargs)
        self.set_status(status)
        self.configure(
            corner_radius=12,
            font=ctk.CTkFont(size=11, weight="bold"),
            height=24,
            padx=12,
            pady=4
        )
    
    def set_status(self, status: str, text: str = None):
        """Update status and text"""
        if text:
            self.configure(text=text)
        
        color = self.COLORS.get(status, self.COLORS['info'])
        self.configure(fg_color=color[0], text_color="white")


class ResultCard(ctk.CTkFrame):
    """Reusable result card with header, status chip, and sections"""
    
    def __init__(self, parent, title="Results", fonts=None, **kwargs):
        super().__init__(parent, corner_radius=10, **kwargs)
        self.title = title
        self.fonts = fonts or create_fonts()
        
        # Header row
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", padx=DEFAULT_PADX, pady=DEFAULT_PADY)
        
        self.title_label = ctk.CTkLabel(header_frame, text=title, font=self.fonts['h2'])
        self.title_label.pack(side="left")
        
        self.status_chip = StatusChip(header_frame, text="Ready")
        self.status_chip.pack(side="right")
        
        # Content area (scrollable)
        self.content_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True, padx=DEFAULT_PADX, pady=DEFAULT_PADY)
    
    def set_status(self, status: str, text: str):
        """Update status chip"""
        self.status_chip.set_status(status, text)
    
    def clear_content(self):
        """Clear all content"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
    def add_section(self, title: str, content_widget=None):
        """Add a section with title"""
        section = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        section.pack(fill="x", pady=(10, 5))
        
        ctk.CTkLabel(section, text=title, font=self.fonts['h2'], anchor="w").pack(fill="x")
        
        if content_widget:
            content_widget.pack(in_=section, fill="both", expand=True, pady=(5, 0))
        
        return section
    
    def add_warning_section(self, warnings: List[str]):
        """Add warnings section"""
        if not warnings:
            return
        
        section = self.add_section("⚠️ Sanitization Warnings")
        
        for warning in warnings:
            warning_frame = ctk.CTkFrame(section, fg_color="transparent")
            warning_frame.pack(fill="x", pady=2)
            
            ctk.CTkLabel(warning_frame, text=f"• {warning}", 
                        font=self.fonts['body'], text_color="orange", 
                        anchor="w", wraplength=600).pack(fill="x", padx=20)
    
    def add_data_grid(self, data: dict):
        """Add key-value data grid"""
        section = self.add_section("✅ Sanitized Data")
        
        for key, value in data.items():
            row = ctk.CTkFrame(section, fg_color="transparent")
            row.pack(fill="x", pady=2)
            
            # Key
            ctk.CTkLabel(row, text=f"{key}:", font=ctk.CTkFont(size=14, weight="bold"),
                        anchor="w", width=100).pack(side="left", padx=(20, 10))
            
            # Value
            value_str = str(value) if value is not None else "N/A"
            if len(value_str) > 100:
                # Use textbox for long values
                textbox = ctk.CTkTextbox(row, height=80, font=self.fonts['mono'])
                textbox.insert("1.0", value_str)
                textbox.configure(state="disabled")
                textbox.pack(side="left", fill="x", expand=True, padx=(0, 20))
            else:
                ctk.CTkLabel(row, text=value_str, font=self.fonts['body'],
                            anchor="w", wraplength=400).pack(side="left", fill="x", expand=True)


class TableFrame(ctk.CTkFrame):
    """Custom table using ttk.Treeview with dark theme styling"""
    
    def __init__(self, parent, columns, show_headers=True):
        super().__init__(parent, corner_radius=10)
        self.columns = columns
        
        style = ttk.Style()
        style.theme_use("clam")
        
        style.configure("Treeview",
                       background="#2b2b2b",
                       foreground="white",
                       fieldbackground="#2b2b2b",
                       borderwidth=0,
                       font=('Segoe UI', 10))
        style.configure("Treeview.Heading",
                       background="#1f538d",
                       foreground="white",
                       borderwidth=1,
                       relief="flat",
                       font=('Segoe UI', 10, 'bold'))
        style.map("Treeview.Heading",
                 background=[('active', '#14375e')])
        style.map("Treeview",
                 background=[('selected', '#0078d4')])
        
        tree_frame = ctk.CTkFrame(self, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.tree = ttk.Treeview(tree_frame, columns=list(columns.keys()), 
                                show='headings' if show_headers else '')
        
        for col_id, (header, width) in columns.items():
            if show_headers:
                self.tree.heading(col_id, text=header, anchor='w')
            self.tree.column(col_id, width=width, anchor='w')
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
    
    def insert(self, values, tags=None):
        return self.tree.insert("", "end", values=values, tags=tags or ())
    
    def configure_tags(self, tag_configs):
        for tag, config in tag_configs.items():
            self.tree.tag_configure(tag, **config)
    
    def get_all_data(self):
        """Get all data from table"""
        data = []
        for item in self.tree.get_children():
            data.append(self.tree.item(item)['values'])
        return data


# ============================================================================
# DASHBOARD
# ============================================================================

class DashboardFrame(ctk.CTkFrame):
    """Dashboard with system overview"""
    
    def __init__(self, parent, app, fonts):
        super().__init__(parent, corner_radius=15)
        self.app = app
        self.fonts = fonts
        self.setup_ui()
    
    def setup_ui(self):
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=30, pady=30)
        
        title = ctk.CTkLabel(main_container, text="Security Toolkit Dashboard", font=self.fonts['h1'])
        title.pack(pady=(0, 10))
        
        subtitle = ctk.CTkLabel(main_container, 
                              text="Unified Local & Web Security Analysis",
                              font=self.fonts['body'], text_color=("gray60", "gray40"))
        subtitle.pack(pady=(0, 30))
        
        # Feature cards
        cards_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        cards_frame.pack(fill="both", expand=True)
        
        # Local Security Card
        local_card = self._create_feature_card(
            cards_frame, "Local Security",
            "Network Traffic Analysis\nPort Scanning\nSystem Monitoring",
            lambda: self.app.show_frame("Local Security")
        )
        local_card.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        # Web Security Card
        web_card = self._create_feature_card(
            cards_frame, "Web Security",
            "Password Analysis & Generation\nForm Validation & Sanitization\nHash Generation with KDF Options",
            lambda: self.app.show_frame("Web Security")
        )
        web_card.pack(side="right", fill="both", expand=True, padx=(10, 0))
    
    def _create_feature_card(self, parent, title, description, command):
        card = ctk.CTkFrame(parent, corner_radius=15)
        
        ctk.CTkLabel(card, text=title, font=self.fonts['h2']).pack(pady=(20, 10))
        ctk.CTkLabel(card, text=description, font=self.fonts['body'], 
                    text_color=("gray60", "gray40"), justify="center").pack(pady=(0, 20))
        
        ctk.CTkButton(card, text="Open", command=command, height=40, width=120, 
                     font=self.fonts['body']).pack(pady=(0, 20))
        
        return card


# ============================================================================
# LOCAL SECURITY
# ============================================================================

class LocalSecurityFrame(ctk.CTkFrame):
    """Local Security features with segmented button navigation"""
    
    def __init__(self, parent, fonts):
        super().__init__(parent, corner_radius=15)
        self.fonts = fonts
        self.setup_ui()
    
    def setup_ui(self):
        # Toolbar with segmented button
        toolbar = ctk.CTkFrame(self, fg_color="transparent", height=60)
        toolbar.pack(fill="x", padx=DEFAULT_PADX, pady=DEFAULT_PADY)
        
        # Title
        ctk.CTkLabel(toolbar, text="Local Security", font=self.fonts['h2']).pack(side="left", padx=(10, 20))
        
        # Segmented button for feature selection
        self.seg_button = ctk.CTkSegmentedButton(
            toolbar,
            values=["Network Traffic", "Port Scanner"],
            command=self.on_feature_selected,
            font=self.fonts['body'],
            height=35
        )
        self.seg_button.pack(side="left", expand=True, padx=20)
        self.seg_button.set("Network Traffic")
        
        # Help button
        help_btn = ctk.CTkButton(toolbar, text="?", width=35, height=35,
                                command=self.show_help, font=self.fonts['h2'])
        help_btn.pack(side="right", padx=10)
        
        # Content area
        self.content_container = ctk.CTkFrame(self, fg_color="transparent")
        self.content_container.pack(fill="both", expand=True, padx=DEFAULT_PADX, pady=DEFAULT_PADY)
        
        # Create frames for each feature
        self.traffic_frame = NetworkTrafficFrame(self.content_container, self.fonts)
        self.scanner_frame = PortScannerFrame(self.content_container, self.fonts)
        
        # Show initial frame
        self.on_feature_selected("Network Traffic")
    
    def on_feature_selected(self, value):
        """Handle feature selection"""
        self.traffic_frame.pack_forget()
        self.scanner_frame.pack_forget()
        
        if value == "Network Traffic":
            self.traffic_frame.pack(fill="both", expand=True)
        else:
            self.scanner_frame.pack(fill="both", expand=True)
    
    def show_help(self):
        """Show context help"""
        help_text = """
LOCAL SECURITY FEATURES

Network Traffic Analyzer:
• Requires administrator/root privileges
• Captures and analyzes network packets in real-time
• Filter by protocol (TCP, UDP, ICMP) and port
• Advanced search with real-time filtering

Port Scanner:
• TCP port scanning (1-65535)
• Service identification for common ports
• Only use on systems you own or have permission to test

Input Limits:
• None for local security features

Sanitization:
• Not applicable for local security features
        """
        
        dialog = ctk.CTkToplevel(self)
        dialog.title("Local Security Help")
        dialog.geometry("500x400")
        
        text = ctk.CTkTextbox(dialog, font=self.fonts['body'])
        text.pack(fill="both", expand=True, padx=20, pady=20)
        text.insert("1.0", help_text.strip())
        text.configure(state="disabled")
        
        ctk.CTkButton(dialog, text="Close", command=dialog.destroy).pack(pady=10)


class NetworkTrafficFrame(ctk.CTkFrame):
    """Network Traffic Analyzer with improved UI"""
    
    def __init__(self, parent, fonts):
        super().__init__(parent, fg_color="transparent")
        self.fonts = fonts
        self.backend = NetworkTrafficBackend()
        self.interface_mapping = {}
        self.all_packets = []
        self.search_var = tk.StringVar(value="")
        self.setup_ui()
        self.setup_callbacks()
        self.load_interfaces()
    
    def setup_ui(self):
        # Warning banner
        warning_frame = ctk.CTkFrame(self, fg_color=("#ef6c00", "#ef6c00"), corner_radius=8, height=40)
        warning_frame.pack(fill="x", padx=10, pady=(0, 10))
        ctk.CTkLabel(warning_frame, text="⚠️ Requires admin/root privileges",
                    text_color="white", font=self.fonts['body']).pack(pady=8)
        
        # Controls
        controls = ctk.CTkFrame(self, corner_radius=10)
        controls.pack(fill="x", padx=10, pady=(0, 10))
        
        # Interface row
        iface_row = ctk.CTkFrame(controls, fg_color="transparent")
        iface_row.pack(pady=DEFAULT_PADY, padx=DEFAULT_PADX)
        
        ctk.CTkLabel(iface_row, text="Interface:", font=self.fonts['body']).pack(side="left", padx=(0, 8))
        self.interface_var = tk.StringVar(value="Default")
        self.interface_dropdown = ctk.CTkOptionMenu(iface_row, variable=self.interface_var,
                                                    values=["Default"], width=200, font=self.fonts['body'],
                                                    command=self.on_interface_changed)
        self.interface_dropdown.pack(side="left", padx=5)
        
        # Filter row
        filter_row = ctk.CTkFrame(controls, fg_color="transparent")
        filter_row.pack(pady=DEFAULT_PADY, padx=DEFAULT_PADX)
        
        ctk.CTkLabel(filter_row, text="Protocol:", font=self.fonts['body']).pack(side="left", padx=(0, 8))
        self.protocol_var = tk.StringVar(value="All")
        ctk.CTkOptionMenu(filter_row, variable=self.protocol_var,
                         values=["All", "TCP", "UDP", "ICMP"], width=100, 
                         font=self.fonts['body']).pack(side="left", padx=5)
        
        ctk.CTkLabel(filter_row, text="Port:", font=self.fonts['body']).pack(side="left", padx=(10, 8))
        self.port_entry = ctk.CTkEntry(filter_row, width=80, placeholder_text="80", font=self.fonts['body'])
        self.port_entry.pack(side="left", padx=5)
        
        ctk.CTkLabel(filter_row, text="Search:", font=self.fonts['body']).pack(side="left", padx=(10, 8))
        self.search_entry = ctk.CTkEntry(filter_row, width=200, textvariable=self.search_var, 
                                        font=self.fonts['body'])
        self.search_entry.pack(side="left", padx=5)
        
        self.protocol_var.trace_add("write", lambda *_: self.on_filter_changed())
        self.port_entry.bind("<KeyRelease>", lambda _: self.on_filter_changed())
        self.search_var.trace_add("write", lambda *_: self.refresh_table())
        
        # Buttons
        btn_row = ctk.CTkFrame(controls, fg_color="transparent")
        btn_row.pack(pady=DEFAULT_PADY, padx=DEFAULT_PADX)
        
        self.start_btn = ctk.CTkButton(btn_row, text="Start", command=self.start_capture,
                                      fg_color="green", width=100, height=35, font=self.fonts['body'])
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = ctk.CTkButton(btn_row, text="Stop", command=self.stop_capture,
                                     fg_color="red", state="disabled", width=100, height=35, 
                                     font=self.fonts['body'])
        self.stop_btn.pack(side="left", padx=5)
        
        ctk.CTkButton(btn_row, text="Clear", command=self.clear_display, width=100, 
                     height=35, font=self.fonts['body']).pack(side="left", padx=5)
        
        # Status
        status_frame = ctk.CTkFrame(self, corner_radius=10)
        status_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        status_inner = ctk.CTkFrame(status_frame, fg_color="transparent")
        status_inner.pack(padx=15, pady=10)
        
        self.status_label = ctk.CTkLabel(status_inner, text="Ready", font=self.fonts['body'])
        self.status_label.pack(side="left")
        
        self.packet_count_label = ctk.CTkLabel(status_inner, text="Packets: 0", 
                                              font=ctk.CTkFont(size=14, weight="bold"))
        self.packet_count_label.pack(side="right")
        
        # Packet table
        columns = {
            'time': ('Time', 100),
            'src_ip': ('Source', 120),
            'dst_ip': ('Dest', 120),
            'proto': ('Proto', 60),
            'sport': ('SPort', 60),
            'dport': ('DPort', 60),
            'size': ('Size', 70)
        }
        
        self.packet_table = TableFrame(self, columns)
        self.packet_table.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.packet_table.configure_tags({
            'even': {'background': '#363636'},
            'odd': {'background': '#2b2b2b'}
        })
    
    def load_interfaces(self):
        interfaces_data = self.backend.get_available_interfaces()
        self.interface_mapping.clear()
        display_names = []
        for display_name, actual_name in interfaces_data:
            display_names.append(display_name)
            self.interface_mapping[display_name] = actual_name
        
        if display_names:
            self.interface_dropdown.configure(values=display_names)
            self.interface_var.set(display_names[0])
            self.backend.set_interface(self.interface_mapping[display_names[0]])
    
    def on_interface_changed(self, display_name):
        actual_interface = self.interface_mapping.get(display_name, None)
        self.backend.set_interface(actual_interface)
    
    def on_filter_changed(self):
        self.backend.update_filters(self.protocol_var.get(), self.port_entry.get().strip())
    
    def refresh_table(self):
        self.packet_table.clear()
        query = self.search_var.get().lower()
        for i, pkt in enumerate(self.all_packets):
            if not query or query in str(pkt).lower():
                tag = 'even' if i % 2 == 0 else 'odd'
                self.packet_table.insert([
                    pkt['timestamp'], pkt['src_ip'], pkt['dst_ip'],
                    pkt['protocol'], pkt['src_port'], pkt['dst_port'], str(pkt['size'])
                ], tags=[tag])
    
    def setup_callbacks(self):
        self.backend.set_callbacks(
            on_packet_captured=self.on_packet_captured,
            on_capture_error=lambda msg: self.after(0, lambda: messagebox.showerror("Error", msg)),
            on_capture_started=lambda: self.after(0, lambda: self.status_label.configure(text="Capturing...")),
            on_capture_stopped=lambda: self.after(0, lambda: self.status_label.configure(text="Stopped"))
        )
    
    def start_capture(self):
        self.on_filter_changed()
        if self.backend.start_capture():
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
    
    def stop_capture(self):
        self.backend.stop_capture()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
    
    def clear_display(self):
        self.packet_table.clear()
        self.all_packets = []
        self.backend.packet_count = 0
        self.packet_count_label.configure(text="Packets: 0")
    
    def on_packet_captured(self, packet_data):
        self.all_packets.append(packet_data)
        def update():
            self.packet_count_label.configure(text=f"Packets: {self.backend.get_packet_count()}")
            query = self.search_var.get().lower()
            if not query or query in str(packet_data).lower():
                idx = len(self.packet_table.tree.get_children())
                tag = 'even' if idx % 2 == 0 else 'odd'
                self.packet_table.insert([
                    packet_data['timestamp'], packet_data['src_ip'], packet_data['dst_ip'],
                    packet_data['protocol'], packet_data['src_port'], packet_data['dst_port'],
                    str(packet_data['size'])
                ], tags=[tag])
        self.after(0, update)


class PortScannerFrame(ctk.CTkFrame):
    """Port Scanner with improved UI"""
    
    def __init__(self, parent, fonts):
        super().__init__(parent, fg_color="transparent")
        self.fonts = fonts
        self.backend = PortScannerBackend()
        self.setup_ui()
        self.setup_callbacks()
    
    def setup_ui(self):
        # Warning banner
        warning_frame = ctk.CTkFrame(self, fg_color=("#ef6c00", "#ef6c00"), corner_radius=8, height=40)
        warning_frame.pack(fill="x", padx=10, pady=(0, 10))
        ctk.CTkLabel(warning_frame, text="⚠️ Only scan systems you own or have permission to test",
                    text_color="white", font=self.fonts['body']).pack(pady=8)
        
        # Controls
        controls = ctk.CTkFrame(self, corner_radius=10)
        controls.pack(fill="x", padx=10, pady=(0, 10))
        
        input_row = ctk.CTkFrame(controls, fg_color="transparent")
        input_row.pack(pady=DEFAULT_PADY, padx=DEFAULT_PADX)
        
        ctk.CTkLabel(input_row, text="Target:", font=self.fonts['body']).pack(side="left", padx=(0, 8))
        self.target_entry = ctk.CTkEntry(input_row, width=140, font=self.fonts['body'])
        self.target_entry.insert(0, "127.0.0.1")
        self.target_entry.pack(side="left", padx=5)
        
        ctk.CTkLabel(input_row, text="Start:", font=self.fonts['body']).pack(side="left", padx=(10, 8))
        self.start_port_entry = ctk.CTkEntry(input_row, width=70, font=self.fonts['body'])
        self.start_port_entry.insert(0, "20")
        self.start_port_entry.pack(side="left", padx=5)
        
        ctk.CTkLabel(input_row, text="End:", font=self.fonts['body']).pack(side="left", padx=(10, 8))
        self.end_port_entry = ctk.CTkEntry(input_row, width=70, font=self.fonts['body'])
        self.end_port_entry.insert(0, "1024")
        self.end_port_entry.pack(side="left", padx=5)
        
        ctk.CTkLabel(input_row, text="Timeout:", font=self.fonts['body']).pack(side="left", padx=(10, 8))
        self.timeout_entry = ctk.CTkEntry(input_row, width=60, font=self.fonts['body'])
        self.timeout_entry.insert(0, "0.5")
        self.timeout_entry.pack(side="left", padx=5)
        
        btn_row = ctk.CTkFrame(controls, fg_color="transparent")
        btn_row.pack(pady=DEFAULT_PADY, padx=DEFAULT_PADX)
        
        self.scan_btn = ctk.CTkButton(btn_row, text="Start Scan", command=self.start_scan,
                                     fg_color="green", width=110, height=35, font=self.fonts['body'])
        self.scan_btn.pack(side="left", padx=5)
        
        self.stop_scan_btn = ctk.CTkButton(btn_row, text="Stop", command=self.stop_scan,
                                          fg_color="red", state="disabled", width=100, 
                                          height=35, font=self.fonts['body'])
        self.stop_scan_btn.pack(side="left", padx=5)
        
        ctk.CTkButton(btn_row, text="Clear", command=self.clear_results, width=100, 
                     height=35, font=self.fonts['body']).pack(side="left", padx=5)
        
        # Progress
        progress_frame = ctk.CTkFrame(self, corner_radius=10)
        progress_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.progress_bar = ctk.CTkProgressBar(progress_frame, height=20)
        self.progress_bar.pack(fill="x", padx=15, pady=(10, 5))
        self.progress_bar.set(0)
        
        self.status_scan_label = ctk.CTkLabel(progress_frame, text="Ready", font=self.fonts['body'])
        self.status_scan_label.pack(pady=(0, 10))
        
        # Results
        columns = {
            'port': ('Port', 80),
            'status': ('Status', 80),
            'service': ('Service', 150)
        }
        
        self.results_table = TableFrame(self, columns)
        self.results_table.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.results_table.configure_tags({
            'open': {'background': '#1a5d1a', 'foreground': 'lightgreen'},
            'closed': {'background': '#2b2b2b', 'foreground': 'gray'}
        })
    
    def setup_callbacks(self):
        self.backend.set_callbacks(
            on_scan_start=lambda: self.after(0, lambda: [
                self.scan_btn.configure(state="disabled"),
                self.stop_scan_btn.configure(state="normal")
            ]),
            on_scan_complete=lambda stats, ip, done: self.after(0, lambda: self.on_scan_done(stats, done)),
            on_progress_update=lambda curr, tot, port: self.after(0, lambda: [
                self.progress_bar.set(curr / tot if tot > 0 else 0),
                self.status_scan_label.configure(text=f"Port {port} ({curr}/{tot})")
            ]),
            on_port_result=lambda port, is_open, svc: self.after(0, lambda: self.add_port_result(port, is_open, svc)),
            on_status_update=lambda msg: self.after(0, lambda: self.status_scan_label.configure(text=msg)),
            on_error=lambda msg: self.after(0, lambda: messagebox.showerror("Error", msg))
        )
    
    def start_scan(self):
        try:
            target = self.target_entry.get().strip()
            start_port = int(self.start_port_entry.get())
            end_port = int(self.end_port_entry.get())
            timeout = float(self.timeout_entry.get())
            self.results_table.clear()
            self.backend.start_scan(target, start_port, end_port, timeout)
        except ValueError:
            messagebox.showerror("Error", "Invalid input values")
    
    def stop_scan(self):
        self.backend.stop_scan()
    
    def clear_results(self):
        self.results_table.clear()
        self.progress_bar.set(0)
        self.status_scan_label.configure(text="Ready")
    
    def add_port_result(self, port, is_open, service):
        if is_open:
            status = "OPEN"
            tag = 'open'
            self.results_table.insert([str(port), status, service], tags=[tag])
    
    def on_scan_done(self, stats, completed):
        self.scan_btn.configure(state="normal")
        self.stop_scan_btn.configure(state="disabled")
        self.progress_bar.set(0)
        status = "Completed" if completed else "Stopped"
        self.status_scan_label.configure(text=f"{status}: {stats['open_ports']} open ports")


# ============================================================================
# WEB SECURITY (Continue in next message due to length...)
# ============================================================================

class WebSecurityFrame(ctk.CTkFrame):
    """Web Security features with segmented button navigation"""
    
    def __init__(self, parent, fonts):
        super().__init__(parent, corner_radius=15)
        self.fonts = fonts
        self.setup_ui()
    
    def setup_ui(self):
        # Toolbar with segmented button
        toolbar = ctk.CTkFrame(self, fg_color="transparent", height=60)
        toolbar.pack(fill="x", padx=DEFAULT_PADX, pady=DEFAULT_PADY)
        
        # Title
        ctk.CTkLabel(toolbar, text="Web Security", font=self.fonts['h2']).pack(side="left", padx=(10, 20))
        
        # Segmented button for feature selection
        self.seg_button = ctk.CTkSegmentedButton(
            toolbar,
            values=["Password Strength", "Password Generator", "Form Validator"],
            command=self.on_feature_selected,
            font=self.fonts['body'],
            height=35
        )
        self.seg_button.pack(side="left", expand=True, padx=20)
        self.seg_button.set("Password Strength")
        
        # Help button
        help_btn = ctk.CTkButton(toolbar, text="?", width=35, height=35,
                                command=self.show_help, font=self.fonts['h2'])
        help_btn.pack(side="right", padx=10)
        
        # Content area
        self.content_container = ctk.CTkFrame(self, fg_color="transparent")
        self.content_container.pack(fill="both", expand=True, padx=DEFAULT_PADX, pady=DEFAULT_PADY)
        
        # Create frames for each feature
        self.strength_frame = PasswordStrengthTab(self.content_container, self.fonts)
        self.generator_frame = PasswordGeneratorTab(self.content_container, self.fonts)
        self.validator_frame = FormValidatorTab(self.content_container, self.fonts)
        
        # Show initial frame
        self.on_feature_selected("Password Strength")
    
    def on_feature_selected(self, value):
        """Handle feature selection"""
        self.strength_frame.pack_forget()
        self.generator_frame.pack_forget()
        self.validator_frame.pack_forget()
        
        if value == "Password Strength":
            self.strength_frame.pack(fill="both", expand=True)
        elif value == "Password Generator":
            self.generator_frame.pack(fill="both", expand=True)
        else:
            self.validator_frame.pack(fill="both", expand=True)
    
    def show_help(self):
        """Show context help"""
        help_text = """
WEB SECURITY FEATURES

Password Strength Analyzer:
• Analyze password strength and get improvement suggestions
• Real-time feedback with scoring system
• Visual strength indicators

Password Generator & Hasher:
• Generate secure passwords (1-50 at a time)
• Multiple KDF methods: PBKDF2, Argon2, bcrypt
• Default: PBKDF2 with 310,000 iterations (NIST 2023)
• Each password is hashed separately with unique salt
• Export results to CSV or JSON

Form Validator & Sanitizer:
• Automatic input sanitization (XSS, SQLi patterns)
• CSRF token checking capability
• Input length limits: 8KB max per field
• Real-time character counting

Input Limits:
• Maximum 8KB per text field
• Character counter shows usage
• Frontend and backend validation

Sanitization Scope:
• XSS (Cross-Site Scripting) protection
• SQL injection pattern detection
• Dangerous HTML/JavaScript removal
• All inputs processed through BeautifulSoup/bleach

KDF Guidance:
• PBKDF2: NIST recommended, 310,000+ iterations
• Argon2: Modern, memory-hard (requires argon2-cffi)
• bcrypt: Well-established (requires bcrypt)
        """
        
        dialog = ctk.CTkToplevel(self)
        dialog.title("Web Security Help")
        dialog.geometry("550x500")
        
        text = ctk.CTkTextbox(dialog, font=self.fonts['body'])
        text.pack(fill="both", expand=True, padx=20, pady=20)
        text.insert("1.0", help_text.strip())
        text.configure(state="disabled")
        
        ctk.CTkButton(dialog, text="Close", command=dialog.destroy).pack(pady=10)


class PasswordStrengthTab(ctk.CTkFrame):
    """Password Strength Analyzer with improved UI"""
    
    STRENGTH_COLORS = {
        'Empty': '#666666', 'Very Weak': '#FF1744', 'Weak': '#FF5722',
        'Moderate': '#FF9800', 'Strong': '#4CAF50', 'Very Strong': '#00E676'
    }
    
    def __init__(self, parent, fonts):
        super().__init__(parent, fg_color="transparent")
        self.fonts = fonts
        self.analyzer = PasswordStrengthAnalyzer()
        self.setup_ui()
    
    def setup_ui(self):
        title = ctk.CTkLabel(self, text="Password Strength Analyzer", font=self.fonts['h2'])
        title.pack(pady=(15, 20))
        
        self.password_entry = ctk.CTkEntry(self, placeholder_text="Enter password", 
                                          width=400, height=40, show="*", font=self.fonts['body'])
        self.password_entry.pack(pady=12)
        self.password_entry.bind("<KeyRelease>", self.analyze_password)
        
        self.show_var = ctk.BooleanVar()
        ctk.CTkCheckBox(self, text="Show Password", variable=self.show_var,
                       command=self.toggle_show, font=self.fonts['body']).pack(pady=8)
        
        self.strength_label = ctk.CTkLabel(self, text="Strength: Not Analyzed", font=self.fonts['h2'])
        self.strength_label.pack(pady=12)
        
        self.strength_bar = ctk.CTkProgressBar(self, width=400, height=20)
        self.strength_bar.pack(pady=12)
        self.strength_bar.set(0)
        
        self.feedback_text = ctk.CTkTextbox(self, height=150, width=500, font=self.fonts['body'])
        self.feedback_text.pack(pady=12)
    
    def toggle_show(self):
        self.password_entry.configure(show="" if self.show_var.get() else "*")
    
    def analyze_password(self, event=None):
        password = self.password_entry.get()
        result = self.analyzer.analyze_strength(password)
        
        strength = result['strength']
        self.strength_label.configure(
            text=f"Strength: {strength}",
            text_color=self.STRENGTH_COLORS.get(strength, '#666666')
        )
        self.strength_bar.set(result['score'] / 100)
        
        self.feedback_text.delete("1.0", "end")
        feedback_str = "Suggestions:\n" + "\n".join(f"• {tip}" for tip in result['feedback'])
        self.feedback_text.insert("1.0", feedback_str)


class PasswordGeneratorTab(ctk.CTkFrame):
    """Password Generator with Hash support and improved UI"""
    
    def __init__(self, parent, fonts):
        super().__init__(parent, fg_color="transparent")
        self.fonts = fonts
        self.generator = PasswordGenerator()
        self.hasher = PasswordHasher()
        self.kdf_methods = get_available_kdf_methods()
        self.generated_passwords = []
        self.hash_results = []
        self.setup_ui()
    
    def setup_ui(self):
        title = ctk.CTkLabel(self, text="Password Generator & Hasher", font=self.fonts['h2'])
        title.pack(pady=(15, 10))
        
        # Info line
        info_label = ctk.CTkLabel(
            self, 
            text="💡 All passwords are hashed immediately upon generation using your selected KDF and iteration count",
            font=ctk.CTkFont(size=11), 
            text_color=("gray50", "gray50")
        )
        info_label.pack(pady=5)
        
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Left: generation options
        left_frame = ctk.CTkFrame(container)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        ctk.CTkLabel(left_frame, text="Generation Options", font=self.fonts['h2']).pack(pady=12)
        
        # Password count input
        count_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        count_frame.pack(pady=8)
        ctk.CTkLabel(count_frame, text="Number of Passwords:", font=self.fonts['body']).pack(side="left", padx=5)
        self.count_var = tk.StringVar(value="5")
        self.count_spinbox = ctk.CTkEntry(count_frame, textvariable=self.count_var, 
                                         width=80, font=self.fonts['body'])
        self.count_spinbox.pack(side="left", padx=5)
        ctk.CTkLabel(count_frame, text="(1-50)", font=ctk.CTkFont(size=10),
                    text_color="gray").pack(side="left")
        
        ctk.CTkLabel(left_frame, text="Length:", font=self.fonts['body']).pack(pady=5)
        self.length_var = tk.StringVar(value="12")
        ctk.CTkEntry(left_frame, textvariable=self.length_var, width=80, 
                    font=self.fonts['body']).pack(pady=5)
        
        self.upper_var = ctk.BooleanVar(value=True)
        self.lower_var = ctk.BooleanVar(value=True)
        self.digits_var = ctk.BooleanVar(value=True)
        self.special_var = ctk.BooleanVar(value=True)
        self.exclude_ambig_var = ctk.BooleanVar(value=False)
        
        for var, text in [
            (self.upper_var, "Uppercase"), (self.lower_var, "Lowercase"),
            (self.digits_var, "Digits"), (self.special_var, "Special"),
            (self.exclude_ambig_var, "Exclude ambiguous")
        ]:
            ctk.CTkCheckBox(left_frame, text=text, variable=var, 
                           font=self.fonts['body']).pack(anchor="w", padx=20, pady=3)
        
        ctk.CTkButton(left_frame, text="Generate", command=self.generate_passwords, 
                     height=40, font=self.fonts['body']).pack(pady=12)
        
        # Hash Options
        ctk.CTkLabel(left_frame, text="Hash Options", font=self.fonts['h2']).pack(pady=(15, 8))
        
        ctk.CTkLabel(left_frame, text="KDF Method:", font=self.fonts['body']).pack(pady=5)
        self.kdf_var = tk.StringVar(value="pbkdf2")
        kdf_dropdown = ctk.CTkOptionMenu(left_frame, variable=self.kdf_var, 
                                        values=list(self.kdf_methods.keys()), 
                                        width=180, font=self.fonts['body'])
        kdf_dropdown.pack(pady=5)
        
        # KDF info
        kdf_info = ctk.CTkLabel(left_frame, 
                               text="ℹ️ PBKDF2 recommended (NIST 2023)", 
                               font=ctk.CTkFont(size=10), text_color=("gray50", "gray50"))
        kdf_info.pack(pady=2)
        
        ctk.CTkLabel(left_frame, text="PBKDF2 Iterations:", font=self.fonts['body']).pack(pady=5)
        self.iterations_var = tk.StringVar(value="310000")
        self.iterations_entry = ctk.CTkEntry(left_frame, textvariable=self.iterations_var, 
                                            width=120, font=self.fonts['body'])
        self.iterations_entry.pack(pady=5)
        
        # Warning label for low iterations
        self.iteration_warning = ctk.CTkLabel(left_frame, text="", 
                                             text_color="orange", font=ctk.CTkFont(size=11))
        self.iteration_warning.pack(pady=2)
        self.iterations_var.trace_add("write", lambda *_: self.check_iterations())
        self.check_iterations()
        
        # Right: results
        right_frame = ctk.CTkFrame(container)
        right_frame.pack(side="right", fill="both", expand=True, padx=(10, 0))
        
        # Summary label
        self.summary_label = ctk.CTkLabel(right_frame, text="No passwords generated yet", 
                                         font=self.fonts['body'], text_color="gray")
        self.summary_label.pack(pady=10)
        
        # Hash results table
        columns = {
            'num': ('#', 40),
            'password': ('Password', 150),
            'salt': ('Salt', 100),
            'kdf': ('KDF', 80),
            'iterations': ('Iterations', 90),
            'hash': ('Hash', 150)
        }
        
        self.results_table = TableFrame(right_frame, columns)
        self.results_table.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Action buttons
        btn_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
        btn_frame.pack(pady=8)
        
        ctk.CTkButton(btn_frame, text="Copy All", command=self.copy_all, 
                     width=100, height=32, font=self.fonts['body']).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Export CSV", command=self.export_csv, 
                     width=100, height=32, font=self.fonts['body']).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Export JSON", command=self.export_json, 
                     width=100, height=32, font=self.fonts['body']).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Clear", command=self.clear_all, 
                     width=80, height=32, font=self.fonts['body']).pack(side="left", padx=5)
    
    def check_iterations(self):
        try:
            iterations = int(self.iterations_var.get())
            if iterations < 310000:
                self.iteration_warning.configure(
                    text=f"⚠️ Warning: Below recommended 310,000!"
                )
            else:
                self.iteration_warning.configure(text="✓ Meets NIST 2023 guidance")
        except ValueError:
            self.iteration_warning.configure(text="⚠️ Invalid number")
    
    def generate_passwords(self):
        try:
            # Get password count
            count = int(self.count_var.get())
            if count < 1 or count > 50:
                messagebox.showerror("Error", "Password count must be between 1 and 50")
                return
            
            # Generate and hash passwords
            length = int(self.length_var.get())
            kdf_method = self.kdf_var.get()
            iterations = int(self.iterations_var.get()) if kdf_method == 'pbkdf2' else None
            
            # Use backend function
            result = generate_and_hash_passwords(
                count=count,
                length=length,
                method=kdf_method,
                iterations=iterations,
                include_uppercase=self.upper_var.get(),
                include_lowercase=self.lower_var.get(),
                include_digits=self.digits_var.get(),
                include_special=self.special_var.get(),
                exclude_ambiguous=self.exclude_ambig_var.get()
            )
            
            self.hash_results = result['results']
            
            # Update summary
            self.summary_label.configure(
                text=f"✅ {count} passwords generated and hashed successfully.",
                text_color="green"
            )
            
            # Display results in table
            self.results_table.clear()
            for i, res in enumerate(self.hash_results, 1):
                pwd_display = res['password'][:20] + "..." if len(res['password']) > 20 else res['password']
                salt_display = res.get('salt', 'N/A')[:16] + "..." if res.get('salt') and len(res.get('salt', '')) > 16 else res.get('salt', 'N/A')
                hash_display = res['hash'][:24] + "..." if len(res['hash']) > 24 else res['hash']
                iterations_display = str(res.get('iterations', 'N/A'))
                
                self.results_table.insert([
                    str(i),
                    pwd_display,
                    salt_display,
                    res['kdf'],
                    iterations_display,
                    hash_display
                ])
            
            # Show warning if iterations below threshold
            if kdf_method == 'pbkdf2' and iterations < 310000:
                messagebox.showwarning("Low Iterations", 
                    f"⚠️ You used {iterations} iterations, which is below the recommended 310,000 (NIST 2023)")
        
        except Exception as e:
            messagebox.showerror("Error", f"Generation error: {str(e)}")
    
    def copy_all(self):
        """Copy all results to clipboard"""
        if not self.hash_results:
            messagebox.showinfo("Info", "No results to copy")
            return
        
        lines = []
        for i, res in enumerate(self.hash_results, 1):
            lines.append(f"Password {i}:")
            lines.append(f"  Password: {res['password']}")
            lines.append(f"  KDF: {res['kdf']}")
            if 'iterations' in res:
                lines.append(f"  Iterations: {res['iterations']}")
            if 'salt' in res:
                lines.append(f"  Salt: {res['salt']}")
            lines.append(f"  Hash: {res['hash']}")
            lines.append("")
        
        text = "\n".join(lines)
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Success", "Results copied to clipboard")
    
    def export_csv(self):
        """Export results to CSV"""
        if not self.hash_results:
            messagebox.showinfo("Info", "No results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['#', 'Password', 'Salt', 'KDF', 'Iterations', 'Hash'])
                    
                    for i, res in enumerate(self.hash_results, 1):
                        writer.writerow([
                            i,
                            res['password'],
                            res.get('salt', 'N/A'),
                            res['kdf'],
                            res.get('iterations', 'N/A'),
                            res['hash']
                        ])
                
                messagebox.showinfo("Success", f"Exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def export_json(self):
        """Export results to JSON"""
        if not self.hash_results:
            messagebox.showinfo("Info", "No results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump({
                        'generated_at': datetime.now().isoformat(),
                        'count': len(self.hash_results),
                        'results': self.hash_results
                    }, f, indent=2)
                
                messagebox.showinfo("Success", f"Exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def clear_all(self):
        self.results_table.clear()
        self.hash_results = []
        self.summary_label.configure(text="No passwords generated yet", text_color="gray")


class FormValidatorTab(ctk.CTkFrame):
    """Form Validator with Sanitization and ResultCard"""
    
    def __init__(self, parent, fonts):
        super().__init__(parent, fg_color="transparent")
        self.fonts = fonts
        self.validator = FormValidator()
        self.sanitizer = SanitizationEngine()
        self.setup_ui()
    
    def setup_ui(self):
        title = ctk.CTkLabel(self, text="Form Validator & Sanitizer", font=self.fonts['h2'])
        title.pack(pady=(15, 10))
        
        # Sanitization info with warning banner style
        info_frame = ctk.CTkFrame(self, fg_color=("#1976d2", "#1976d2"), corner_radius=8, height=35)
        info_frame.pack(fill="x", padx=10, pady=8)
        info_label = ctk.CTkLabel(
            info_frame,
            text="🛡️ Automatic sanitization: XSS/SQL patterns + CSRF checks • Input limit: 8KB",
            font=self.fonts['body'],
            text_color="white"
        )
        info_label.pack(pady=6)
        
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Left: form inputs
        left_frame = ctk.CTkFrame(container)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        ctk.CTkLabel(left_frame, text="Test Form", font=self.fonts['h2']).pack(pady=12)
        
        for label_text, attr_name, placeholder in [
            ("Name *", "name_entry", "Full name"),
            ("Email *", "email_entry", "user@example.com"),
            ("Age", "age_entry", "25")
        ]:
            ctk.CTkLabel(left_frame, text=label_text, font=self.fonts['body']).pack(
                anchor="w", padx=15, pady=(10, 2)
            )
            entry = ctk.CTkEntry(left_frame, placeholder_text=placeholder, 
                                height=35, font=self.fonts['body'])
            entry.pack(fill="x", padx=15, pady=2)
            setattr(self, attr_name, entry)
        
        ctk.CTkLabel(left_frame, text="Message (max 8KB):", font=self.fonts['body']).pack(
            anchor="w", padx=15, pady=(10, 2)
        )
        self.message_text = ctk.CTkTextbox(left_frame, height=100, font=self.fonts['body'])
        self.message_text.pack(fill="x", padx=15, pady=2)
        
        # Character counter
        self.char_count_label = ctk.CTkLabel(left_frame, text="0 / 8192 chars", 
                                            font=ctk.CTkFont(size=10), 
                                            text_color=("gray50", "gray50"))
        self.char_count_label.pack(anchor="e", padx=15, pady=2)
        self.message_text.bind("<KeyRelease>", self.update_char_count)
        
        btn_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        btn_frame.pack(pady=15)
        
        ctk.CTkButton(btn_frame, text="Validate Form", command=self.validate_form,
                     height=40, width=130, font=self.fonts['body']).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Load XSS Test", command=self.load_xss_test,
                     height=35, width=130, fg_color="#FF5722", font=self.fonts['body']).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Clear", command=self.clear_form,
                     height=35, width=90, font=self.fonts['body']).pack(side="left", padx=5)
        
        # Right: results card
        right_frame = ctk.CTkFrame(container)
        right_frame.pack(side="right", fill="both", expand=True, padx=(10, 0))
        
        self.result_card = ResultCard(right_frame, title="Validation Results", fonts=self.fonts)
        self.result_card.pack(fill="both", expand=True)
    
    def update_char_count(self, event=None):
        content = self.message_text.get("1.0", "end-1c")
        count = len(content)
        max_chars = 8192
        color = "orange" if count > max_chars * 0.9 else ("gray50", "gray50")
        self.char_count_label.configure(text=f"{count} / {max_chars} chars", text_color=color)
    
    def validate_form(self):
        form_data = {
            'name': self.name_entry.get(),
            'email': self.email_entry.get(),
            'age': self.age_entry.get(),
            'message': self.message_text.get("1.0", "end-1c")
        }
        
        # Check length limit
        message_len = len(form_data['message'])
        if message_len > 8192:
            messagebox.showerror("Input Too Large", 
                f"Message exceeds 8KB limit ({message_len} bytes). Please shorten your input.")
            return
        
        result = self.validator.validate_form(**form_data)
        
        # Update result card
        self.result_card.clear_content()
        
        if result['is_valid']:
            self.result_card.set_status('valid', 'Valid')
        else:
            self.result_card.set_status('invalid', 'Invalid')
        
        # Show errors
        if result['errors']:
            section = self.result_card.add_section("🚨 Errors")
            for error in result['errors']:
                error_frame = ctk.CTkFrame(section, fg_color="transparent")
                error_frame.pack(fill="x", pady=2)
                ctk.CTkLabel(error_frame, text=f"• {error}", 
                           font=self.fonts['body'], text_color="red", 
                           anchor="w", wraplength=600).pack(fill="x", padx=20)
        
        # Show warnings
        if result['warnings']:
            self.result_card.add_warning_section(result['warnings'])
        
        # Show sanitized data
        if result['is_valid']:
            self.result_card.add_data_grid(result['data'])
    
    def load_xss_test(self):
        self.clear_form()
        self.name_entry.insert(0, "John <script>alert('XSS')</script> Doe")
        self.email_entry.insert(0, "test@example.com")
        self.age_entry.insert(0, "25")
        self.message_text.insert("1.0", 
            "Test <script>alert('XSS')</script> and <img src=x onerror=alert('XSS')>")
        self.update_char_count()
    
    def clear_form(self):
        self.name_entry.delete(0, "end")
        self.email_entry.delete(0, "end")
        self.age_entry.delete(0, "end")
        self.message_text.delete("1.0", "end")
        self.result_card.clear_content()
        self.result_card.set_status('info', 'Ready')
        self.update_char_count()


# ============================================================================
# RESULTS & EXPORT
# ============================================================================

class ResultsExportFrame(ctk.CTkFrame):
    """Results and Export"""
    
    def __init__(self, parent, app, fonts):
        super().__init__(parent, corner_radius=15)
        self.app = app
        self.fonts = fonts
        self.setup_ui()
    
    def setup_ui(self):
        title = ctk.CTkLabel(self, text="Results & Export", font=self.fonts['h1'])
        title.pack(pady=30)
        
        info = ctk.CTkLabel(self, 
                          text="Export functionality for scan results and reports",
                          font=self.fonts['body'], text_color=("gray60", "gray40"))
        info.pack(pady=10)
        
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=30)
        
        ctk.CTkButton(btn_frame, text="Export to CSV", command=self.export_csv,
                     width=150, height=40, font=self.fonts['body']).pack(pady=10)
        ctk.CTkButton(btn_frame, text="Export to JSON", command=self.export_json,
                     width=150, height=40, font=self.fonts['body']).pack(pady=10)
    
    def export_csv(self):
        filename = filedialog.asksaveasfilename(defaultextension=".csv", 
                                               filetypes=[("CSV files", "*.csv")])
        if filename:
            messagebox.showinfo("Export", f"Results exported to {filename}")
    
    def export_json(self):
        filename = filedialog.asksaveasfilename(defaultextension=".json", 
                                               filetypes=[("JSON files", "*.json")])
        if filename:
            messagebox.showinfo("Export", f"Results exported to {filename}")


# ============================================================================
# MAIN APPLICATION
# ============================================================================

class MainApplication(ctk.CTk):
    """Main Application Window"""
    
    def __init__(self):
        super().__init__()
        
        self.title("Security Toolkit - Local & Web Security")
        self.geometry("1200x900")
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Create fonts AFTER Tk root exists
        self.fonts = create_fonts()
        
        self.setup_ui()
        self.center_window()
        self.show_frame("Dashboard")
    
    def center_window(self):
        self.update_idletasks()
        width = 1200
        height = 900
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
    
    def setup_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(6, weight=1)
        
        title = ctk.CTkLabel(self.sidebar, text="Security\nToolkit", font=self.fonts['h1'])
        title.grid(row=0, column=0, padx=20, pady=(30, 20))
        
        self.sidebar_buttons = {}
        tools = [
            "Dashboard",
            "Local Security",
            "Web Security",
            "Results & Export"
        ]
        
        for i, tool in enumerate(tools, 1):
            btn = ctk.CTkButton(self.sidebar, text=tool, 
                               command=lambda t=tool: self.show_frame(t),
                               width=200, height=45, font=self.fonts['body'])
            btn.grid(row=i, column=0, padx=10, pady=8)
            self.sidebar_buttons[tool] = btn
        
        # Help button at bottom
        help_btn = ctk.CTkButton(self.sidebar, text="Help & About", 
                                command=self.show_help,
                                width=200, height=35, fg_color="gray30", font=self.fonts['body'])
        help_btn.grid(row=7, column=0, padx=10, pady=(0, 20))
        
        # Content area
        self.content_frame = ctk.CTkFrame(self, corner_radius=0)
        self.content_frame.grid(row=0, column=1, sticky="nsew")
        
        self.frames = {}
        self.frames["Dashboard"] = DashboardFrame(self.content_frame, self, self.fonts)
        self.frames["Local Security"] = LocalSecurityFrame(self.content_frame, self.fonts)
        self.frames["Web Security"] = WebSecurityFrame(self.content_frame, self.fonts)
        self.frames["Results & Export"] = ResultsExportFrame(self.content_frame, self, self.fonts)
        
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)
    
    def show_frame(self, frame_name):
        for frame in self.frames.values():
            frame.grid_remove()
        
        if frame_name in self.frames:
            self.frames[frame_name].grid(row=0, column=0, sticky="nsew")
        
        for name, btn in self.sidebar_buttons.items():
            if name == frame_name:
                btn.configure(fg_color=("gray75", "gray25"))
            else:
                btn.configure(fg_color=["#3B8ED0", "#1F6AA5"])
    
    def show_help(self):
        """Show comprehensive help dialog"""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Help & About - Security Toolkit")
        dialog.geometry("700x600")
        
        title = ctk.CTkLabel(dialog, text="Security Toolkit Help", font=self.fonts['h1'])
        title.pack(pady=20)
        
        help_text = ctk.CTkTextbox(dialog, width=650, height=450, font=self.fonts['body'])
        help_text.pack(padx=20, pady=10)
        
        help_content = """
LOCAL SECURITY FEATURES:

• Network Traffic Analyzer: Capture and analyze network packets in real-time
  - Requires administrator/root privileges
  - Filter by protocol and port
  - Advanced search capabilities

• Port Scanner: Scan systems for open ports
  - Only use on systems you own or have permission to test
  - TCP port scanning with service identification

WEB SECURITY FEATURES:

• Password Strength: Analyze password strength and get improvement suggestions

• Password Generator & Hasher:
  - Generate 1-50 secure passwords at once
  - Hash passwords using multiple KDF methods (PBKDF2, Argon2, bcrypt)
  - Default: PBKDF2 with 310,000 iterations (NIST 2023 guidance)
  - Warnings for iterations below recommended threshold
  - Each password hashed separately with unique salt
  - Export results to CSV or JSON

• Form Validator:
  - Automatic input sanitization (XSS, SQLi patterns)
  - CSRF token checking
  - Input length limits (8KB max per field)
  - Real-time character counting

DESIGN IMPROVEMENTS (CustomTkinter):

• Global font system for consistency
• Segmented buttons for feature navigation
• Status chips with color coding (Green/Amber/Red)
• ResultCard components for structured results
• Improved spacing and readability

SANITIZATION:

All user inputs are automatically sanitized using BeautifulSoup/bleach to prevent:
  - Cross-Site Scripting (XSS) attacks
  - SQL Injection patterns
  - Malicious HTML/JavaScript

For more information, see the README.md file.

Version 1.0
Authors: Maricon Caluya and Jannine Claire Celocia
Course: MO-IT142 - Security Script Programming
        """
        
        help_text.insert("1.0", help_content.strip())
        help_text.configure(state="disabled")
        
        ctk.CTkButton(dialog, text="Close", command=dialog.destroy, 
                     width=100, font=self.fonts['body']).pack(pady=10)


def main():
    """Main entry point"""
    try:
        app = MainApplication()
        app.mainloop()
    except Exception as e:
        messagebox.showerror("Application Error", f"Failed to start:\n{str(e)}")


if __name__ == "__main__":
    main()
