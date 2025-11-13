"""
Unified Security Toolkit
Combines local security (network analysis, port scanning) with web security 
(password analysis, generation, hashing, form validation).

Requirements:
- customtkinter: GUI framework
- scapy: Network packet capture (for network traffic analysis)
- bleach or beautifulsoup4: Input sanitization
- Optional: argon2-cffi, bcrypt (for additional KDF methods)
- Optional: psutil (for better interface detection)

Usage:
    python main.py
"""

import sys
import os
import logging
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import messagebox

# Configure logging
LOG_DIR = Path.home() / '.security_toolkit' / 'logs'
LOG_DIR.mkdir(parents=True, exist_ok=True)

log_file = LOG_DIR / f"security_toolkit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)


def check_required_dependencies():
    """Check for required dependencies"""
    missing = []
    
    try:
        import customtkinter
    except ImportError:
        missing.append("customtkinter")
    
    return missing


def check_optional_dependencies():
    """Check for optional dependencies and return status"""
    status = {}
    
    # Network capture
    try:
        import scapy
        status['scapy'] = True
    except ImportError:
        status['scapy'] = False
    
    # Sanitization
    try:
        import bleach
        status['bleach'] = True
    except ImportError:
        status['bleach'] = False
    
    try:
        from bs4 import BeautifulSoup
        status['beautifulsoup4'] = True
    except ImportError:
        status['beautifulsoup4'] = False
    
    # KDF methods
    try:
        import argon2
        status['argon2-cffi'] = True
    except ImportError:
        status['argon2-cffi'] = False
    
    try:
        import bcrypt
        status['bcrypt'] = True
    except ImportError:
        status['bcrypt'] = False
    
    # Utilities
    try:
        import psutil
        status['psutil'] = True
    except ImportError:
        status['psutil'] = False
    
    return status


def show_dependency_warning(optional_status):
    """Show warning about missing optional dependencies"""
    missing_critical = []
    missing_optional = []
    
    # Critical for features
    if not optional_status.get('scapy', False):
        missing_critical.append("scapy (for Network Traffic Analyzer)")
    
    if not optional_status.get('bleach', False) and not optional_status.get('beautifulsoup4', False):
        missing_critical.append("bleach or beautifulsoup4 (for input sanitization)")
    
    # Optional enhancements
    if not optional_status.get('argon2-cffi', False):
        missing_optional.append("argon2-cffi (for Argon2 password hashing)")
    
    if not optional_status.get('bcrypt', False):
        missing_optional.append("bcrypt (for bcrypt password hashing)")
    
    if not optional_status.get('psutil', False):
        missing_optional.append("psutil (for better network interface detection)")
    
    if missing_critical or missing_optional:
        msg_parts = []
        
        if missing_critical:
            msg_parts.append("⚠️ Missing dependencies (features disabled):")
            msg_parts.extend([f"  • {dep}" for dep in missing_critical])
            msg_parts.append("")
        
        if missing_optional:
            msg_parts.append("ℹ️ Optional enhancements available:")
            msg_parts.extend([f"  • {dep}" for dep in missing_optional])
            msg_parts.append("")
        
        msg_parts.append("Install with:")
        msg_parts.append("  pip install scapy bleach argon2-cffi bcrypt psutil")
        
        message = "\n".join(msg_parts)
        
        logger.warning("Some dependencies are missing")
        
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showinfo("Dependency Information", message)
            root.destroy()
        except Exception:
            print(message)


def check_system_requirements():
    """Check if system requirements are met"""
    if sys.version_info < (3, 8):
        return False, ["Python 3.8 or higher is required"]
    
    return True, []


def main():
    """Main application entry point"""
    
    logger.info("=" * 60)
    logger.info("Starting Unified Security Toolkit")
    logger.info("=" * 60)
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Log file: {log_file}")
    
    # Check system requirements
    requirements_met, issues = check_system_requirements()
    if not requirements_met:
        error_msg = "System Requirements Not Met:\n\n" + "\n".join(f"• {issue}" for issue in issues)
        logger.error(error_msg)
        
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("System Requirements Error", error_msg)
            root.destroy()
        except Exception:
            pass
        
        sys.exit(1)
    
    # Check required dependencies
    missing_required = check_required_dependencies()
    if missing_required:
        error_msg = (
            "Missing Required Dependencies:\n\n"
            + "\n".join(f"• {dep}" for dep in missing_required)
            + "\n\nInstall with:\n"
            + f"pip install {' '.join(missing_required)}"
        )
        logger.error(error_msg)
        
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Dependencies Error", error_msg)
            root.destroy()
        except Exception:
            pass
        
        sys.exit(1)
    
    # Check optional dependencies
    optional_status = check_optional_dependencies()
    logger.info("Dependency status:")
    for dep, available in optional_status.items():
        status_console = "[OK]" if available else "[X]"
        logger.info(f"  {status_console} {dep}")
    
    # Show warnings for missing optional dependencies
    show_dependency_warning(optional_status)
    
    # Import and start application
    try:
        logger.info("Initializing GUI...")
        from frontend import MainApplication
        
        app = MainApplication()
        
        # Handle window close
        def on_closing():
            logger.info("Application closing...")
            
            # Stop any running operations
            try:
                # Stop port scanner if running
                port_scanner_frame = app.frames.get("Local Security")
                if port_scanner_frame and hasattr(port_scanner_frame, 'scanner_frame'):
                    scanner = port_scanner_frame.scanner_frame
                    if scanner.backend.is_scanning():
                        if messagebox.askyesno("Scan in Progress", 
                                              "A port scan is running. Stop and exit?"):
                            scanner.backend.stop_scan()
                        else:
                            return
                
                # Stop network capture if running
                if port_scanner_frame and hasattr(port_scanner_frame, 'traffic_frame'):
                    traffic = port_scanner_frame.traffic_frame
                    if traffic.backend.is_capturing:
                        if messagebox.askyesno("Capture in Progress", 
                                              "Network capture is running. Stop and exit?"):
                            traffic.backend.stop_capture()
                        else:
                            return
            except Exception as e:
                logger.warning(f"Error during cleanup: {e}")
            
            logger.info("Application stopped")
            app.destroy()
        
        app.protocol("WM_DELETE_WINDOW", on_closing)
        
        logger.info("Starting main loop...")
        print("\n" + "=" * 60)
        print("Unified Security Toolkit - Ready")
        print("=" * 60)
        print("Note: Network capture requires administrator/root privileges")
        print("=" * 60 + "\n")
        
        app.mainloop()
        
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        sys.exit(0)
    
    except Exception as e:
        error_msg = f"Failed to start application:\n\n{str(e)}"
        logger.exception("Application error")
        
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Application Error", error_msg)
            root.destroy()
        except Exception:
            pass
        
        sys.exit(1)


if __name__ == "__main__":
    main()
