# Unified Security Toolkit

A comprehensive GUI application combining local and web security analysis tools, built with Python and CustomTkinter.

---

## 📚 Academic Project

**Course:** MO-IT142 - Security Script Programming  
**Assessment:** Terminal Assessment  
**Authors:** Maricon Caluya and Jannine Claire Celocia  
**Year:** 2025

**Project Repositories:**
- [MS1: Web Security](https://github.com/JCCelocia/SSP-MS1)
- [MS2: Local Security](https://github.com/JCCelocia/SSP-MS2)
- [Terminal Assessment (Unified)](https://github.com/JCCelocia/SSP-TA)

---

## 🎯 Overview

This toolkit integrates two comprehensive security toolsets:

- **Local Security (MS2)**: Network traffic analysis, port scanning, and network performance monitoring
- **Web Security (MS1)**: Password security, form validation, and input sanitization

All features are unified in a modern dark-themed GUI with professional styling and enhanced usability.

---

## ✨ Features

### 🔒 Local Security Tools

#### Network Traffic Analyzer
- Real-time packet capture and analysis using Scapy
- Multiple network interface selection with auto-detection
- Protocol filtering (TCP, UDP, ICMP, All)
- Port-based filtering
- Advanced search with real-time keyword filtering
- IPv4 and IPv6 support
- Packet counter and detailed packet information display

> **⚠️ Requires administrator/root privileges**

#### Port Scanner
- Comprehensive TCP port scanning (range: 1-65535)
- Automatic service identification for common ports
- Real-time progress tracking with visual progress bar
- Configurable timeout settings
- Scan cancellation support
- Color-coded results (green for open ports)

> **⚠️ Only use on systems you own or have permission to test**

#### Network Performance Monitor 
- Real-time network performance statistics
- **Upload Speed:** Live upload speed monitoring (MB/s)
- **Download Speed:** Live download speed monitoring (MB/s)
- **Total Data Transfer:**
  - Cumulative bytes sent
  - Cumulative bytes received
- **Active Connections:** Count of active network connections
- Auto-refresh every second
- Clean visual indicators with color-coded speeds

> **ℹ️ Requires psutil library for functionality**

### 🌐 Web Security Tools

#### Password Strength Analyzer
- Comprehensive strength analysis with scoring system (0-100)
- Real-time feedback as you type
- Visual strength indicators with color coding
- Requirements checklist (length, uppercase, lowercase, digits, special chars)
- Detailed improvement suggestions
- Show/hide password toggle

#### Password Generator & Hasher
- **Secure Random Generation:**
  - Generate 1-50 passwords simultaneously
  - Customizable password length
  - Character type selection (uppercase, lowercase, digits, special)
  - Option to exclude ambiguous characters (0, O, l, 1, I)

- **Multi-KDF Hash Support:**
  - **PBKDF2-HMAC-SHA256** (default, NIST recommended)
  - **Argon2id** (modern, memory-hard) - requires `argon2-cffi`
  - **bcrypt** (well-established) - requires `bcrypt`

- **PBKDF2 Configuration:**
  - Default: **310,000 iterations** (NIST 2023 guidance)
  - User-configurable iteration count
  - Visual warnings for iterations below recommended threshold
  - Automatic logging of low iteration warnings

- **Multiple Password Hashing:**
  - Each password hashed separately with unique salt
  - Comprehensive results table showing:
    - Password (truncated for display)
    - Salt (hex format)
    - KDF method used
    - Iteration count (for PBKDF2)
    - Hash value (truncated for display)

- **Export Capabilities:**
  - Export to CSV format
  - Export to JSON format
  - Copy all results to clipboard

#### Form Validator & Sanitizer
- **Advanced Input Sanitization:**
  - Uses **BeautifulSoup** and/or **bleach** for robust sanitization
  - XSS (Cross-Site Scripting) protection
  - SQL injection pattern detection
  - CSRF token presence checking capability
  - Automatic removal of dangerous HTML/JavaScript

- **Input Validation:**
  - Full name validation (2-100 characters, no numbers)
  - Username validation (3-20 characters, alphanumeric + underscore/hyphen)
  - Email format validation (RFC-compliant)
  - Age range validation (18-120 years)
  - Required field checking

- **Input Length Limits:**
  - Maximum 8 KB per text field
  - Real-time character counting with visual feedback
  - Color-coded warnings at 90% capacity
  - Frontend and backend validation

- **User Experience:**
  - Real-time character counter
  - Clear error and warning messages
  - Sanitized data preview
  - Test data loading for XSS testing

---

## 📋 Requirements

### System Requirements
- **Python:** 3.8 or higher
- **OS:** Windows, Linux, or macOS
- **Privileges:** Administrator/root access for network capture

### Python Dependencies

#### Core Dependencies
```bash
customtkinter>=5.0.0     # Modern GUI framework
```

#### Local Security Features
```bash
scapy>=2.4.5            # Network packet capture and analysis
psutil>=5.8.0           # Network performance monitoring & interface detection
```

#### Web Security Features
```bash
# Input Sanitization (at least one required)
bleach>=5.0.0           # HTML sanitization (recommended)
beautifulsoup4>=4.9.0   # HTML parsing and sanitization

# Enhanced KDF Support (optional)
argon2-cffi>=21.3.0     # Argon2 password hashing
bcrypt>=4.0.0           # bcrypt password hashing
```

---

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/JCCelocia/SSP-TA.git
cd SSP-TA
```

### 2. Install Dependencies

**Quick Install (All Features):**
```bash
pip install -r requirements.txt
```

**Minimum Installation (Core GUI only):**
```bash
pip install customtkinter
```

**Local Security Features:**
```bash
pip install customtkinter scapy psutil
```

**Web Security Features:**
```bash
pip install customtkinter bleach beautifulsoup4
```

**Complete Installation (Manual):**
```bash
pip install customtkinter scapy psutil bleach beautifulsoup4 argon2-cffi bcrypt
```

### 3. Run the Application

**Normal Mode:**
```bash
python main.py
```

**With Administrator Privileges (for network capture):**

- **Windows:**
  1. Right-click Command Prompt
  2. Select "Run as Administrator"
  3. Navigate to project directory
  4. Run: `python main.py`

- **Linux/macOS:**
  ```bash
  sudo python main.py
  # Or with virtual environment:
  sudo /path/to/venv/bin/python main.py
  ```

---

## 📖 Usage Guide

### Dashboard
The main dashboard provides quick access to all security tools:
- **Local Security**: Access network analyzer, port scanner, and performance monitor
- **Web Security**: Access password tools and form validator

### Local Security Tools

#### Network Traffic Analyzer

1. **Select Network Interface:**
   - Choose from dropdown (or use "Default (Auto-detect)")
   - Available interfaces are auto-detected

2. **Configure Filters (Optional):**
   - **Protocol Filter:** Select TCP, UDP, ICMP, or All
   - **Port Filter:** Enter specific port number (e.g., 80, 443)

3. **Start Capture:**
   - Click **"Start"** button
   - Status changes to "Capturing..."
   - Packets appear in real-time

4. **Advanced Search:**
   - Use search box to filter displayed packets
   - Filters by IP, port, protocol, or any packet data
   - Updates in real-time as you type

5. **Stop and Clear:**
   - Click **"Stop"** to end capture
   - Click **"Clear"** to reset display

#### Port Scanner

1. **Configure Scan:**
   - **Target:** Enter IP address or hostname (e.g., `127.0.0.1`, `localhost`)
   - **Port Range:**
     - Start Port: e.g., 20
     - End Port: e.g., 1024
   - **Timeout:** Default 0.5 seconds (adjust for slow networks)

2. **Execute Scan:**
   - Click **"Start Scan"**
   - Progress bar shows real-time progress
   - Open ports appear immediately (highlighted in green)

3. **View Results:**
   - Port number
   - Status (OPEN/CLOSED)
   - Identified service (for common ports)

4. **Stop or Clear:**
   - Click **"Stop"** to cancel running scan
   - Click **"Clear"** to reset results

#### Network Performance Monitor

1. **Access Monitor:**
   - Navigate to Local Security
   - Click **"Network Performance"** in the segmented button

2. **View Real-Time Statistics:**
   - **Network Speed:**
     - ⬆️ Upload Speed: Current upload rate in MB/s
     - ⬇️ Download Speed: Current download rate in MB/s
   
   - **Total Data Transfer:**
     - 📤 Bytes Sent: Cumulative data transmitted
     - 📥 Bytes Received: Cumulative data received
   
   - **Network Connections:**
     - 🔗 Active Connections: Count of active network connections

3. **Auto-Refresh:**
   - Statistics update automatically every second
   - No manual refresh needed

4. **Requirements:**
   - Requires `psutil` library to be installed
   - Shows "N/A" if psutil is not available
   - May require elevated privileges for connection count on some systems

### Web Security Tools

#### Password Strength Analyzer

1. Enter password in the input field
2. Toggle **"Show Password"** to view/hide
3. View real-time analysis:
   - Strength rating (Very Weak to Very Strong)
   - Numeric score (0-100)
   - Color-coded progress bar
   - Detailed suggestions for improvement

#### Password Generator & Hasher

**Generation Configuration:**
1. Set number of passwords (1-50)
2. Set password length (minimum 4)
3. Select character types:
   - ✓ Uppercase letters
   - ✓ Lowercase letters
   - ✓ Digits
   - ✓ Special characters
   - ☐ Exclude ambiguous characters

**Hashing Configuration:**
1. **Select KDF Method:**
   - PBKDF2 (default, recommended)
   - Argon2 (if installed)
   - bcrypt (if installed)

2. **Configure PBKDF2 Iterations:**
   - Default: 310,000 (NIST 2023)
   - ⚠️ Warning shown if below 310,000
   - ✓ Green confirmation if meets guidance

**Generate and Hash:**
1. Click **"Generate"**
2. All passwords are generated and hashed automatically
3. Each password receives:
   - Unique salt
   - Separate hash computation
   - Individual result entry

**Results Table:**
- Password (first 20 characters)
- Salt (hex format, truncated)
- KDF method
- Iterations (for PBKDF2)
- Hash value (truncated)

**Export Options:**
- **Copy All:** Copy results to clipboard
- **Export CSV:** Save as spreadsheet
- **Export JSON:** Save as structured data

#### Form Validator & Sanitizer

**Automatic Sanitization Banner:**
```
🛡️ Automatic sanitization: XSS/SQL patterns + CSRF checks • Input limit: 8KB
```

**Fill Form:**
1. **Name** (required): Full name, 2-100 characters
2. **Username** (required): 3-20 characters, alphanumeric + _-
3. **Email** (required): Valid email format
4. **Age** (optional): 18-120 years
5. **Message** (optional): Up to 8KB
   - Character counter shows: "0 / 8192 chars"
   - Orange warning at 90% capacity

**Validate:**
1. Click **"Validate Form"**
2. View results:
   - ✓ Valid or ✗ Invalid status
   - 🚨 Error messages (if any)
   - ⚠️ Sanitization warnings
   - ✅ Sanitized data preview

**Test XSS Protection:**
Try entering malicious content like:
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
```
The validator will automatically remove dangerous content and show warnings.

---

## 🏗️ Project Structure

```
unified-security-toolkit/
├── main.py              # Application entry point with logging
├── backend.py           # Unified backend logic
│   ├── SanitizationEngine
│   ├── PasswordStrengthAnalyzer
│   ├── PasswordGenerator
│   ├── PasswordHasher
│   ├── FormValidator
│   ├── NetworkTrafficBackend
│   ├── PortScannerBackend
│   └── NetworkPerformanceBackend
├── frontend.py          # GUI components (CustomTkinter)
│   ├── DashboardFrame
│   ├── LocalSecurityFrame
│   │   ├── NetworkTrafficFrame
│   │   ├── PortScannerFrame
│   │   └── NetworkPerformanceFrame
│   └── WebSecurityFrame
│       ├── PasswordStrengthTab
│       ├── PasswordGeneratorTab
│       └── FormValidatorTab
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

---

## 🔧 Technical Details

### Architecture
- **Pattern:** Model-View-Controller (MVC) with unified backend
- **GUI Framework:** CustomTkinter (dark theme)
- **Threading:** Non-blocking operations for all long-running tasks
- **Logging:** Comprehensive logging to `~/.security_toolkit/logs/`

### Security Implementation

#### Input Sanitization
- **Primary:** `bleach` library (industry standard)
- **Fallback:** `BeautifulSoup` for HTML parsing
- **Final:** HTML entity escaping
- **Removes:**
  - `<script>` tags
  - Event handlers (onclick, onerror, etc.)
  - All HTML tags (converted to plain text)
  - SQL injection patterns (detected and logged)

#### Password Hashing
- **PBKDF2-HMAC-SHA256:**
  - Default iterations: 310,000
  - SHA-256 hash function
  - Unique 16-byte salt per password
  
- **Argon2id** (optional):
  - Memory-hard algorithm
  - Resistant to GPU attacks
  
- **bcrypt** (optional):
  - Adaptive hash function
  - Built-in salt generation

#### Network Analysis
- **Scapy:** Professional packet manipulation library
- **BPF Filters:** Berkeley Packet Filter for efficient capture
- **Thread-safe:** Capture runs in separate thread

#### Port Scanning
- **Socket-based:** Python's built-in socket library
- **Sequential:** One port at a time for reliability
- **Timeout control:** Configurable timeout per port

#### Network Performance Monitoring
- **psutil:** Cross-platform system and network utilities
- **Real-time metrics:**
  - Network I/O counters (bytes sent/received)
  - Upload/download speed calculation (MB/s)
  - Active connection counting
- **Auto-refresh:** Updates every 1 second
- **Error handling:** Graceful degradation if psutil unavailable

---

## ⚠️ Important Notes

### Security & Legal

> **⚠️ EDUCATIONAL PURPOSES ONLY**
> 
> This toolkit is designed for educational purposes only. Users are responsible for:
> - Only testing systems they own or have explicit permission to test
> - Complying with all applicable laws and regulations
> - Understanding that unauthorized scanning may violate laws and policies

**Legal Considerations:**
- Network packet capture may be subject to wiretapping laws
- Unauthorized port scanning may violate computer fraud laws
- Always obtain written permission before testing third-party systems

### System Requirements

**Administrator/Root Privileges:**
- Required for network traffic capture on all platforms
- May be required for network connection counting on some systems
- Port scanning works without elevated privileges
- Web security features work without elevated privileges

**Network Considerations:**
- Firewall may block scans or give false negatives
- VPN interfaces might not be detectable
- Some network adapters may not support packet capture

### Known Limitations

1. **Network Capture:**
   - Requires elevated privileges
   - May not work with all network adapters
   - Performance depends on packet rate

2. **Port Scanner:**
   - Sequential scanning (not parallel)
   - No UDP scanning support
   - Firewall may affect results

3. **Network Performance Monitor:**
   - Requires psutil library
   - Connection count may require elevated privileges
   - Counters reset on application restart
   - Accuracy depends on system load

4. **Sanitization:**
   - Requires at least one library (bleach or beautifulsoup4)
   - Cannot prevent all sophisticated attacks
   - 8KB limit may be restrictive for some use cases

5. **KDF Methods:**
   - Argon2 and bcrypt require separate installation
   - Only PBKDF2 available by default
   - Iteration warnings are informational only

---

## 🐛 Troubleshooting

### Missing Dependencies

**Error: "ModuleNotFoundError: No module named 'X'"**

```bash
# Install specific missing module
pip install <module_name>

# Or install all dependencies
pip install -r requirements.txt
```

### Network Capture Issues

**Error: "Scapy module required"**
```bash
pip install scapy
```

**Error: "Admin/root privileges required"**
- Run application with administrator/root privileges (see Installation section)

**No network interfaces found:**
```bash
pip install psutil
# Then restart application with admin/root privileges
```

### Network Performance Issues

**Error: "psutil is not available"**
```bash
pip install psutil
# Restart application
```

**Shows N/A for all values:**
- Install psutil library
- Check that network interfaces are active
- Try running with elevated privileges

**Connection count shows N/A:**
- May require administrator/root privileges
- Try running application with elevated privileges

### Port Scanner Issues

**No open ports found:**
- Test with localhost first: `127.0.0.1`
- Increase timeout value (try 1.0 or 2.0 seconds)
- Check firewall settings
- Verify target system is running services

**Scan very slow:**
- Reduce port range
- Increase timeout slightly
- Check network connectivity

### Sanitization Issues

**Warning: "bleach not available - using basic sanitization"**
```bash
pip install bleach beautifulsoup4
```

### KDF Issues

**"Argon2 not available" message:**
```bash
pip install argon2-cffi
```

**"bcrypt not available" message:**
```bash
pip install bcrypt
```

### Application Won't Start

```bash
# Check Python version (must be 3.8+)
python --version

# Reinstall core dependencies
pip install --upgrade customtkinter

# Check logs for detailed error
cat ~/.security_toolkit/logs/*.log  # Linux/macOS
type %USERPROFILE%\.security_toolkit\logs\*.log  # Windows
```

---

## 📊 Export Features

### CSV Export
- Structured data for spreadsheet analysis
- Contains all result fields
- Compatible with Excel, Google Sheets, LibreOffice Calc

### JSON Export
- Machine-readable format
- Full data preservation including metadata
- Suitable for programmatic access or API integration

### Clipboard Copy
- Quick copy of all results
- Formatted for easy pasting
- Includes passwords, hashes, and metadata

---

## 🎨 UI/UX Features

### Modern Design
- Dark theme optimized for extended use
- Consistent color scheme throughout
- Professional typography and spacing

### Navigation
- Sidebar navigation for main sections
- Segmented buttons for feature selection within sections
- Contextual help buttons

### Visual Feedback
- Color-coded status chips (Green/Amber/Red)
- Progress bars for long-running operations
- Real-time character counters
- Tooltips and inline help
- Auto-refreshing statistics

### Results Display
- Structured result cards
- Searchable and filterable tables
- Color-coded results (green for success, red for issues)
- Scrollable content areas
- Real-time updates

---

## 📚 Standards & References

This toolkit follows industry standards and best practices:

- **NIST SP 800-132:** Password-Based Key Derivation (PBKDF2 iterations)
- **OWASP:** Input validation and sanitization guidelines
- **RFC 5321:** Email address validation
- **CVE Database:** Vulnerability awareness

---

## 🤝 Contributing

This is an academic project for MO-IT142 - Security Script Programming. While this specific project is not open for contributions, you are welcome to:

- Fork the repository for educational purposes
- Report bugs or issues
- Suggest improvements via GitHub issues
- Use as reference for your own projects

---

## 📄 License & Disclaimer

**License:** Educational Use Only

**Disclaimer:**
This software is provided "as is" without warranty of any kind. The authors are not responsible for any misuse or damage caused by this software. Users assume all responsibility for:

- Legal compliance in their jurisdiction
- Proper authorization before testing systems
- Consequences of using the software

**Always:**
- Obtain written permission before security testing
- Use only on systems you own or have explicit permission to test
- Comply with all applicable laws and regulations
- Practice responsible disclosure of vulnerabilities

---

## 👥 Credits & Acknowledgments

### Development Team
- **Maricon Caluya** - Lead Developer
- **Jannine Claire Celocia** - Lead Developer

### Course Information
- **Course:** MO-IT142 - Security Script Programming
- **Assessment:** Terminal Assessment
- **Institution:** Mapúa Malayan Digital College 
- **Year:** 2025

### Technologies Used
- **CustomTkinter** - Modern GUI framework
- **Scapy** - Network packet capture and analysis
- **psutil** - System and network utilities
- **bleach** - HTML sanitization
- **BeautifulSoup** - HTML parsing
- **Argon2** - Modern password hashing
- **bcrypt** - Password hashing

### Standards & Guidance
- NIST SP 800-132 for PBKDF2 iteration recommendations
- OWASP guidelines for input validation and sanitization
- Python PEP 8 style guide

---

## 🔄 Version History

### Version 1.0 (Current)
- Initial unified release combining MS1 and MS2
- Complete local security suite
- Complete web security suite
- Modern CustomTkinter UI
- Comprehensive documentation

### Features from MS1
- Password strength analysis
- Secure password generation
- Multi-KDF password hashing
- Form validation and sanitization

### Features from MS2
- Network traffic analyzer
- Port scanner
- Network performance monitor
- System monitoring capabilities

---

*Last Updated: 2025*
