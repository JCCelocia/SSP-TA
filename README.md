# Unified Security Toolkit

A comprehensive GUI application combining local and web security features, built with Python and CustomTkinter.

> **Academic Project**  
> **Course:** MO-IT142 - Security Script Programming  
> **Milestone:** Terminal Assessment  
> **Authors:** Maricon Caluya and Jannine Claire Celocia  
> **Repositories:**
> - [MS1: Web Security](https://github.com/JCCelocia/SSP-MS1)
> - [MS2: Local Security](https://github.com/JCCelocia/SSP-MS2)

---

## Features

### Local Security Tools (MS2)

#### Network Traffic Analyzer
- Real-time packet capture and analysis
- Network interface selection with auto-detection
- Protocol filtering (TCP, UDP, ICMP)
- Port filtering capabilities
- Advanced search with real-time filtering
- IPv4 and IPv6 support
- **Requires administrator/root privileges**

#### Port Scanner
- TCP port scanning (1-65535)
- Service identification for common ports
- Real-time progress tracking with cancellation
- **Only use on systems you own or have permission to test**

### Web Security Tools (MS1 with Enhancements)

#### Password Strength Analyzer
- Comprehensive strength analysis with scoring system
- Real-time feedback and improvement suggestions
- Visual strength indicators
- Requirements checklist display

#### Password Generator & Hasher
- Secure password generation with customizable options
- Multiple password generation (5 at once)
- **Multi-KDF Support:**
  - **PBKDF2-HMAC-SHA256** (default, NIST recommended)
  - **Argon2id** (modern, memory-hard) - optional
  - **bcrypt** (well-established) - optional
- **Configurable PBKDF2 iterations:**
  - Default: **310,000 iterations** (NIST 2023 guidance)
  - Visual warnings for iterations below recommended threshold
  - Logging of low iteration warnings
- **Multiple password hashing:**
  - Each password hashed separately
  - Results table with password, KDF, iterations, and hash
  - Clear presentation of all results

#### Form Validator & Sanitizer
- **Advanced Input Sanitization:**
  - Uses **BeautifulSoup** and/or **bleach** for robust sanitization
  - XSS (Cross-Site Scripting) protection
  - Basic SQL injection pattern detection
  - CSRF token presence checking capability
  - Automatic removal of dangerous HTML/JavaScript
- **Input Length Limits:**
  - Maximum 8 KB per text field (configurable in backend)
  - Real-time character counting with visual feedback
  - Frontend and backend validation for security
  - Friendly error messages when limits exceeded
- **Comprehensive Validation:**
  - Email format validation
  - Age range validation (18-120)
  - Required field checking
  - Detailed error and warning reporting

### Documentation & Usability Improvements

- **In-app Help:**
  - Tooltips for KDF selection explaining PBKDF2, Argon2, and bcrypt
  - Iteration count guidance with NIST 2023 recommendations
  - Input limit indicators with character counters
  - Sanitization scope information on form validator
- **Help/About Dialog:**
  - Comprehensive guide to local vs web security features
  - Explanation of sanitization process
  - Password hashing method descriptions
  - Feature usage instructions

---

## Requirements

```bash
Python 3.8+

# Required
customtkinter>=5.0.0

# For Local Security Features
scapy>=2.4.5  # Network traffic analysis

# For Input Sanitization (at least one required)
bleach>=5.0.0  # Recommended for HTML sanitization
beautifulsoup4>=4.9.0  # Alternative/additional sanitization

# Optional - Enhanced KDF Support
argon2-cffi>=21.3.0  # For Argon2 password hashing
bcrypt>=4.0.0  # For bcrypt password hashing

# Optional - Better Interface Detection
psutil>=5.8.0  # Improved network interface information
```

---

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/JCCelocia/SSP-TA
cd SSP-TA
```

### 2. Install Core Dependencies
```bash
# Minimum required
pip install customtkinter

# For full local security features
pip install customtkinter scapy

# For full web security features with sanitization
pip install customtkinter bleach beautifulsoup4

# Complete installation (all features)
pip install customtkinter scapy bleach beautifulsoup4 argon2-cffi bcrypt psutil
```

### 3. Run Application
```bash
# Normal mode
python main.py

# With admin privileges (for network capture)
# Windows: Run Command Prompt as Administrator, then:
python main.py

# Linux/macOS:
sudo python main.py
```

---

## Usage

### Dashboard
- Launch point for all security tools
- Quick access to Local and Web Security features
- Overview of available functionality

### Local Security

#### Network Traffic Analyzer
1. Select network interface from dropdown (or use auto-detect)
2. Set filters (optional):
   - **Protocol:** TCP, UDP, ICMP, or All
   - **Port:** Specific port number
3. Click **"Start"** to begin capture
4. Use search box for advanced filtering:
   - Type keywords to filter packets
   - Search updates in real-time
5. Click **"Stop"** when done
6. Use **"Clear"** to reset display

#### Port Scanner
1. Enter target IP or hostname (e.g., `127.0.0.1`, `localhost`)
2. Set port range:
   - **Start Port:** e.g., 20
   - **End Port:** e.g., 1024
3. Set timeout (default: 0.5 seconds)
4. Click **"Start Scan"**
5. View open ports as they're discovered (green highlights)
6. Stop scan anytime with **"Stop"** button

### Web Security

#### Password Strength Analyzer
1. Enter a password in the input field
2. Toggle **"Show Password"** to view what you're typing
3. View real-time strength analysis:
   - Strength rating (Very Weak to Very Strong)
   - Numeric score (0-100)
   - Progress bar visualization
   - Requirements checklist
   - Improvement suggestions

#### Password Generator & Hasher
1. **Configure Generation:**
   - Set password length (default: 12)
   - Select character types:
     - Uppercase letters
     - Lowercase letters
     - Digits
     - Special characters
     - Option to exclude ambiguous characters (0, O, l, 1, I)

2. **Generate Passwords:**
   - Click **"Generate Password"** for single password
   - Click **"Generate Multiple (5)"** for five passwords at once

3. **Select KDF Method:**
   - Choose from dropdown (PBKDF2 is default and recommended)
   - **PBKDF2:** Most widely supported, NIST recommended
   - **Argon2:** Modern, memory-hard (requires `argon2-cffi`)
   - **bcrypt:** Well-established (requires `bcrypt`)

4. **Configure PBKDF2 Iterations:**
   - Default: **310,000** (NIST 2023 guidance)
   - **⚠️ Warning:** If you set below 310,000, you'll see:
     - Orange warning text in UI: "⚠️ Warning: Below recommended 310,000!"
     - Warning dialog when hashing completes
     - Log entry recording the low iteration count
   - **✓ Meets guidance:** Green confirmation when ≥ 310,000

5. **Hash Passwords:**
   - Click **"Hash All"** to hash all generated passwords
   - **Each password is hashed separately** with its own result
   - View results table showing:
     - Password (first 20 chars)
     - KDF method used
     - Iterations (for PBKDF2)
     - Hash value (truncated for display)

**Example: Multiple Password Hashing Behavior**
```
Generated passwords:
1. aB3#xYz9!mK2
2. Pq7$wEr4@nM5
3. Hs6^tUv8&jL9

After clicking "Hash All" with PBKDF2 (310,000 iterations):

Password 1: aB3#xYz9!mK2
  KDF: pbkdf2
  Iterations: 310000
  Hash: 3f4a8b2c1d9e5f7a8b0c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4...

Password 2: Pq7$wEr4@nM5
  KDF: pbkdf2
  Iterations: 310000
  Hash: 9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d...

Password 3: Hs6^tUv8&jL9
  KDF: pbkdf2
  Iterations: 310000
  Hash: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2...
```

#### Form Validator
1. **Fill in test form:**
   - Name (required) - automatically sanitized
   - Email (required) - validated for format
   - Age (optional) - validated for range 18-120
   - Message (optional, max 8KB) - automatically sanitized
   - Character counter shows usage: "0 / 8192 chars"

2. **Automatic Sanitization Information:**
   - 🛡️ Header shows: "Automatic sanitization: XSS, SQLi patterns, CSRF checks • Input limit: 8KB"
   - All inputs processed through BeautifulSoup/bleach
   - Dangerous content automatically removed:
     - `<script>` tags
     - `onclick`, `onerror`, and similar event handlers
     - All HTML tags (converted to plain text)
     - SQL injection patterns detected

3. **Test XSS Protection:**
   - Click **"Load XSS Test"** to populate form with malicious content:
     - Name: `John <script>alert('XSS')</script> Doe`
     - Message: `Test <script>alert('XSS')</script> and <img src=x onerror=alert('XSS')>`
   - Click **"Validate Form"**
   - See sanitization warnings showing what was removed

4. **View Results:**
   - ✓ Valid or ✗ Invalid status
   - 🚨 Error messages (if any)
   - ⚠️ Sanitization warnings showing removed elements
   - ✅ Sanitized data (safe for use)

5. **Length Limit Example:**
   - Try entering more than 8,192 characters in message
   - Character counter turns orange at 90% (7,372 chars)
   - Error shown if you exceed limit when validating

### Results & Export
- Export scan results to CSV format
- Export data to JSON format
- Unified results view (planned for future enhancement)

### Help & About
- Click **"Help & About"** in sidebar
- View comprehensive guide covering:
  - All local security features
  - All web security features
  - Sanitization explanations
  - KDF method comparisons
  - Iteration recommendations
  - Best practices

---

## Project Structure

```
unified-security-toolkit/
├── main.py              # Application entry point with logging
├── backend.py           # Unified backend logic
│                        # - Sanitization engine (BeautifulSoup/bleach)
│                        # - Password analysis, generation, hashing
│                        # - Network traffic capture
│                        # - Port scanning
│                        # - Form validation
├── frontend.py          # GUI components (MS2 style)
│                        # - Dashboard
│                        # - Local Security (Network, Port Scanner)
│                        # - Web Security (Passwords, Forms)
│                        # - Results & Export
│                        # - Help dialog
└── README.md           # This file
```

---

## Technical Details

### Architecture
- **Pattern:** MVC with unified backend
- **GUI:** CustomTkinter with dark theme (MS2 style preserved)
- **Network Analysis:** Scapy for packet capture
- **Port Scanning:** Python socket library with threading
- **Sanitization:** BeautifulSoup and/or bleach for XSS/injection prevention
- **Hashing:** PBKDF2 (hashlib), optional Argon2/bcrypt
- **Threading:** Non-blocking operations for all long-running tasks

### Security Features Implementation

#### Input Sanitization (MS1 Feedback Implementation)
- **Centralized in `backend.py`:**
  - `SanitizationEngine` class handles all sanitization
  - Methods: `sanitize_html()`, `check_sql_injection()`, `validate_length()`
- **Used by frontend before processing:**
  - All form inputs sanitized before validation
  - Results shown to user with warnings
- **Technologies:**
  - Primary: `bleach` (if available) - industry standard
  - Fallback: `BeautifulSoup` for HTML parsing
  - Final: HTML entity escaping
- **What's sanitized:**
  - `<script>` tags completely removed
  - Event handlers (onclick, onerror, etc.) stripped
  - All HTML tags converted to plain text
  - SQL injection patterns detected and logged

#### Password Hashing (MS1 Feedback Implementation)
- **PBKDF2 Configuration:**
  - Default iterations: `310_000` (constant in `PasswordHasher`)
  - User can modify via UI input field
  - Backend validates and logs warnings
  - Warnings shown both in UI and logs
- **Multiple KDF Support:**
  - `get_available_kdf_methods()` checks installed libraries
  - Graceful degradation if Argon2/bcrypt unavailable
  - Clear UI messages: "Install with: pip install argon2-cffi"
  - Dropdown only shows available methods
- **Multiple Password Behavior:**
  - `hash_passwords()` accepts list of passwords
  - Each password hashed individually with unique salt
  - Results array contains separate entry for each
  - UI displays table format for clarity

#### Input Length Limits (MS1 Feedback Implementation)
- **Default: 8 KB** (`MAX_INPUT_LENGTH` in `SanitizationEngine`)
- **Enforcement:**
  - Frontend: Character counter shows usage
  - Backend: `validate_length()` checks byte size
  - Both validations prevent submission if exceeded
- **User Experience:**
  - Real-time character count display
  - Color change at 90% capacity (orange warning)
  - Clear error message on validation
  - Configurable limit in backend for future changes

---

## Important Notes

### Security & Legal

⚠️ **Educational purposes only. Use responsibly.**

- **Only test systems you own or have explicit permission to test**
- Unauthorized scanning may violate laws and policies
- Network capture requires administrator/root privileges
- Packet capture may be subject to wiretapping laws

### System Requirements

- **Python 3.8+** required for all features
- **Administrator/root privileges** required for network traffic capture
- **Network access** required for port scanning

### Known Limitations

1. **Network Capture:**
   - Requires elevated privileges on all platforms
   - May not work with all network adapters
   - VPN interfaces might not be detectable

2. **Port Scanner:**
   - TCP only (UDP scanning not implemented)
   - Sequential scanning (not parallel for reliability)
   - Firewall may block scans or give false negatives

3. **Sanitization:**
   - Requires at least one of: bleach or beautifulsoup4
   - Falls back to basic regex if neither available
   - Cannot prevent all sophisticated attacks

4. **KDF Methods:**
   - Argon2 and bcrypt are optional (install separately)
   - Only PBKDF2 available by default
   - Iteration warnings are informational only

---

## Troubleshooting

### Missing Dependencies

**Install all optional dependencies:**
```bash
pip install scapy bleach beautifulsoup4 argon2-cffi bcrypt psutil
```

**Specific issues:**
```bash
# Network Traffic not working
pip install scapy
# Then run with: sudo python main.py (Linux/Mac) or as Administrator (Windows)

# Sanitization warnings
pip install bleach beautifulsoup4

# "Argon2 not available" message
pip install argon2-cffi

# "bcrypt not available" message
pip install bcrypt
```

### Administrator Privileges Required

**Windows:**
1. Right-click Command Prompt
2. Select "Run as Administrator"
3. Navigate to project directory
4. Run: `python main.py`

**Linux/macOS:**
```bash
sudo python main.py
# Or with virtual environment:
sudo /path/to/venv/bin/python main.py
```

### No Network Interfaces Found

- Install `psutil`: `pip install psutil`
- Check if network adapters are enabled
- Try selecting "Default (Auto-detect)"
- Run with administrator/root privileges

### No Open Ports Found in Scan

- Test with localhost first: `127.0.0.1`
- Increase timeout value (try 1.0 or 2.0 seconds)
- Check firewall settings
- Verify target system is running services

### Application Won't Start

```bash
# Check Python version (must be 3.8+)
python --version

# Reinstall dependencies
pip install --upgrade customtkinter

# Check for errors in log file
cat ~/.security_toolkit/logs/*.log
```

### Iteration Warning Not Showing

- Verify PBKDF2 is selected (not Argon2/bcrypt)
- Check iterations value is below 310,000
- Warning appears both in UI and popup after hashing
- Check log file for warning entry

---

## Export Features

### CSV Export
- Structured data export for spreadsheet analysis
- Contains timestamps, sources, targets, statuses
- Compatible with Excel, Google Sheets, LibreOffice

### JSON Export
- Machine-readable format for programmatic access
- Full data preservation including metadata
- Suitable for further processing or API integration

---

## Logging

Application logs are stored in:
- **Location:** `~/.security_toolkit/logs/`
- **Format:** `security_toolkit_YYYYMMDD_HHMMSS.log`
- **Contents:**
  - Application startup and shutdown
  - Dependency availability
  - Security warnings (low iterations, sanitization)
  - Error messages and exceptions
  - User actions (scans started/stopped)

**View logs:**
```bash
# Linux/macOS
cat ~/.security_toolkit/logs/*.log

# Windows
type %USERPROFILE%\.security_toolkit\logs\*.log
```

---

## Future Enhancements

- Unified results database with search and filtering
- Report generation (PDF format)
- Scheduled/automated scanning
- Network intrusion detection rules
- More sophisticated SQL injection detection
- CSRF token generation and validation
- Rate limiting for API protection
- Integration with external vulnerability databases

---

## License & Disclaimer

This project is for **educational purposes only**. The authors are not responsible for any misuse or damage caused by this software.

**Always ensure you have proper authorization before conducting any security testing.**

Users are responsible for complying with all applicable laws and regulations.

---

## Credits & Acknowledgments

**Original Projects:**
- **SSP MS1:** Web security features (password tools, form validation)
- **SSP MS2:** Local security features (network analysis, port scanning)

**Technologies:**
- CustomTkinter for modern GUI framework
- Scapy for network packet capture and analysis
- bleach and BeautifulSoup for HTML sanitization
- Argon2 and bcrypt libraries for enhanced KDF support

**Standards & Guidance:**
- NIST SP 800-132 for PBKDF2 iteration recommendations
- OWASP guidelines for input validation and sanitization
- CVE database for vulnerability awareness

---

**Course:** MO-IT142 - Security Script Programming  
**Authors:** Maricon Caluya and Jannine Claire Celocia  
**Unified Project:** Combining SSP MS1 and SSP MS2  
**Year:** 2025

**Repository:** [GitHub Link]
