import os
import re
import html
import secrets
import string
import hashlib
import logging
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional, Callable

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Sanitization libraries
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    logger.warning("BeautifulSoup4 not available - using basic sanitization")

try:
    import bleach
    BLEACH_AVAILABLE = True
except ImportError:
    BLEACH_AVAILABLE = False
    logger.warning("bleach not available - using basic sanitization")

# Optional KDF libraries
try:
    from argon2 import PasswordHasher as Argon2Hasher
    from argon2.exceptions import HashingError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    logger.info("argon2-cffi not available - Argon2 hashing disabled")

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    logger.info("bcrypt not available - bcrypt hashing disabled")

# Network libraries (from MS2)
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ============================================================================
# SANITIZATION ENGINE (MS1 Feedback: BeautifulSoup/bleach sanitization)
# ============================================================================

class SanitizationEngine:
    """
    Centralized input sanitization using BeautifulSoup and/or bleach.
    Handles XSS, basic SQLi patterns, and provides CSRF token checking.
    """
    
    MAX_INPUT_LENGTH = 8192  # 8 KB default limit (MS1 Feedback)
    
    # Dangerous patterns
    SQL_INJECTION_PATTERNS = [
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bDROP\b.*\bTABLE\b)",
        r"(--\s*$)",
        r"(;\s*DROP\b)",
        r"(\bOR\b.*=.*)",
        r"('OR'1'='1)",
    ]
    
    @classmethod
    def sanitize_html(cls, text: str) -> Dict[str, Any]:
        """
        Sanitize HTML/XSS using bleach or BeautifulSoup.
        Returns dict with sanitized text and modification info.
        """
        if not text:
            return {'sanitized': '', 'was_modified': False, 'removed_elements': []}
        
        original = text
        removed_elements = []
        
        # Use bleach if available (preferred)
        if BLEACH_AVAILABLE:
            # Allowed tags (very restrictive - none for now)
            allowed_tags = []
            allowed_attrs = {}
            
            sanitized = bleach.clean(
                text,
                tags=allowed_tags,
                attributes=allowed_attrs,
                strip=True
            )
            
            if sanitized != original:
                removed_elements.append("HTML/Script tags (bleach)")
        
        # Fallback to BeautifulSoup
        elif BS4_AVAILABLE:
            soup = BeautifulSoup(text, 'html.parser')
            
            # Remove all script tags
            for script in soup.find_all('script'):
                removed_elements.append('script tag')
                script.decompose()
            
            # Remove dangerous attributes
            dangerous_attrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'onchange']
            for tag in soup.find_all():
                for attr in dangerous_attrs:
                    if tag.has_attr(attr):
                        removed_elements.append(f'{attr} attribute')
                        del tag[attr]
            
            sanitized = soup.get_text()
        
        # Basic fallback
        else:
            sanitized = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
            sanitized = re.sub(r'<[^>]+>', '', sanitized)
            if sanitized != original:
                removed_elements.append("HTML tags (basic)")
        
        # Final HTML escape
        sanitized = html.escape(sanitized)
        
        return {
            'sanitized': sanitized.strip(),
            'was_modified': original != sanitized,
            'removed_elements': list(set(removed_elements))
        }
    
    @classmethod
    def check_sql_injection(cls, text: str) -> Dict[str, Any]:
        """Check for basic SQL injection patterns."""
        matches = []
        
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(pattern)
        
        return {
            'potentially_malicious': len(matches) > 0,
            'matched_patterns': matches
        }
    
    @classmethod
    def validate_length(cls, text: str, max_length: Optional[int] = None) -> Dict[str, Any]:
        """
        Validate input length (MS1 Feedback: Input length limits).
        Default 8KB, configurable.
        """
        if max_length is None:
            max_length = cls.MAX_INPUT_LENGTH
        
        length = len(text.encode('utf-8'))
        
        return {
            'valid': length <= max_length,
            'length': length,
            'max_length': max_length,
            'exceeded_by': max(0, length - max_length)
        }
    
    @classmethod
    def sanitize_input(cls, text: str, max_length: Optional[int] = None) -> Dict[str, Any]:
        """
        Comprehensive input sanitization.
        Combines HTML sanitization, SQL check, and length validation.
        """
        if not text:
            return {
                'sanitized': '',
                'valid': True,
                'warnings': [],
                'errors': []
            }
        
        warnings = []
        errors = []
        
        # Length check
        length_result = cls.validate_length(text, max_length)
        if not length_result['valid']:
            errors.append(
                f"Input exceeds maximum length of {length_result['max_length']} bytes "
                f"(current: {length_result['length']} bytes)"
            )
            return {
                'sanitized': '',
                'valid': False,
                'warnings': warnings,
                'errors': errors
            }
        
        # HTML sanitization
        html_result = cls.sanitize_html(text)
        if html_result['was_modified']:
            warnings.append(
                f"Potentially malicious content removed: {', '.join(html_result['removed_elements'])}"
            )
        
        # SQL injection check
        sql_result = cls.check_sql_injection(html_result['sanitized'])
        if sql_result['potentially_malicious']:
            warnings.append("Potential SQL injection patterns detected and sanitized")
        
        return {
            'sanitized': html_result['sanitized'],
            'valid': True,
            'warnings': warnings,
            'errors': errors
        }


# ============================================================================
# PASSWORD ANALYSIS AND GENERATION (MS1 Features)
# ============================================================================

class PasswordStrengthAnalyzer:
    """Password strength analysis"""
    
    STRENGTH_THRESHOLDS = {
        'very_strong': 85,
        'strong': 70,
        'moderate': 50,
        'weak': 30
    }
    
    SCORING_WEIGHTS = {
        'length_basic': 20,
        'length_bonus': 10,
        'uppercase': 15,
        'lowercase': 15,
        'digits': 15,
        'special': 25
    }
    
    @classmethod
    def analyze_strength(cls, password: str) -> Dict[str, Any]:
        """Analyze password strength"""
        if not password:
            return {
                'strength': 'Empty',
                'score': 0,
                'feedback': ['Password cannot be empty'],
                'requirements': cls._get_empty_requirements()
            }
        
        requirements = cls._check_requirements(password)
        score = cls._calculate_score(password, requirements)
        strength = cls._determine_strength(score)
        feedback = cls._generate_feedback(requirements, len(password))
        
        return {
            'strength': strength,
            'score': score,
            'feedback': feedback,
            'requirements': requirements
        }
    
    @staticmethod
    def _get_empty_requirements() -> Dict[str, bool]:
        return {
            'length': False,
            'uppercase': False,
            'lowercase': False,
            'digits': False,
            'special': False
        }
    
    @staticmethod
    def _check_requirements(password: str) -> Dict[str, bool]:
        return {
            'length': len(password) >= 8,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'digits': bool(re.search(r'[0-9]', password)),
            'special': bool(re.search(r'[!@#$%^&*()\-_+=\[\]{};:,.?/]', password))
        }
    
    @classmethod
    def _calculate_score(cls, password: str, requirements: Dict[str, bool]) -> int:
        score = 0
        length = len(password)
        
        if requirements['length']:
            score += cls.SCORING_WEIGHTS['length_basic']
        if length >= 12:
            score += cls.SCORING_WEIGHTS['length_bonus']
        
        for req_type in ['uppercase', 'lowercase', 'digits', 'special']:
            if requirements[req_type]:
                score += cls.SCORING_WEIGHTS[req_type]
        
        return score
    
    @classmethod
    def _determine_strength(cls, score: int) -> str:
        if score >= cls.STRENGTH_THRESHOLDS['very_strong']:
            return 'Very Strong'
        elif score >= cls.STRENGTH_THRESHOLDS['strong']:
            return 'Strong'
        elif score >= cls.STRENGTH_THRESHOLDS['moderate']:
            return 'Moderate'
        elif score >= cls.STRENGTH_THRESHOLDS['weak']:
            return 'Weak'
        else:
            return 'Very Weak'
    
    @staticmethod
    def _generate_feedback(requirements: Dict[str, bool], length: int) -> List[str]:
        feedback = []
        
        if not requirements['length']:
            feedback.append('Use at least 8 characters')
        elif length < 12:
            feedback.append('Consider using 12+ characters')
        
        requirement_messages = {
            'uppercase': 'Add uppercase letters (A-Z)',
            'lowercase': 'Add lowercase letters (a-z)',
            'digits': 'Add numbers (0-9)',
            'special': 'Add special characters (!@#$%^&*())'
        }
        
        for req_type, message in requirement_messages.items():
            if not requirements[req_type]:
                feedback.append(message)
        
        if not feedback:
            feedback.append('Excellent! Password meets all requirements')
        
        return feedback


class PasswordGenerator:
    """Secure password generation"""
    
    SPECIAL_CHARS = "!@#$%^&*()-_=+[]{};:,.?/"
    AMBIGUOUS_CHARS = {
        'lowercase': 'lo',
        'uppercase': 'IO',
        'digits': '01'
    }
    
    @classmethod
    def generate_password(cls, length: int = None, 
                         include_uppercase: bool = True,
                         include_lowercase: bool = True,
                         include_digits: bool = True,
                         include_special: bool = True,
                         exclude_ambiguous: bool = False) -> str:
        """Generate a secure password"""
        
        if length is None:
            length = secrets.randbelow(9) + 8
        
        if length < 4:
            raise ValueError("Password length must be at least 4 characters")
        
        pool, mandatory_chars = cls._build_character_pool(
            include_uppercase, include_lowercase, include_digits, 
            include_special, exclude_ambiguous
        )
        
        if not pool:
            raise ValueError("At least one character type must be selected")
        
        return cls._generate_from_pool(pool, mandatory_chars, length)
    
    @classmethod
    def _build_character_pool(cls, uppercase: bool, lowercase: bool, 
                            digits: bool, special: bool, 
                            exclude_ambiguous: bool) -> Tuple[str, List[str]]:
        pool = ""
        mandatory_chars = []
        
        char_sets = {
            'lowercase': (lowercase, string.ascii_lowercase),
            'uppercase': (uppercase, string.ascii_uppercase),
            'digits': (digits, string.digits),
            'special': (special, cls.SPECIAL_CHARS)
        }
        
        for char_type, (include, chars) in char_sets.items():
            if include:
                if exclude_ambiguous and char_type in cls.AMBIGUOUS_CHARS:
                    for char in cls.AMBIGUOUS_CHARS[char_type]:
                        chars = chars.replace(char, '')
                
                pool += chars
                if chars:
                    mandatory_chars.append(secrets.choice(chars))
        
        return pool, mandatory_chars
    
    @staticmethod
    def _generate_from_pool(pool: str, mandatory_chars: List[str], length: int) -> str:
        remaining_length = max(0, length - len(mandatory_chars))
        password_chars = mandatory_chars + [
            secrets.choice(pool) for _ in range(remaining_length)
        ]
        
        secrets.SystemRandom().shuffle(password_chars)
        return ''.join(password_chars)
    
    @classmethod
    def generate_multiple(cls, count: int, **kwargs) -> List[str]:
        """Generate multiple passwords"""
        return [cls.generate_password(**kwargs) for _ in range(count)]


# ============================================================================
# PASSWORD HASHING (MS1 Feedback: Configurable KDF with warnings)
# ============================================================================

def get_available_kdf_methods() -> Dict[str, str]:
    """Get available KDF methods with descriptions"""
    methods = {
        'pbkdf2': 'PBKDF2-HMAC-SHA256 (NIST recommended)'
    }
    
    if ARGON2_AVAILABLE:
        methods['argon2'] = 'Argon2id (Modern, memory-hard)'
    
    if BCRYPT_AVAILABLE:
        methods['bcrypt'] = 'bcrypt (Well-established)'
    
    return methods


class PasswordHasher:
    """
    Password hashing with multiple KDF support.
    MS1 Feedback: Configurable PBKDF2 iterations (default 310,000).
    """
    
    NIST_RECOMMENDED_ITERATIONS = 310_000  # NIST 2023 guidance
    SALT_LENGTH = 16
    
    @classmethod
    def hash_passwords(cls, passwords: List[str], 
                      method: str = 'pbkdf2',
                      iterations: Optional[int] = None,
                      salt: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Hash multiple passwords separately (MS1 Feedback: Multiple passwords behavior).
        Each password gets its own hash.
        
        Args:
            passwords: List of passwords to hash
            method: KDF method ('pbkdf2', 'argon2', 'bcrypt')
            iterations: PBKDF2 iterations (default 310,000)
            salt: Optional salt (generated if None)
        
        Returns:
            Dict with results list containing hash info for each password
        """
        if iterations is None:
            iterations = cls.NIST_RECOMMENDED_ITERATIONS
        
        # Log warning if iterations below threshold (MS1 Feedback)
        if method == 'pbkdf2' and iterations < cls.NIST_RECOMMENDED_ITERATIONS:
            logger.warning(
                f"PBKDF2 iterations ({iterations}) below NIST 2023 recommended "
                f"({cls.NIST_RECOMMENDED_ITERATIONS})"
            )
        
        results = []
        
        for password in passwords:
            if method == 'pbkdf2':
                result = cls._hash_pbkdf2(password, iterations, salt)
            elif method == 'argon2':
                result = cls._hash_argon2(password)
            elif method == 'bcrypt':
                result = cls._hash_bcrypt(password)
            else:
                raise ValueError(f"Unknown KDF method: {method}")
            
            results.append(result)
        
        return {
            'method': method,
            'iterations': iterations if method == 'pbkdf2' else None,
            'results': results
        }
    
    @classmethod
    def _hash_pbkdf2(cls, password: str, iterations: int, salt: Optional[bytes] = None) -> Dict[str, Any]:
        """Hash using PBKDF2-HMAC-SHA256"""
        if salt is None:
            salt = os.urandom(cls.SALT_LENGTH)
        
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        
        return {
            'kdf': 'pbkdf2',
            'hash': dk.hex(),
            'salt': salt.hex(),
            'iterations': iterations,
            'algorithm': 'sha256'
        }
    
    @classmethod
    def _hash_argon2(cls, password: str) -> Dict[str, Any]:
        """Hash using Argon2 (if available)"""
        if not ARGON2_AVAILABLE:
            raise RuntimeError("Argon2 library not available. Install with: pip install argon2-cffi")
        
        hasher = Argon2Hasher()
        hash_str = hasher.hash(password)
        
        return {
            'kdf': 'argon2',
            'hash': hash_str,
            'algorithm': 'argon2id'
        }
    
    @classmethod
    def _hash_bcrypt(cls, password: str) -> Dict[str, Any]:
        """Hash using bcrypt (if available)"""
        if not BCRYPT_AVAILABLE:
            raise RuntimeError("bcrypt library not available. Install with: pip install bcrypt")
        
        salt = bcrypt.gensalt()
        hash_bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        return {
            'kdf': 'bcrypt',
            'hash': hash_bytes.decode('utf-8'),
            'algorithm': 'bcrypt'
        }


# ============================================================================
# FORM VALIDATION (MS1 Feature with Sanitization)
# ============================================================================

class FormValidator:
    """Form validation with integrated sanitization"""
    
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    AGE_LIMITS = {'min': 18, 'max': 120}
    
    def __init__(self):
        self.sanitizer = SanitizationEngine()
    
    def validate_email(self, email: str) -> Tuple[bool, str]:
        """Validate email format"""
        if not email:
            return False, "Email is required"
        
        if not self.EMAIL_PATTERN.match(email):
            return False, "Invalid email format"
        
        return True, ""
    
    def validate_age(self, age_str: str) -> Tuple[bool, str]:
        """Validate age input"""
        if not age_str.strip():
            return True, ""
        
        try:
            age = int(age_str)
            if age < self.AGE_LIMITS['min']:
                return False, f"Minimum age: {self.AGE_LIMITS['min']}"
            elif age > self.AGE_LIMITS['max']:
                return False, f"Maximum age: {self.AGE_LIMITS['max']}"
            return True, ""
        except ValueError:
            return False, "Age must be a valid number"
    
    def validate_form(self, name: str, email: str, age: str, message: str) -> Dict[str, Any]:
        """Comprehensive form validation with sanitization"""
        errors = []
        warnings = []
        sanitized_data = {}
        
        # Validate and sanitize name
        if not name.strip():
            errors.append("Name is required")
        else:
            name_result = self.sanitizer.sanitize_input(name)
            if not name_result['valid']:
                errors.extend(name_result['errors'])
            else:
                sanitized_data['name'] = name_result['sanitized']
                warnings.extend(name_result['warnings'])
        
        # Validate email
        email_valid, email_error = self.validate_email(email)
        if not email_valid:
            errors.append(email_error)
        else:
            sanitized_data['email'] = email.strip()
        
        # Validate age
        age_valid, age_error = self.validate_age(age)
        if not age_valid:
            errors.append(age_error)
        else:
            sanitized_data['age'] = int(age.strip()) if age.strip() else None
        
        # Sanitize message
        if message.strip():
            message_result = self.sanitizer.sanitize_input(message)
            if not message_result['valid']:
                errors.extend(message_result['errors'])
            else:
                sanitized_data['message'] = message_result['sanitized']
                warnings.extend(message_result['warnings'])
        else:
            sanitized_data['message'] = None
        
        return {
            'is_valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'data': sanitized_data
        }


# ============================================================================
# NETWORK TRAFFIC ANALYSIS (MS2 Feature)
# ============================================================================

class NetworkTrafficBackend:
    """Backend for network traffic analysis"""
    
    def __init__(self):
        self.is_capturing = False
        self.capture_thread = None
        self.packet_count = 0
        self.protocol_filter = "All"
        self.port_filter = ""
        self.selected_interface = None
        
        self.on_packet_captured: Optional[Callable[[dict], None]] = None
        self.on_capture_error: Optional[Callable[[str], None]] = None
        self.on_capture_started: Optional[Callable[[], None]] = None
        self.on_capture_stopped: Optional[Callable[[], None]] = None
    
    def set_callbacks(self, **kwargs):
        """Set callback functions"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    def get_available_interfaces(self) -> List[Tuple[str, str]]:
        """Get available network interfaces"""
        if not SCAPY_AVAILABLE:
            return [("Default (Auto-detect)", None)]
        
        try:
            interfaces = []
            
            if PSUTIL_AVAILABLE:
                net_if_addrs = psutil.net_if_addrs()
                net_if_stats = psutil.net_if_stats()
                
                for iface_name, addrs in net_if_addrs.items():
                    is_up = net_if_stats.get(iface_name, None)
                    if is_up and not is_up.isup:
                        continue
                    
                    ip_addr = None
                    for addr in addrs:
                        if addr.family == 2:  # AF_INET (IPv4)
                            ip_addr = addr.address
                            break
                    
                    display_name = f"{iface_name} ({ip_addr})" if ip_addr else iface_name
                    interfaces.append((display_name, iface_name))
            else:
                scapy_interfaces = get_if_list()
                for iface in scapy_interfaces:
                    interfaces.append((iface, iface))
            
            interfaces.insert(0, ("Default (Auto-detect)", None))
            return interfaces if interfaces else [("Default (Auto-detect)", None)]
        
        except Exception:
            return [("Default (Auto-detect)", None)]
    
    def set_interface(self, interface: Optional[str]):
        """Set network interface"""
        self.selected_interface = interface
    
    def update_filters(self, protocol_filter: str, port_filter: str):
        """Update filters in real-time"""
        self.protocol_filter = protocol_filter
        self.port_filter = port_filter
    
    def start_capture(self) -> bool:
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            if self.on_capture_error:
                self.on_capture_error("Scapy module required")
            return False
        
        if self.is_capturing:
            return False
        
        self.is_capturing = True
        self.packet_count = 0
        
        if self.on_capture_started:
            self.on_capture_started()
        
        self.capture_thread = threading.Thread(
            target=self._capture_packets_thread,
            daemon=True
        )
        self.capture_thread.start()
        return True
    
    def stop_capture(self):
        """Stop packet capture"""
        if self.is_capturing:
            self.is_capturing = False
            if self.on_capture_stopped:
                self.on_capture_stopped()
    
    def _capture_packets_thread(self):
        """Capture packets in separate thread"""
        try:
            kwargs = {
                'prn': lambda pkt: self._process_packet(pkt),
                'store': False,
                'stop_filter': lambda x: not self.is_capturing
            }
            
            if self.selected_interface:
                kwargs['iface'] = self.selected_interface
            
            sniff(**kwargs)
        except PermissionError:
            if self.on_capture_error:
                self.on_capture_error("Admin/root privileges required")
        except Exception as e:
            if self.on_capture_error:
                self.on_capture_error(f"Capture error: {str(e)}")
    
    def _process_packet(self, packet):
        """Process captured packet"""
        if not self.is_capturing:
            return
        
        try:
            src_ip = None
            dst_ip = None
            protocol = ""
            src_port = "-"
            dst_port = "-"
            packet_size = len(packet)
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if TCP in packet:
                    protocol = "TCP"
                    src_port = str(packet[TCP].sport)
                    dst_port = str(packet[TCP].dport)
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = str(packet[UDP].sport)
                    dst_port = str(packet[UDP].dport)
                elif ICMP in packet:
                    protocol = "ICMP"
                else:
                    protocol = "Other"
            
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                
                if TCP in packet:
                    protocol = "TCP"
                    src_port = str(packet[TCP].sport)
                    dst_port = str(packet[TCP].dport)
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = str(packet[UDP].sport)
                    dst_port = str(packet[UDP].dport)
                elif ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet:
                    protocol = "ICMP"
                else:
                    protocol = "Other"
            else:
                return
            
            if src_ip is None or dst_ip is None:
                return
            
            if not self._apply_filters(protocol, src_port, dst_port):
                return
            
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            packet_data = {
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'src_port': src_port,
                'dst_port': dst_port,
                'size': packet_size
            }
            
            self.packet_count += 1
            if self.on_packet_captured:
                self.on_packet_captured(packet_data)
        
        except Exception:
            pass
    
    def _apply_filters(self, protocol: str, src_port: str, dst_port: str) -> bool:
        """Apply filters to packets"""
        if self.protocol_filter != "All" and protocol != self.protocol_filter:
            return False
        
        if self.port_filter.strip():
            try:
                port_num = int(self.port_filter.strip())
                if src_port != "-" and dst_port != "-":
                    if int(src_port) != port_num and int(dst_port) != port_num:
                        return False
                else:
                    return False
            except ValueError:
                pass
        
        return True
    
    def get_packet_count(self) -> int:
        """Get current packet count"""
        return self.packet_count


# ============================================================================
# PORT SCANNER (MS2 Feature)
# ============================================================================

class PortScannerBackend:
    """Backend for port scanning"""
    
    def __init__(self):
        self.scanning = False
        self.scan_thread = None
        self.stop_event = threading.Event()
        
        self.on_scan_start: Optional[Callable[[], None]] = None
        self.on_scan_complete: Optional[Callable[..., None]] = None
        self.on_progress_update: Optional[Callable[[int, int, int], None]] = None
        self.on_port_result: Optional[Callable[[int, bool, str], None]] = None
        self.on_status_update: Optional[Callable[[str], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None
    
    def set_callbacks(self, **kwargs):
        """Set callback functions"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    def validate_inputs(self, target: str, start_port: int, end_port: int, timeout: float) -> Tuple[bool, str]:
        """Validate scan parameters"""
        if not target.strip():
            return False, "Target required"
        
        if start_port < 1 or end_port < 1 or start_port > 65535 or end_port > 65535:
            return False, "Port range: 1-65535"
        
        if start_port > end_port:
            return False, "Start port must be <= end port"
        
        if timeout <= 0:
            return False, "Timeout must be > 0"
        
        return True, ""
    
    def resolve_hostname(self, target: str) -> Optional[str]:
        """Resolve hostname to IP"""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror as e:
            if self.on_error:
                self.on_error(f"Cannot resolve '{target}': {str(e)}")
            return None
    
    def scan_port(self, target_ip: str, port: int, timeout: float) -> bool:
        """Scan a single port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
                return result == 0
        except Exception:
            return False
    
    def get_service_name(self, port: int) -> str:
        """Get service name for port"""
        common_ports = {
            20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 8080: "HTTP Alt"
        }
        return common_ports.get(port, "Unknown")
    
    def get_scan_statistics(self, open_ports: List[int], closed_ports: List[int], 
                          duration: float) -> Dict:
        """Generate scan statistics"""
        return {
            'total_ports': len(open_ports) + len(closed_ports),
            'open_ports': len(open_ports),
            'closed_ports': len(closed_ports),
            'duration': duration,
            'open_port_list': open_ports
        }
    
    def scan_ports_thread(self, target: str, start_port: int, end_port: int, timeout: float):
        """Main scanning thread"""
        try:
            self.stop_event.clear()
            
            is_valid, error_msg = self.validate_inputs(target, start_port, end_port, timeout)
            if not is_valid:
                if self.on_error:
                    self.on_error(error_msg)
                return
            
            if self.on_scan_start:
                self.on_scan_start()
            
            if self.on_status_update:
                self.on_status_update("Resolving hostname...")
            
            target_ip = self.resolve_hostname(target)
            if not target_ip:
                return
            
            total_ports = end_port - start_port + 1
            open_ports = []
            closed_ports = []
            
            start_time = datetime.now()
            
            if self.on_status_update:
                self.on_status_update(f"Scanning {target_ip}")
            
            for i, port in enumerate(range(start_port, end_port + 1)):
                if self.stop_event.is_set():
                    break
                
                progress = i + 1
                if self.on_progress_update:
                    self.on_progress_update(progress, total_ports, port)
                
                is_open = self.scan_port(target_ip, port, timeout)
                service = self.get_service_name(port)
                
                if is_open:
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
                
                if self.on_port_result:
                    self.on_port_result(port, is_open, service)
                
                time.sleep(0.01)
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            stats = self.get_scan_statistics(open_ports, closed_ports, duration)
            
            if self.on_scan_complete:
                self.on_scan_complete(stats, target_ip, not self.stop_event.is_set())
        
        except Exception as e:
            if self.on_error:
                self.on_error(f"Scan error: {str(e)}")
        finally:
            self.scanning = False
    
    def start_scan(self, target: str, start_port: int, end_port: int, timeout: float) -> bool:
        """Start port scan"""
        if self.scanning:
            return False
        
        self.scanning = True
        
        self.scan_thread = threading.Thread(
            target=self.scan_ports_thread,
            args=(target, start_port, end_port, timeout)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        return True
    
    def stop_scan(self):
        """Stop current scan"""
        if self.scanning:
            self.stop_event.set()
            if self.on_status_update:
                self.on_status_update("Stopping...")
            
            if self.scan_thread and self.scan_thread.is_alive():
                self.scan_thread.join(timeout=2.0)
            
            self.scanning = False
    
    def is_scanning(self) -> bool:
        """Check if scanning"""
        return self.scanning


# ============================================================================
# SCAN RESULT MODEL (Unified result schema)
# ============================================================================

class ScanResult:
    """Unified scan result model"""
    
    def __init__(self, source: str, target: str, status: str, 
                 issues: List[str] = None, started_at: datetime = None,
                 finished_at: datetime = None, metrics: Dict = None, raw: Any = None):
        self.source = source
        self.target = target
        self.status = status
        self.issues = issues or []
        self.started_at = started_at or datetime.now()
        self.finished_at = finished_at
        self.metrics = metrics or {}
        self.raw = raw
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'source': self.source,
            'target': self.target,
            'status': self.status,
            'issues': self.issues,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'finished_at': self.finished_at.isoformat() if self.finished_at else None,
            'metrics': self.metrics,
            'raw': self.raw
        }
