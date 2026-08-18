"""
Scanwell Core Scanner Module

Sensitive data scanner using YARA rules (primary) with Python regex fallback.
Detects PII, PHI, PCI, and source code secrets in files on a local host.

Cross-platform: macOS, Windows, Linux.
"""

import os
import re
import logging
import mmap
from pathlib import Path
from typing import Optional

# File content extraction
# Optional python-magic for MIME detection; falls back to extension-based detection
# if libmagic is not installed (common on Windows where libmagic needs manual install).
try:
    import magic
    _magic_instance = magic.Magic(mime=True)

    def detect_mime_type(file_path: str) -> str:
        """Detect MIME type via libmagic."""
        try:
            return _magic_instance.from_file(file_path)
        except Exception:
            return _detect_mime_by_extension(file_path)

    MAGIC_AVAILABLE = True
except (ImportError, OSError):
    MAGIC_AVAILABLE = False

    def detect_mime_type(file_path: str) -> str:
        """Detect MIME type by file extension (fallback when libmagic unavailable)."""
        return _detect_mime_by_extension(file_path)

# Extension to MIME-type mapping for the fallback path
_EXT_TO_MIME = {
    '.txt': 'text/plain', '.csv': 'text/csv', '.log': 'text/plain',
    '.json': 'application/json', '.xml': 'application/xml',
    '.yaml': 'text/yaml', '.yml': 'text/yaml', '.ini': 'text/plain',
    '.cfg': 'text/plain', '.conf': 'text/plain',
    '.py': 'text/x-python', '.java': 'text/x-java', '.c': 'text/x-c',
    '.cpp': 'text/x-c++', '.h': 'text/x-c', '.go': 'text/x-go',
    '.rs': 'text/x-rust', '.rb': 'text/x-ruby', '.js': 'text/javascript',
    '.ts': 'text/typescript', '.sh': 'text/x-shellscript',
    '.bat': 'text/plain', '.ps1': 'text/plain', '.sql': 'text/x-sql',
    '.md': 'text/markdown',
    '.pdf': 'application/pdf',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.doc': 'application/msword',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.xls': 'application/vnd.ms-excel',
}


def _detect_mime_by_extension(file_path: str) -> str:
    """Return MIME type based on file extension."""
    ext = Path(file_path).suffix.lower()
    return _EXT_TO_MIME.get(ext, 'application/octet-stream')

import docx
import pdfplumber
from openpyxl import load_workbook

# Optional YARA integration (falls back to regex if unavailable)
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# Optional Levenshtein for similarity scoring
try:
    from Levenshtein import ratio as lev_ratio
    SIMILARITY_AVAILABLE = True
except ImportError:
    SIMILARITY_AVAILABLE = False

logger = logging.getLogger(__name__)

# Default file size limit: 50 MB. Files larger than this are skipped.
DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024

# Supported file extensions for directory scanning
SUPPORTED_EXTENSIONS = {
    ".txt", ".csv", ".log", ".json", ".xml", ".yaml", ".yml", ".ini",
    ".py", ".java", ".c", ".cpp", ".h", ".go", ".rs", ".rb", ".js",
    ".ts", ".sh", ".bat", ".ps1", ".sql", ".conf", ".cfg",
    ".pdf", ".docx", ".xlsx", ".doc", ".xls",
}

# Regex patterns (used when YARA is unavailable or for post-validation)
REGEX_PATTERS = {
    "PII": {
        "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "Credit Card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
        "Email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "Phone": re.compile(r"\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"),
        "Driver License": re.compile(r"\b[A-Z]\d{7}\b"),
    },
    "PHI": {
        "Medical Record": re.compile(r"\b(?:MRN|Medical Record Number)\s*:?\s*\d+\b", re.IGNORECASE),
        "Health Plan ID": re.compile(r"\b(?:Insurance ID|Policy Number|Health Plan)\s*:?\s*[\w\d-]+\b", re.IGNORECASE),
        "ICD-10 Code": re.compile(r"\b[A-Z]\d{2}[-.]\d{1,2}\b"),
        "Treatment Date": re.compile(r"(?:Treatment|Admission|Discharge)\s*Date:\s*\d{2}[-/]\d{2}[-/]\d{4}", re.IGNORECASE),
    },
    "PCI": {
        "CVV": re.compile(r"\bCVV2?\s*:?\s*\d{3,4}\b", re.IGNORECASE),
        "Expiry Date": re.compile(r"\b(?:Exp(?:iration)?)?\s*Date\s*:?\s*(?:0[1-9]|1[0-2])[/\-]\d{2,4}\b", re.IGNORECASE),
    },
    "Source Code": {
        "API Key": re.compile(r"(?:api[_-]?key|api[_-]?token|access[_-]?token|secret[_-]?key)['\"]?\s*[:=]\s*['\"][\w\-]{16,}['\"]", re.IGNORECASE),
        "Password": re.compile(r"(?:password|pwd|passwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE),
        "AWS Key": re.compile(r"\b(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}\b"),
        "Private Key": re.compile(r"-----BEGIN (?:RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----"),
        "DB Connection": re.compile(r"(?:mongodb|jdbc:postgresql|postgresql://|mysql://)[^\s<>]+", re.IGNORECASE),
    },
}


def luhn_check(card_number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
    digits = re.sub(r'[^0-9]', '', card_number)
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def mask_sensitive(data: str) -> str:
    """Mask sensitive data, keeping first and last characters."""
    if len(data) <= 4:
        return "*" * len(data)
    return data[0] + "*" * (len(data) - 2) + data[-1]


def _clean_match(text: str) -> str:
    """Strip surrounding quotes/whitespace from a regex match."""
    return text.strip().strip('"').strip("'").strip()


class SensitiveDataScanner:
    """
    Scans files and directories for sensitive data patterns.
    
    Uses YARA rules when available (faster, more accurate), falls back to
    Python regex. Supports text, PDF, Word, and Excel file extraction.
    """

    def __init__(self, yara_rules_dir: Optional[str] = None,
                 max_file_size: int = DEFAULT_MAX_FILE_SIZE,
                 use_yara: bool = True):
        self.max_file_size = max_file_size
        self.current_file = None
        self.rules = None
        self._use_yara = use_yara and YARA_AVAILABLE

        if self._use_yara and yara_rules_dir:
            self._load_yara_rules(yara_rules_dir)
        elif self._use_yara and not yara_rules_dir:
            # Try default location
            default_rules = Path(__file__).parent.parent.parent / "resources" / "patterns"
            if default_rules.exists():
                self._load_yara_rules(str(default_rules))
            else:
                logger.warning("No YARA rules directory found, falling back to regex")
                self._use_yara = False
        elif use_yara and not YARA_AVAILABLE:
            logger.warning("yara-python not installed, falling back to regex patterns")
            self._use_yara = False

    def _load_yara_rules(self, rules_dir: str):
        """Compile YARA rules from .yara files in the given directory."""
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            logger.error(f"YARA rules directory not found: {rules_dir}")
            self._use_yara = False
            return
        
        filepaths = {}
        for yara_file in rules_path.glob("*.yara"):
            namespace = yara_file.stem
            filepaths[namespace] = str(yara_file)
        
        if not filepaths:
            logger.warning(f"No .yara files found in {rules_dir}, using regex")
            self._use_yara = False
            return
        
        try:
            self.rules = yara.compile(filepaths=filepaths)
            logger.info(f"Loaded {len(filepaths)} YARA rule files from {rules_dir}")
        except yara.Error as e:
            logger.error(f"Failed to compile YARA rules: {e}. Falling back to regex.")
            self._use_yara = False

    def scan_file(self, file_path: str, similarity_file: Optional[str] = None) -> Optional[dict]:
        """
        Scan a single file for sensitive data.
        
        Returns a dict of findings or None if no sensitive data found / file unreadable.
        """
        self.current_file = file_path
        try:
            if not os.access(file_path, os.R_OK):
                logger.warning(f"No read permission: {file_path}")
                return None
            
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                logger.info(f"Skipping {file_path} ({file_size} bytes > {self.max_file_size} limit)")
                return None
            
            if file_size == 0:
                return None
            
            mime = detect_mime_type(file_path)
            content = self._extract_content(file_path, mime)
            if not content:
                return None
            
            findings = self._scan_content(content, file_path)
            
            if similarity_file:
                score = self._calculate_similarity(content, similarity_file)
                if score > 0:
                    findings["similarity_score"] = score
            
            return findings if findings else None
            
        except PermissionError:
            logger.warning(f"Permission denied: {file_path}")
            return None
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
            return None

    def _extract_content(self, file_path: str, mime_type: str) -> Optional[str]:
        """Extract text content from a file based on its MIME type."""
        try:
            if "text" in mime_type or "json" in mime_type or "xml" in mime_type:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            
            elif "pdf" in mime_type:
                with pdfplumber.open(file_path) as pdf:
                    pages = []
                    for page in pdf.pages:
                        text = page.extract_text()
                        if text:
                            pages.append(text)
                    return "\n".join(pages) if pages else None
            
            elif "word" in mime_type or "officedocument.wordprocessing" in mime_type:
                doc = docx.Document(file_path)
                paragraphs = [p.text for p in doc.paragraphs if p.text]
                # Also extract table text
                for table in doc.tables:
                    for row in table.rows:
                        for cell in row.cells:
                            if cell.text:
                                paragraphs.append(cell.text)
                return "\n".join(paragraphs) if paragraphs else None
            
            elif "spreadsheet" in mime_type or "officedocument.spreadsheet" in mime_type:
                wb = load_workbook(file_path, read_only=True, data_only=True)
                content = []
                for sheet in wb.worksheets:
                    for row in sheet.iter_rows(values_only=True):
                        for cell in row:
                            if cell is not None:
                                content.append(str(cell))
                wb.close()
                return "\n".join(content) if content else None
            
            else:
                # Fallback: try reading as text
                ext = Path(file_path).suffix.lower()
                if ext in SUPPORTED_EXTENSIONS:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        return f.read()
                return None
                
        except PermissionError:
            logger.warning(f"Permission denied reading: {file_path}")
            return None
        except Exception as e:
            logger.warning(f"Could not extract content from {file_path}: {e}")
            return None

    def _scan_content(self, content: str, file_path: str) -> dict:
        """Scan extracted text content for sensitive data patterns."""
        findings = {}
        
        if self._use_yara and self.rules:
            # YARA path: scan raw bytes, then validate with regex/Luhn
            try:
                matches = self.rules.match(data=content.encode('utf-8', errors='ignore'))
                for match in matches:
                    rule_name = match.rule
                    category = self._categorize_yara_rule(rule_name)
                    if category not in findings:
                        findings[category] = {}
                    
                    # Extract matched strings for masking
                    for string_match in match.strings:
                        matched_text = ""
                        # yara-python 4.5+ uses .instances (list of StringInstance)
                        if hasattr(string_match, 'instances') and string_match.instances:
                            for instance in string_match.instances:
                                raw = instance.matched_data if hasattr(instance, 'matched_data') else getattr(instance, 'match_data', b'')
                                if isinstance(raw, bytes):
                                    matched_text = raw.decode('utf-8', errors='ignore')
                                else:
                                    matched_text = str(raw)
                                matched_text = _clean_match(matched_text)
                                masked = mask_sensitive(matched_text)
                                pattern_name = self._identify_pattern(category, matched_text)
                                if pattern_name not in findings[category]:
                                    findings[category][pattern_name] = []
                                findings[category][pattern_name].append(masked)
            except Exception as e:
                logger.warning(f"YARA scan failed for {file_path}: {e}. Using regex.")
                findings = self._scan_content_regex(content)
        else:
            findings = self._scan_content_regex(content)
        
        return findings

    def _scan_content_regex(self, content: str) -> dict:
        """Scan content using Python regex patterns."""
        findings = {}
        
        for category, patterns in REGEX_PATTERS.items():
            category_findings = {}
            for name, pattern in patterns.items():
                matches = pattern.finditer(content)
                found = []
                for match in matches:
                    matched_text = _clean_match(match.group())
                    # Luhn validation for credit cards
                    if name == "Credit Card":
                        if not luhn_check(matched_text):
                            continue
                    # Skip obvious false positives
                    if name == "Expiry Date" and not self._is_likely_expiry(content, match.start()):
                        continue
                    masked = mask_sensitive(matched_text)
                    found.append(masked)
                if found:
                    category_findings[name] = found
            if category_findings:
                findings[category] = category_findings
        
        return findings

    def _categorize_yara_rule(self, rule_name: str) -> str:
        """Map YARA rule names to categories."""
        name_lower = rule_name.lower()
        if "pii" in name_lower:
            return "PII"
        elif "phi" in name_lower:
            return "PHI"
        elif "pci" in name_lower:
            return "PCI"
        elif "source" in name_lower or "secret" in name_lower:
            return "Source Code"
        return "Other"

    def _identify_pattern(self, category: str, matched_text: str) -> str:
        """Identify the specific pattern type from matched text."""
        if category == "PII":
            if re.match(r"\d{3}-\d{2}-\d{4}", matched_text):
                return "SSN"
            if "@" in matched_text:
                return "Email"
            if luhn_check(matched_text):
                return "Credit Card"
            if re.match(r"\+?\d?[\d\s().-]{10,}", matched_text):
                return "Phone"
            return "PII"
        elif category == "PHI":
            if "mrn" in matched_text.lower():
                return "Medical Record"
            if "insurance" in matched_text.lower() or "policy" in matched_text.lower():
                return "Health Plan ID"
            return "PHI"
        elif category == "PCI":
            if "cvv" in matched_text.lower():
                return "CVV"
            return "Expiry Date"
        elif category == "Source Code":
            if "akia" in matched_text.lower():
                return "AWS Key"
            if "private key" in matched_text.lower():
                return "Private Key"
            if "password" in matched_text.lower():
                return "Password"
            return "API Key"
        return "Unknown"

    def _is_likely_expiry(self, content: str, pos: int) -> bool:
        """Check if a date pattern is likely a card expiry (near CC or CVV context)."""
        context = content[max(0, pos - 200):pos + 50].lower()
        return any(kw in context for kw in ["exp", "valid", "card", "cvv", "cvc", "expiry"])

    def _calculate_similarity(self, content: str, similarity_file: str) -> int:
        """Calculate similarity between content and a reference file (0-10 scale)."""
        if not SIMILARITY_AVAILABLE:
            logger.warning("python-Levenshtein not installed, skipping similarity")
            return 0
        try:
            with open(similarity_file, 'r', encoding='utf-8', errors='ignore') as f:
                ref_content = f.read()
            similarity = lev_ratio(content, ref_content)
            return round(similarity * 10)
        except Exception as e:
            logger.error(f"Error calculating similarity: {e}")
            return 0

    def scan_directory(self, directory_path: str, similarity_file: Optional[str] = None,
                       progress_callback=None) -> Optional[dict]:
        """
        Scan all supported files in a directory tree.
        
        Returns a dict mapping file paths to their findings.
        """
        if not self._check_directory_access(directory_path):
            logger.error(f"Cannot access directory: {directory_path}")
            return None
        
        results = {}
        try:
            for root, dirs, files in os.walk(directory_path):
                # Skip hidden directories and common non-scannable paths
                dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
                
                for filename in files:
                    file_path = os.path.join(root, filename)
                    ext = Path(filename).suffix.lower()
                    
                    # Only scan supported file types
                    if ext not in SUPPORTED_EXTENSIONS:
                        continue
                    
                    self.current_file = file_path
                    if progress_callback:
                        progress_callback(f"Scanning: {file_path}")
                    
                    try:
                        file_results = self.scan_file(file_path, similarity_file)
                        if file_results:
                            results[file_path] = file_results
                    except Exception as e:
                        logger.warning(f"Error scanning {file_path}: {e}")
                        continue
            
            return results if results else None
        
        except Exception as e:
            logger.error(f"Error scanning directory {directory_path}: {e}")
            return None

    def _check_directory_access(self, directory_path: str) -> bool:
        """Verify directory exists and is readable."""
        try:
            test_path = Path(directory_path)
            if not test_path.exists():
                logger.error(f"Path does not exist: {directory_path}")
                return False
            if not test_path.is_dir():
                logger.error(f"Not a directory: {directory_path}")
                return False
            if not os.access(str(test_path), os.R_OK):
                logger.error(f"No read permission: {directory_path}")
                return False
            return True
        except Exception as e:
            logger.error(f"Error checking directory access: {e}")
            return False


# Backward-compatible alias
Scanner = SensitiveDataScanner
