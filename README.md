# Scanwell

Cross-platform sensitive data scanner for local host devices. Detects PII, PHI, PCI, and source code secrets in files.

## What's New in v2.0

- **CLI-first** — no GUI dependency
- **Cross-platform** — macOS, Windows, Linux
- **YARA + Regex hybrid** — YARA for pattern matching, regex for validation (Luhn, context-aware expiry)
- **Luhn validation** — eliminates credit card false positives
- **File size limits** — prevents memory bombs
- **Real reports** — CSV, TXT, JSON, PDF all fully implemented
- **Fixed tests** — all imports corrected, full coverage

## Install

```bash
python3 -m venv venv
# macOS/Linux:
source venv/bin/activate
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

### Platform Notes

- **macOS**: Works out of the box. libmagic is installed via Homebrew if you want MIME sniffing, but extension-based fallback works fine without it.
- **Linux**: Works out of the box on most distros. Install `libmagic1` (Debian/Ubuntu) or `file-libs` (Alpine) for MIME sniffing.
- **Windows**: `python-magic` is optional. The scanner falls back to extension-based MIME detection if libmagic isn't installed. For MIME sniffing, install [libmagic](https://github.com/julian-r/python-magic#dependencies) and ensure `magic.dll` is on your PATH.

## Usage

```bash
# Scan a directory
python -m src.cli scan /path/to/scan --format csv

# Scan a single file
python -m src.cli scan /path/to/file.txt

# Disable YARA (regex only)
python -m src.cli scan /path/to/scan --no-yara

# Set max file size (MB)
python -m src.cli scan /path/to/scan --max-size 100

# Generate report from existing results
python -m src.cli report scanwell_results.json --format pdf

# View/reset config
python -m src.cli config
python -m src.cli config --reset

# Version
python -m src.cli version
```

## Detection Categories

- **PII**: SSN, credit cards (Luhn-validated), email, phone, driver's license
- **PHI**: Medical record numbers, health plan IDs, ICD-10 codes, treatment dates
- **PCI**: CVV/CVV2, expiration dates (context-aware)
- **Source Code**: API keys, passwords, AWS keys, private keys, DB connection strings

## File Support

- Plain text, CSV, JSON, XML, YAML
- Microsoft Word (.docx), Excel (.xlsx)
- PDF
- Source code: Python, Java, C/C++, Go, Rust, JavaScript, SQL, shell scripts

## Output

Reports go to `~/Scanwell Reports/scanwell_report_<timestamp>.<format>` by default.

## Tests

```bash
pytest tests/
```
