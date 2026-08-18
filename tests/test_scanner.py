"""
Scanwell tests

Tests for the rebuilt scanner, config, and report generator.
"""

import json
import pytest
import tempfile
from pathlib import Path

from src.core.scanner import SensitiveDataScanner, luhn_check, mask_sensitive
from src.core.config_manager import ConfigManager
from src.utils.report_generator import ReportGenerator


class TestLuhnValidation:
    """Test credit card validation."""

    def test_valid_visa(self):
        assert luhn_check("4111111111111111") is True

    def test_valid_mastercard(self):
        assert luhn_check("5500000000000004") is True

    def test_invalid_card(self):
        assert luhn_check("1234567890123456") is False

    def test_card_with_dashes(self):
        assert luhn_check("4111-1111-1111-1111") is True

    def test_too_short(self):
        assert luhn_check("12345") is False


class TestMaskSensitive:
    """Test data masking."""

    def test_short_data_fully_masked(self):
        assert mask_sensitive("ab") == "**"
        assert mask_sensitive("abcd") == "****"

    def test_long_data_partial_mask(self):
        result = mask_sensitive("1234567890")
        assert result[0] == "1"
        assert result[-1] == "0"
        assert "*" in result


class TestConfigManager:
    """Test configuration persistence."""

    def test_default_config_has_required_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            cfg = ConfigManager(str(config_path))
            assert "resource_limits" in cfg.config
            assert "risk_thresholds" in cfg.config
            assert "file_types" in cfg.config
            assert "scan_settings" in cfg.config

    def test_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            cfg1 = ConfigManager(str(config_path))
            cfg1.set("custom_key", "test_value")
            
            cfg2 = ConfigManager(str(config_path))
            assert cfg2.get("custom_key") == "test_value"

    def test_risk_level(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = ConfigManager(str(Path(tmpdir) / "config.json"))
            assert cfg.get_risk_level(15) == "High"
            assert cfg.get_risk_level(7) == "Medium"
            assert cfg.get_risk_level(2) == "Low"
            assert cfg.get_risk_level(0) == "None"


class TestSensitiveDataScanner:
    """Test the core scanner."""

    def test_init_without_yara(self):
        scanner = SensitiveDataScanner(use_yara=False)
        assert scanner is not None

    def test_scan_text_file_with_pii(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write("SSN: 123-45-6789\nEmail: test@example.com\n")
            f.flush()
            path = f.name
        
        scanner = SensitiveDataScanner(use_yara=False)
        results = scanner.scan_file(path)
        assert results is not None
        # Should detect PII (SSN, Email)

    def test_scan_file_not_found(self):
        scanner = SensitiveDataScanner(use_yara=False)
        result = scanner.scan_file("/nonexistent/path/file.txt")
        assert result is None

    def test_scan_oversized_file_skipped(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write("test data")
            f.flush()
            path = f.name
        
        scanner = SensitiveDataScanner(max_file_size=2)  # 2 bytes
        result = scanner.scan_file(path)
        assert result is None  # File is larger than limit, should skip


class TestReportGenerator:
    """Test report generation in all formats."""

    @pytest.fixture
    def sample_results(self):
        return {
            "/tmp/test.txt": {
                "PII": {
                    "SSN": ["1**-**-***9"],
                    "Email": ["t**t@e*********.com"],
                },
                "PCI": {
                    "CVV": ["***"],
                },
            }
        }

    def test_csv_report(self, sample_results):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            path = gen.generate_report(sample_results, "csv")
            assert path is not None
            assert path.exists()
            content = path.read_text()
            assert "file_path" in content
            assert "SSN" in content

    def test_txt_report(self, sample_results):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            path = gen.generate_report(sample_results, "txt")
            assert path is not None
            assert path.exists()
            content = path.read_text()
            assert "SCANWELL" in content

    def test_json_report(self, sample_results):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            path = gen.generate_report(sample_results, "json")
            assert path is not None
            assert path.exists()
            data = json.loads(path.read_text())
            assert "findings" in data
            assert data["tool"] == "Scanwell"

    def test_pdf_report(self, sample_results):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            path = gen.generate_report(sample_results, "pdf")
            assert path is not None
            assert path.exists()
            assert path.suffix == ".pdf"

    def test_empty_results(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            path = gen.generate_report({}, "txt")
            assert path is not None
            assert "No sensitive data found" in path.read_text()
