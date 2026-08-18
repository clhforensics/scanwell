# In scanner.py
import yara

class SensitiveDataScanner:
    def __init__(self):
        # Compile YARA rules from files
        self.rules = yara.compile(filepaths={
            'pii': 'patterns/pii_patterns.yara',
            'phi': 'patterns/phi_patterns.yara',
            'pci': 'patterns/pci_patterns.yara',
            'source': 'patterns/source_code_patterns.yara'
        })