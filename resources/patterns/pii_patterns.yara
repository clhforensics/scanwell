// pii_patterns.yara
// YARA-compatible rules for PII data detection.

rule PII_Detection
{
    meta:
        description = "Detect PII data patterns"
        author = "Scanwell"
        severity = "high"

    strings:
        // Social Security Numbers (XXX-XX-XXXX)
        $ssn = /[0-9]{3}[\-][0-9]{2}[\-][0-9]{4}/

        // Email Addresses
        $email = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/

        // Phone Numbers (various formats)
        $phone1 = /[0-9]{3}[\-\.]?[0-9]{3}[\-\.]?[0-9]{4}/
        $phone2 = /\([0-9]{3}\)[ ]?[0-9]{3}[\-\.]?[0-9]{4}/

        // Driver's License (state-specific patterns)
        $dl_ca = /[A-Z][0-9]{7}/
        $dl_tx = /[0-9]{7,8}/

    condition:
        any of them
}
