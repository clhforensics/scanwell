// source_code_patterns.yara
// YARA-compatible rules for detecting secrets in source code.

rule SourceCode_Secrets
{
    meta:
        description = "Detect secrets in source code"
        author = "Scanwell"
        severity = "high"

    strings:
        // API Keys and Tokens (key="value" with 16+ chars)
        $api_key = /(api[_\-]?key|api[_\-]?token|access[_\-]?token|secret[_\-]key)['"]?[ ]*[:=][ ]*['"][A-Za-z0-9_\-]{16,}['"]/

        // Database Connection Strings
        $db_conn = /(mongodb|jdbc:postgresql|postgresql|mysql):\/\/[^\s<>'"]+/

        // AWS Keys (AKIA prefix)
        $aws_key = /(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}/

        // Private Keys
        $private_key = /-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----/

        // Generic password/secret assignments
        $password = /(password|pwd|passwd)['"]?[ ]*[:=][ ]*['"][^'"]{8,}['"]/

    condition:
        any of them
}
