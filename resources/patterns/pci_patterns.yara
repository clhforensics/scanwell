// pci_patterns.yara
// YARA-compatible rules for PCI data detection.
// YARA uses POSIX regex (no \b word boundaries).

rule PCI_Detection
{
    meta:
        description = "Detect PCI data patterns"
        author = "Scanwell"
        severity = "high"

    strings:
        // Credit Card Numbers (major providers)
        $visa = /4[0-9]{12}([0-9]{3})?/
        $mastercard = /(5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}/
        $amex = /3[47][0-9]{13}/
        $discover = /6(011|5[0-9]{2})[0-9]{12}/

        // CVV Codes
        $cvv = /CVV2?[ ]?:[ ]*[0-9]{3,4}/

        // Expiration Dates (MM/YY or MM/YYYY)
        $exp_date = /(0[1-9]|1[0-2])[\/\-][0-9]{2,4}/

    condition:
        any of them
}
