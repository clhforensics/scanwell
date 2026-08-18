// phi_patterns.yara
// YARA-compatible rules for PHI data detection.

rule PHI_Detection
{
    meta:
        description = "Detect PHI data patterns"
        author = "Scanwell"
        severity = "high"

    strings:
        // Medical Record Numbers
        $mrn1 = /MRN[: ]*[0-9]+/
        $mrn2 = /Medical Record Number[: ]*[0-9]+/

        // Health Plan Beneficiary Numbers (pattern like 123AB456789)
        $hpbn = /[0-9]{3}[A-Z]{2}[0-9]{6}/

        // Treatment/Admission/Discharge Dates
        $treatment_date = /(Treatment|Admission|Discharge)[ ]*Date[: ]*[0-9]{2}[\/\-][0-9]{2}[\/\-][0-9]{4}/

        // ICD-10 Diagnosis Codes (e.g., J45.20)
        $icd10 = /[A-Z][0-9]{2}[\-\.][0-9]{1,2}/

        // Medical Device Identifiers
        $device_id = /[0-9]{2}[A-Z]{3}[0-9]{8}/

    condition:
        any of them
}
