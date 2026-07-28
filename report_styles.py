"""
report_styles.py

Lets the user pick which forensic reporting standard/style the PDF
report should follow, and adds an organisation name, analyst name,
and free-text "special requirements" note that get woven into the
report. This only changes section structure and wording — the
underlying data (detections, incidents, chain-of-custody status)
is identical regardless of style, and nothing here touches the
detection model, the ledger, or SHAP.

Add a new style by adding an entry to REPORT_STYLES: a short label
plus a list of (heading, paragraph_template) section templates. Any
of "{total}", "{attack}", "{pct}", "{org}", "{analyst}", "{case_id}",
"{requirements}" can be used in a paragraph template.
"""

REPORT_STYLES = {
    "academic": {
        "label": "Academic / Capstone (default)",
        "intro": (
            "This report documents the post-incident forensic analysis performed on "
            "the captured CAN bus traffic for {case_id}, prepared as part of an academic "
            "capstone project on vehicle network security."
        ),
        "sections": ["Summary", "Methodology", "Detected Incidents", "Chain of Custody", "Conclusion"],
        "methodology": (
            "Traffic was classified using a supervised machine-learning model trained on "
            "CAN frame features (inter-arrival time, ID frequency, DLC, payload bytes). "
            "Flagged packets were logged to a SHA-256 hash-chained evidence ledger to "
            "preserve chain of custody, and per-detection explanations were generated "
            "using SHAP to support the classifier's findings."
        ),
    },
    "nist_800-86": {
        "label": "NIST SP 800-86 (Digital Forensics)",
        "intro": (
            "In accordance with NIST Special Publication 800-86 (Guide to Integrating "
            "Forensic Techniques into Incident Response), this report presents the "
            "Collection, Examination, Analysis, and Reporting phases performed against "
            "the CAN bus capture associated with {case_id}."
        ),
        "sections": ["Collection", "Examination", "Analysis", "Reporting", "Chain of Custody"],
        "methodology": (
            "Collection: raw CAN frames were captured with timestamp, identifier, DLC, "
            "and payload preserved unmodified. Examination: frames were parsed and "
            "feature-engineered without altering source data. Analysis: a trained "
            "classifier assessed each frame against known attack signatures (DoS, "
            "Fuzzy, Spoofing), with SHAP used to make the analysis explainable and "
            "defensible. Reporting: findings below summarise all phases per NIST 800-86 "
            "guidance."
        ),
    },
    "iso_27037": {
        "label": "ISO/IEC 27037 (Digital Evidence Handling)",
        "intro": (
            "This report follows the identification, collection, acquisition, and "
            "preservation principles of ISO/IEC 27037:2012 for the handling of digital "
            "evidence relating to {case_id}."
        ),
        "sections": ["Identification", "Collection & Acquisition", "Preservation", "Analysis", "Chain of Custody"],
        "methodology": (
            "Identification: CAN frames of evidentiary interest were flagged by a "
            "trained classification model. Collection & Acquisition: flagged frames "
            "and their context were captured with full fidelity to source data. "
            "Preservation: every flagged event was committed to a cryptographically "
            "chained ledger (SHA-256) immediately upon detection, ensuring integrity "
            "is independently verifiable. Analysis: SHAP-based explanations were "
            "generated to document why each frame was classified as it was."
        ),
    },
    "law_enforcement": {
        "label": "Law Enforcement / Chain-of-Custody Case File",
        "intro": (
            "Case File {case_id} — prepared by {org} for the record. This report "
            "constitutes the examining analyst's summary of digital evidence recovered "
            "from a vehicle CAN bus capture, together with the associated chain of "
            "custody."
        ),
        "sections": ["Case Summary", "Evidence Log", "Analyst's Findings", "Chain of Custody Statement", "Certification"],
        "methodology": (
            "All evidentiary packets were logged at time of detection to a tamper-"
            "evident ledger using SHA-256 hash chaining, such that any post-hoc "
            "alteration of a record would invalidate the chain and be immediately "
            "detectable upon verification. The examining analyst's findings below are "
            "supported by model-generated confidence scores and per-detection SHAP "
            "explanations."
        ),
    },
    "corporate_soc": {
        "label": "Corporate SOC / Incident Report",
        "intro": (
            "Security Operations Center incident report for {case_id}, prepared by "
            "{org}. This report summarises detected anomalous CAN bus activity, "
            "assessed impact, and recommended remediation."
        ),
        "sections": ["Incident Summary", "Indicators of Compromise", "Impact Assessment", "Chain of Custody", "Recommendations"],
        "methodology": (
            "Anomalous traffic was identified using a supervised classifier flagging "
            "Denial-of-Service, Fuzzy, and Spoofing patterns on the CAN bus. Detected "
            "indicators were logged to an integrity-verified evidence ledger. Findings "
            "are supported by SHAP explainability output to aid triage and post-"
            "incident review."
        ),
    },
}


def get_style_keys_and_labels():
    return [(k, v["label"]) for k, v in REPORT_STYLES.items()]
