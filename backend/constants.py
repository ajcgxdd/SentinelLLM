"""Shared constants: patterns, keywords, MITRE mappings."""

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"forget\s+(everything|all|your)\s*(instructions?|above|previous)?",
    r"you\s+are\s+now\s+(a\s+)?(dan|jailbreak|evil|unfiltered|unrestricted)",
    r"do\s+anything\s+now", r"developer\s+mode",
    r"pretend\s+(you\s+)?(have\s+no\s+restrictions?|are\s+not\s+an?\s+ai)",
    r"act\s+as\s+(if\s+you\s+are\s+)?(unrestricted|unfiltered|jailbroken)",
    r"bypass\s+(all\s+)?(safety|security|filter|restriction|content)",
    r"system\s*:\s*(you\s+are|ignore)", r"<\s*system\s*>", r"\[system\]",
    r"<INST>|<\/INST>|<<SYS>>", r"prompt\s*injection",
    r"disregard\s+(your|all)\s+(previous|prior|training|instructions?)",
    r"reveal\s+(your\s+)?(system\s+prompt|instructions?|training)",
]

ZERO_DAY_PATTERNS = [
    r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){3,}",
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]",
    r"(\bexec\b|\beval\b|\bsystem\b|\bshell\b).*[\(\{]",
    r"base64[,\s]*[A-Za-z0-9+/]{20,}",
    r"<script[\s>]", r"javascript\s*:", r"on(load|click|error|mouseover)\s*=",
]

INJECTION_KEYWORDS = {
    "ignore": 0.9, "bypass": 0.85, "jailbreak": 0.95, "unrestricted": 0.88,
    "dan": 0.82, "system prompt": 0.9, "no restrictions": 0.87, "override": 0.75,
    "disregard": 0.83, "pretend": 0.6, "roleplay": 0.45, "forget": 0.7,
    "reveal": 0.65, "leak": 0.72, "exfiltrate": 0.91, "exploit": 0.8,
    "inject": 0.85, "payload": 0.78, "malicious": 0.7, "attack": 0.6,
    "hack": 0.65, "exec(": 0.92, "eval(": 0.9, "shell": 0.75, "base64": 0.7,
}

MITRE_MAPPING = {
    "prompt_injection":  ("T1190", "Exploit Public-Facing Application"),
    "zero_day_anomaly":  ("T1203", "Exploitation for Client Execution"),
    "jailbreak":         ("T1562", "Impair Defenses"),
    "data_exfiltration": ("T1041", "Exfiltration Over C2 Channel"),
    "high_perplexity":   ("T1027", "Obfuscated Files or Information"),
    "suspicious":        ("T1059", "Command and Scripting Interpreter"),
    "benign":            (None,    "No MITRE mapping"),
}
