"""
Stealer log parser.

Identifies messages that are stealer log advertisements or drops,
and extracts structured metadata:
  • Stealer family (RedLine, Raccoon, Vidar, Lumma, etc.)
  • Log count / line count
  • Country breakdown
  • Data types included (passwords, cookies, crypto wallets, etc.)
  • Price (if selling)
  • File information (name, hash, size)
  • Download links / onion URLs
"""

import re
from dataclasses import dataclass, field


# ── Known stealer families ────────────────────────────────────────────
# Tuple of (canonical name, regex pattern matching variations)
_FAMILIES = [
    ("RedLine",     re.compile(r"\bredline\b", re.I)),
    ("Raccoon",     re.compile(r"\braccoon\s*(?:stealer)?\b", re.I)),
    ("Vidar",       re.compile(r"\bvidar\b", re.I)),
    ("Lumma",       re.compile(r"\blumma\b", re.I)),
    ("Meta",        re.compile(r"\bmeta\s*stealer\b", re.I)),
    ("Aurora",      re.compile(r"\baurora\s*(?:stealer)?\b", re.I)),
    ("Stealc",      re.compile(r"\bstealc\b", re.I)),
    ("Titan",       re.compile(r"\btitan\s*stealer\b", re.I)),
    ("Arkei",       re.compile(r"\barkei\b", re.I)),
    ("Mars",        re.compile(r"\bmars\s*stealer\b", re.I)),
    ("Rhadamanthys", re.compile(r"\brhadamanthys\b", re.I)),
    ("Mystic",      re.compile(r"\bmystic\s*stealer\b", re.I)),
    ("RisePro",     re.compile(r"\brisepro\b", re.I)),
    ("Atomic",      re.compile(r"\batomic\s*(?:stealer|macos)\b", re.I)),
    ("Bandit",      re.compile(r"\bbandit\s*stealer\b", re.I)),
    ("Nexus",       re.compile(r"\bnexus\s*stealer\b", re.I)),
]

# ── Signals that a message is about stealer logs ──────────────────────
_LOG_SIGNALS = [
    re.compile(r"\b(?:stealer|steal)\s*logs?\b", re.I),
    re.compile(r"\blogs?\s*(?:fresh|new|free|update|daily|cloud)\b", re.I),
    re.compile(r"\b(?:fresh|new|free)\s*logs?\b", re.I),
    re.compile(r"\bcloud\s*logs?\b", re.I),
    re.compile(r"\bcookies?\s*(?:log|grab|steal)\b", re.I),
    re.compile(r"\bpassw(?:ord)?s?\s*(?:log|grab|steal|dump)\b", re.I),
    re.compile(r"\b\d+\s*(?:k|K)\s*(?:logs?|lines?|entries)\b", re.I),
    re.compile(r"\b(?:combo|combolist)\b", re.I),
]

# ── Data types found in logs ──────────────────────────────────────────
_DATA_TYPES = {
    "passwords":    re.compile(r"\bpassw(?:ord)?s?\b", re.I),
    "cookies":      re.compile(r"\bcookies?\b", re.I),
    "autofill":     re.compile(r"\bauto\s*fill\b", re.I),
    "credit_cards": re.compile(r"\b(?:credit\s*cards?|CC|cvv)\b", re.I),
    "crypto_wallets": re.compile(r"\b(?:crypto|wallet|metamask|exodus|bitcoin|btc|eth)\b", re.I),
    "tokens":       re.compile(r"\b(?:discord|telegram|session)\s*tokens?\b", re.I),
    "screenshots":  re.compile(r"\bscreenshots?\b", re.I),
    "keylog":       re.compile(r"\bkey\s*log(?:ger|ging|s)?\b", re.I),
    "files":        re.compile(r"\b(?:files?|documents?|\.txt|\.doc)\b", re.I),
    "2fa":          re.compile(r"\b(?:2fa|authenticator|otp)\b", re.I),
    "vpn":          re.compile(r"\b(?:vpn|nord|express)\s*(?:cred|account|config)\b", re.I),
    "rdp":          re.compile(r"\brdp\b", re.I),
    "ftp":          re.compile(r"\bftp\b", re.I),
    "email_access": re.compile(r"\b(?:imap|smtp|email\s*access|mailbox)\b", re.I),
    "browser_data": re.compile(r"\b(?:browser|chrome|firefox|edge)\s*(?:data|profile)?\b", re.I),
}

# ── Country extraction ────────────────────────────────────────────────
_COUNTRY_PATTERN = re.compile(
    r"\b(US|USA|UK|GB|DE|FR|CA|AU|IT|ES|NL|BR|IN|RU|"
    r"JP|KR|MX|TR|PL|SE|CH|AT|BE|CZ|DK|FI|NO|PT|"
    r"United\s*States|United\s*Kingdom|Germany|France|Canada|"
    r"Australia|Italy|Spain|Netherlands|Brazil|India|Russia|"
    r"Japan|South\s*Korea|Mexico|Turkey|Poland|Sweden|"
    r"Switzerland|Austria|Belgium|Czech|Denmark|Finland|Norway|Portugal)\b",
    re.I,
)

# ── Count extraction (e.g. "50k logs", "2.3M lines", "15,000 entries")
_COUNT_PATTERN = re.compile(
    r"\b(\d[\d,\.]*)\s*([kKmM])?\s*(?:logs?|lines?|entries|records?|results?|hits?|accounts?)\b"
)

# ── Price extraction ──────────────────────────────────────────────────
_PRICE_PATTERN = re.compile(
    r"\$\s*(\d[\d,\.]*)|(\d[\d,\.]*)\s*(?:USD|usd|\$|USDT|usdt)"
)


@dataclass
class StealerLogEntry:
    is_stealer_log: bool = False
    confidence: float = 0.0           # 0.0 - 1.0
    families: list[str] = field(default_factory=list)
    log_count: int | None = None
    countries: list[str] = field(default_factory=list)
    data_types: list[str] = field(default_factory=list)
    price_usd: str = ""
    has_download: bool = False        # download link/file detected
    download_type: str = ""           # 'mega', 'gofile', 'mediafire', 'onion', 'direct', 'telegram', etc.
    raw_text: str = ""

    def as_dict(self) -> dict:
        if not self.is_stealer_log:
            return {}
        return {
            "is_stealer_log": True,
            "confidence": round(self.confidence, 2),
            "families": self.families,
            "log_count": self.log_count,
            "countries": self.countries,
            "data_types": self.data_types,
            "price_usd": self.price_usd,
            "has_download": self.has_download,
            "download_type": self.download_type,
        }


# ── Download / file hosting indicators ────────────────────────────────
_DOWNLOAD_PATTERNS = [
    ("mega",       re.compile(r"mega\.nz/|mega\.co\.nz/", re.I)),
    ("gofile",     re.compile(r"gofile\.io/", re.I)),
    ("mediafire",  re.compile(r"mediafire\.com/", re.I)),
    ("anonfiles",  re.compile(r"anonfiles\.com/|anonymfile\.com/", re.I)),
    ("pixeldrain", re.compile(r"pixeldrain\.com/", re.I)),
    ("catbox",     re.compile(r"catbox\.moe/|files\.catbox\.moe/", re.I)),
    ("transfer",   re.compile(r"transfer\.sh/|wetransfer\.com/", re.I)),
    ("onion",      re.compile(r"[a-z2-7]{16,56}\.onion", re.I)),
    ("telegram",   re.compile(r"t\.me/\+|t\.me/joinchat/|t\.me/c/", re.I)),
    ("direct",     re.compile(r"\.(zip|rar|7z|gz|tar|txt)\b", re.I)),
    ("password",   re.compile(r"\bpass(?:word)?[\s:=]+\S+", re.I)),  # archive password = downloadable
]


def parse(text: str) -> StealerLogEntry:
    """
    Analyze a message and determine if it's a stealer log post.
    Returns a StealerLogEntry with extracted metadata.
    """
    entry = StealerLogEntry(raw_text=text[:1000])
    score = 0.0

    # Check for stealer family mentions
    for family_name, pattern in _FAMILIES:
        if pattern.search(text):
            entry.families.append(family_name)
            score += 0.35

    # Check for log signals
    signal_hits = sum(1 for s in _LOG_SIGNALS if s.search(text))
    score += min(signal_hits * 0.15, 0.45)

    # Check for data types
    for dtype, pattern in _DATA_TYPES.items():
        if pattern.search(text):
            entry.data_types.append(dtype)
    if len(entry.data_types) >= 2:
        score += 0.15
    if len(entry.data_types) >= 4:
        score += 0.10

    # Extract countries
    country_matches = _COUNTRY_PATTERN.findall(text)
    entry.countries = sorted(set(c.strip() for c in country_matches))
    if entry.countries:
        score += 0.10

    # Extract count
    count_match = _COUNT_PATTERN.search(text)
    if count_match:
        num_str = count_match.group(1).replace(",", "")
        multiplier = count_match.group(2)
        try:
            num = float(num_str)
            if multiplier and multiplier.lower() == "k":
                num *= 1000
            elif multiplier and multiplier.lower() == "m":
                num *= 1_000_000
            entry.log_count = int(num)
            score += 0.10
        except ValueError:
            pass

    # Extract price
    price_match = _PRICE_PATTERN.search(text)
    if price_match:
        entry.price_usd = price_match.group(1) or price_match.group(2)
        score += 0.05

    # Detect download links / file hosting
    for dl_type, dl_pattern in _DOWNLOAD_PATTERNS:
        if dl_pattern.search(text):
            entry.has_download = True
            entry.download_type = dl_type
            score += 0.10
            break  # one match is enough

    # Threshold
    entry.confidence = min(score, 1.0)
    entry.is_stealer_log = entry.confidence >= 0.35

    return entry
