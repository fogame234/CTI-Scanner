"""
Extract IOCs and interesting entities from raw message text.

Pulls out:
  • IPv4 / IPv6 addresses
  • Domains (defanged or normal)
  • URLs
  • File hashes (MD5, SHA1, SHA256)
  • Email addresses
  • CVE IDs
  • Bitcoin / Ethereum / Monero wallet addresses
  • Onion domains (.onion)

Handles common defanging: hxxp, [.], [:]
"""

import re
from dataclasses import dataclass, field


@dataclass
class Extracted:
    ipv4:       list[str] = field(default_factory=list)
    ipv6:       list[str] = field(default_factory=list)
    domain:     list[str] = field(default_factory=list)
    url:        list[str] = field(default_factory=list)
    md5:        list[str] = field(default_factory=list)
    sha1:       list[str] = field(default_factory=list)
    sha256:     list[str] = field(default_factory=list)
    email:      list[str] = field(default_factory=list)
    cve:        list[str] = field(default_factory=list)
    onion:      list[str] = field(default_factory=list)
    btc:        list[str] = field(default_factory=list)
    eth:        list[str] = field(default_factory=list)
    xmr:        list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(len(getattr(self, f)) for f in self.__dataclass_fields__)

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v}

    def all_iocs(self) -> list[tuple[str, str]]:
        """Return flat list of (type, value) tuples."""
        result = []
        for ioc_type in self.__dataclass_fields__:
            for val in getattr(self, ioc_type):
                result.append((ioc_type, val))
        return result


def _refang(text: str) -> str:
    """Undo common defanging."""
    text = text.replace("hxxp", "http")
    text = text.replace("[.]", ".")
    text = text.replace("[:]", ":")
    text = text.replace("(.)", ".")
    text = text.replace("{.}", ".")
    text = text.replace("[at]", "@")
    text = text.replace("[dot]", ".")
    return text


# ── Compiled patterns ─────────────────────────────────────────────────

_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_RE_IPV6 = re.compile(
    r"(?<![\w:])("
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"
    r")(?![\w:])"
)

_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|xyz|ru|cn|tk|top|info|biz|cc|pw|ws|"
    r"su|me|co|de|fr|uk|nl|in|br|it|es|au|ca|se|pl|ch|at|"
    r"onion|exit|i2p)\b",
    re.IGNORECASE,
)

_RE_URL = re.compile(
    r"https?://[^\s<>\"'\)\]]+",
    re.IGNORECASE,
)

_RE_MD5    = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_SHA1   = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

_RE_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

_RE_ONION = re.compile(
    r"\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b",
    re.IGNORECASE,
)

# Crypto wallets
_RE_BTC = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
_RE_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_RE_XMR = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")


# Known false-positive domains to skip
_FP_DOMAINS = {
    "telegram.org", "t.me", "google.com", "github.com",
    "youtube.com", "twitter.com", "x.com", "facebook.com",
}


def extract(text: str) -> Extracted:
    """Extract all IOCs from a block of text."""
    refanged = _refang(text)
    result = Extracted()

    # Order matters: extract longer patterns first to avoid substring collisions.

    # SHA256 before SHA1 before MD5
    result.sha256 = list(set(_RE_SHA256.findall(refanged)))
    # Remove SHA256 from text so they don't also match as SHA1/MD5
    cleaned = _RE_SHA256.sub("", refanged)
    result.sha1 = list(set(_RE_SHA1.findall(cleaned)))
    cleaned2 = _RE_SHA1.sub("", cleaned)
    result.md5 = list(set(_RE_MD5.findall(cleaned2)))

    result.cve = list(set(c.upper() for c in _RE_CVE.findall(refanged)))

    result.url = list(set(_RE_URL.findall(refanged)))

    result.email = list(set(_RE_EMAIL.findall(refanged)))

    result.ipv4 = list(set(_RE_IPV4.findall(refanged)))
    result.ipv6 = list(set(m.group(0) for m in _RE_IPV6.finditer(refanged)))

    # Domains — exclude IPs and known FPs
    ip_set = set(result.ipv4)
    raw_domains = set(_RE_DOMAIN.findall(refanged))
    result.domain = sorted(
        d.lower() for d in raw_domains
        if d not in ip_set and d.lower() not in _FP_DOMAINS
    )

    # Onion addresses
    result.onion = list(set(o.lower() for o in _RE_ONION.findall(refanged)))

    # Crypto wallets
    result.btc = list(set(_RE_BTC.findall(text)))  # case-sensitive
    result.eth = list(set(_RE_ETH.findall(refanged)))
    result.xmr = list(set(_RE_XMR.findall(text)))

    return result
