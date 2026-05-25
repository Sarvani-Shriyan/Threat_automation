# pip install pydantic

import json
import logging
import re
from pathlib import Path
from typing import Any

from ingestion.config import PLATFORM_KEYWORDS

logger = logging.getLogger(__name__)

DEFAULT_INPUT_PATH = Path("data/threat_queue.json")

# CVE identifiers (NVD-style)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Fixed / patched / remediated context (low priority for detection engineering)
FIXED_CONTEXT_PATTERN = re.compile(
    r"(?:"
    r"\bfixed\b|\bpatched\b|\bremediated\b|\bupdate\s+available\b|"
    r"\bsecurity\s+(?:update|patch)\b|\bhas\s+been\s+(?:fixed|patched)\b|"
    r"\bwas\s+(?:fixed|patched|remediated)\b|\bnow\s+(?:fixed|patched)\b|"
    r"\baddressed\s+in\b|\bmitigation\s+available\b|"
    r"\bno\s+longer\s+vulnerable\b|\bresolved\s+in\b"
    r")",
    re.IGNORECASE,
)

# Historical / legacy vulnerability narrative
HISTORICAL_CONTEXT_PATTERN = re.compile(
    r"(?:"
    r"\blegacy\s+vulnerability\b|\bhistorical\s+(?:cve|vulnerability)\b|"
    r"\bdisclosed\s+in\s+(?:19|20)\d{2}\b|\byears\s+ago\b|"
    r"\bback\s+in\s+(?:19|20)\d{2}\b|\boriginally\s+patched\b"
    r")",
    re.IGNORECASE,
)


def load_platform_keywords() -> list[str]:
    return [k.strip() for k in PLATFORM_KEYWORDS if k.strip()]


def _compile_keyword_patterns(keywords: list[str]) -> list[re.Pattern[str]]:
    """Longer phrases first; word boundaries for short tokens."""
    ordered = sorted(keywords, key=len, reverse=True)
    patterns: list[re.Pattern[str]] = []
    for kw in ordered:
        if " " in kw or len(kw) > 4:
            patterns.append(re.compile(re.escape(kw), re.IGNORECASE))
        else:
            patterns.append(re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE))
    return patterns


class KeywordMatcher:
    """Platform keyword gate — requires >=1 platform keyword in title or content."""

    def __init__(self, keywords: list[str] | None = None) -> None:
        kws = keywords if keywords is not None else load_platform_keywords()
        self._patterns = _compile_keyword_patterns(kws)

    def article_text(self, article: dict[str, Any]) -> str:
        title = article.get("title") or ""
        content = article.get("content") or article.get("raw_content") or ""
        return f"{title}\n{content}"

    def matches_platform(self, article: dict[str, Any]) -> bool:
        text = self.article_text(article)
        return any(p.search(text) for p in self._patterns)

    def filter_articles(
        self, articles: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], int]:
        passed: list[dict[str, Any]] = []
        dropped = 0
        for article in articles:
            if self.matches_platform(article):
                passed.append(article)
            else:
                dropped += 1
        logger.info("platform_keyword_gate passed=%d dropped=%d", len(passed), dropped)
        return passed, dropped


class CvePatchFilter:
    """
    Drop articles that reference CVEs in a fixed/patched/historical context.
    Articles with no CVE identifiers pass through unchanged.
    """

    def __init__(
        self,
        cve_pattern: re.Pattern[str] = CVE_PATTERN,
        fixed_pattern: re.Pattern[str] = FIXED_CONTEXT_PATTERN,
        historical_pattern: re.Pattern[str] = HISTORICAL_CONTEXT_PATTERN,
        cve_window: int = 300,
    ) -> None:
        self._cve = cve_pattern
        self._fixed = fixed_pattern
        self._historical = historical_pattern
        self._window = cve_window

    def has_cve(self, text: str) -> bool:
        return self._cve.search(text) is not None

    def is_fixed_or_historical_cve(self, article: dict[str, Any]) -> bool:
        text = f"{article.get('title', '')}\n{article.get('content', '')}"
        if not self.has_cve(text):
            return False

        if self._historical.search(text):
            return True

        if self._fixed.search(text):
            return True

        for match in self._cve.finditer(text):
            start = max(0, match.start() - self._window)
            end = min(len(text), match.end() + self._window)
            window = text[start:end]
            if self._fixed.search(window):
                return True
        return False

    def filter_articles(
        self, articles: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], int]:
        passed: list[dict[str, Any]] = []
        dropped = 0
        for article in articles:
            if self.is_fixed_or_historical_cve(article):
                dropped += 1
                logger.debug(
                    "cve_patch_drop title=%s",
                    article.get("title"),
                )
            else:
                passed.append(article)
        logger.info("cve_patch_gate passed=%d dropped=%d", len(passed), dropped)
        return passed, dropped


def load_threat_queue(path: Path | str = DEFAULT_INPUT_PATH) -> list[dict[str, Any]]:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Threat queue not found: {file_path}")
    data = json.loads(file_path.read_text(encoding="utf-8"))
    return list(data.get("articles", []))
