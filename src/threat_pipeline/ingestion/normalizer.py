import re
from datetime import datetime

from bs4 import BeautifulSoup, Comment
from markdownify import markdownify

from threat_pipeline.ingestion.fetcher import RawFeedEntry
from threat_pipeline.models.ingestion import NormalizedArticle

BLOCKED_TAGS = {"script", "style", "noscript", "iframe", "svg", "form"}
BLOCKED_SELECTORS = [
    "[class*='ad-']",
    "[class*='advert']",
    "[id*='tracking']",
    "[class*='cookie']",
    "[class*='newsletter']",
]


class ContentNormalizer:
    """Strip boilerplate and emit uniform Markdown/Text with metadata."""

    def normalize(self, entry: RawFeedEntry) -> NormalizedArticle:
        raw = entry.raw_html or entry.raw_text or ""
        clean_html = self._strip_boilerplate(raw)
        plain = self._html_to_plain(clean_html)
        markdown = markdownify(clean_html, heading_style="ATX").strip()
        markdown = self._collapse_whitespace(markdown)
        plain = self._collapse_whitespace(plain)

        return NormalizedArticle(
            source=entry.source,
            title=entry.title.strip(),
            published_at=entry.published_at,
            url=entry.url,
            content_markdown=markdown,
            content_plain=plain,
            fetched_at=datetime.utcnow(),
            raw_metadata=entry.metadata,
        )

    def _strip_boilerplate(self, html: str) -> str:
        if not html.strip():
            return ""
        if "<" not in html:
            return f"<p>{html}</p>"

        soup = BeautifulSoup(html, "lxml")
        for tag in soup.find_all(BLOCKED_TAGS):
            tag.decompose()
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            comment.extract()
        for selector in BLOCKED_SELECTORS:
            for node in soup.select(selector):
                node.decompose()
        for node in soup.find_all(attrs={"data-track": True}):
            node.decompose()
        return str(soup.body or soup)

    def _html_to_plain(self, html: str) -> str:
        soup = BeautifulSoup(html, "lxml")
        return soup.get_text(separator="\n", strip=True)

    def _collapse_whitespace(self, text: str) -> str:
        text = re.sub(r"\n{3,}", "\n\n", text)
        return re.sub(r"[ \t]+", " ", text).strip()
