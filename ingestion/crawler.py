# pip install aiohttp feedparser pydantic

import asyncio
import logging
import re
from html import unescape
from urllib.parse import urlparse

import aiohttp
import feedparser
from pydantic import BaseModel, Field

from ingestion.config import (
    INGESTION_FEED_TIMEOUT_SECONDS,
    INGESTION_MAX_CONCURRENT_FEEDS,
    RSS_FEED_LINKS,
)

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS = INGESTION_FEED_TIMEOUT_SECONDS
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
HTML_TAG_RE = re.compile(r"<[^>]+>")


class NormalizedArticle(BaseModel):
    """Uniform article representation after normalization."""

    source: str
    title: str
    url: str | None = None
    raw_content: str = Field(description="Plain-text body with HTML stripped")


class FeedCrawler:
    """Async RSS fetcher with fault-tolerant per-feed handling."""

    def __init__(
        self,
        feed_urls: list[str] | None = None,
        timeout_seconds: float = REQUEST_TIMEOUT_SECONDS,
        max_concurrent_feeds: int = INGESTION_MAX_CONCURRENT_FEEDS,
    ) -> None:
        self._feed_urls = feed_urls if feed_urls is not None else RSS_FEED_LINKS
        self._timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self._headers = {"User-Agent": USER_AGENT}
        self._max_concurrent = max(1, max_concurrent_feeds)
        self._feed_errors: dict[str, int] = {
            "timeout": 0,
            "http_error": 0,
            "not_found": 0,
            "connection": 0,
            "other": 0,
            "empty": 0,
        }

    @property
    def feed_errors(self) -> dict[str, int]:
        return dict(self._feed_errors)

    async def crawl_all(self) -> list[NormalizedArticle]:
        self._feed_errors = {k: 0 for k in self._feed_errors}
        sem = asyncio.Semaphore(self._max_concurrent)

        async with aiohttp.ClientSession(
            timeout=self._timeout,
            headers=self._headers,
        ) as session:

            async def _bounded(url: str) -> list[NormalizedArticle]:
                async with sem:
                    return await self._fetch_feed(session, url)

            batches = await asyncio.gather(*[_bounded(url) for url in self._feed_urls])

        articles: list[NormalizedArticle] = []
        for batch in batches:
            if not batch:
                self._feed_errors["empty"] += 1
            articles.extend(batch)
        return articles

    async def _fetch_feed(
        self,
        session: aiohttp.ClientSession,
        feed_url: str,
    ) -> list[NormalizedArticle]:
        label = _feed_label(feed_url)
        try:
            async with session.get(feed_url) as response:
                if response.status == 404:
                    self._feed_errors["not_found"] += 1
                    logger.error("feed_not_found url=%s status=404", feed_url)
                    return []
                if response.status >= 400:
                    self._feed_errors["http_error"] += 1
                    logger.error("feed_http_error url=%s status=%s", feed_url, response.status)
                    return []
                body = await response.text()
        except asyncio.TimeoutError:
            self._feed_errors["timeout"] += 1
            logger.error("feed_timeout url=%s", feed_url)
            return []
        except aiohttp.ClientError as exc:
            self._feed_errors["connection"] += 1
            logger.error("feed_connection_error url=%s error=%s", feed_url, exc)
            return []
        except Exception as exc:
            self._feed_errors["other"] += 1
            logger.error("feed_unexpected_error url=%s error=%s", feed_url, exc)
            return []

        return self._parse_and_normalize(feed_url, label, body)

    def _parse_and_normalize(
        self,
        feed_url: str,
        fallback_source: str,
        raw_xml: str,
    ) -> list[NormalizedArticle]:
        parsed = feedparser.parse(raw_xml)
        source = parsed.feed.get("title") or fallback_source
        articles: list[NormalizedArticle] = []

        for entry in parsed.entries:
            title = (entry.get("title") or "Untitled").strip()
            link = entry.get("link") or entry.get("id")
            body = (
                entry.get("summary", "")
                or entry.get("description", "")
                or ""
            )
            if not body and entry.get("content"):
                body = entry["content"][0].get("value", "")

            articles.append(
                NormalizedArticle(
                    source=source,
                    title=title,
                    url=link,
                    raw_content=self._strip_html(body),
                )
            )
        return articles

    @staticmethod
    def _strip_html(html: str) -> str:
        text = HTML_TAG_RE.sub(" ", html or "")
        text = unescape(text)
        text = re.sub(r"\s+", " ", text).strip()
        return text


def _feed_label(feed_url: str) -> str:
    """Human-readable label from URL when no feed title is available."""
    host = urlparse(feed_url).netloc or feed_url
    return host.removeprefix("www.")
