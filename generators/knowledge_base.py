# pip install pydantic

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from generators.platform_router import PlatformRouter, RoutedProfile

logger = logging.getLogger(__name__)

DEFAULT_KB_DIR = Path("knowledge_base")
DEFAULT_MAX_ACTIONS = 15
LARGE_CATALOG_THRESHOLD = 500

PLATFORM_SIGNALS: dict[str, list[str]] = {
    "aws": ["aws", "cloudtrail", "iam", "s3", "ec2", "lambda", "sts", "assume role", "guardduty"],
    "azure": [
        "azure",
        "microsoft azure",
        "entra id",
        "microsoft entra",
        "entra",
        "aad",
        "arm",
        "arm template",
        "microsoft.recoveryservices",
        "resourcegroups",
        "defender",
        "service principal",
        "role assignment",
    ],
    "gcp": ["gcp", "google cloud", "cloud logging", "gsuite", "workspace", "bigquery", "gke"],
    "okta": [
        "okta",
        "okta verify",
        "okta idp",
        "okta system log",
        "mfa",
        "saml bypass",
        "identity takeover",
        "session hijacking",
        "user.session",
        "user.mfa",
        "policy.lifecycle",
        "system.api_token",
    ],
    "github": ["github", "gh api", "repository", "actions", "workflow"],
    "salesforce": ["salesforce", "sfdc"],
    "active_directory": ["active directory", "ad cs", "kerberos", "ldap", "samr", "domain controller"],
    "saml": ["saml", "federation", "assertion"],
    "oidc": ["oidc", "openid", "oauth"],
    "identity": ["oauth", "idp", "sso", "mfa", "identity provider"],
}


@dataclass
class CatalogEntry:
    platform: str
    catalog_profile: str
    keywords: list[str]
    action_names: list[str]
    source_file: str
    display_name: str = ""
    source: str = ""


@dataclass
class GroundingResult:
    matched_platforms: list[str] = field(default_factory=list)
    allowed_actions: list[str] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    match_scores: dict[str, float] = field(default_factory=dict)
    routed_profiles: list[str] = field(default_factory=list)
    primary_platform: str | None = None

    @property
    def action_count(self) -> int:
        return len(self.allowed_actions)


class KnowledgeBase:
    """Local JSON catalogs with modular platform/profile routing."""

    def __init__(
        self,
        base_dir: Path | str = DEFAULT_KB_DIR,
        max_actions: int = DEFAULT_MAX_ACTIONS,
        platforms: list[str] | None = None,
    ) -> None:
        self.base_dir = Path(base_dir)
        self.max_actions = max_actions
        self._platform_filter = {p.lower() for p in platforms} if platforms else None
        self._router = PlatformRouter()
        self._catalog: list[CatalogEntry] = []
        self._load()

    def _load(self) -> None:
        if not self.base_dir.exists():
            self.base_dir.mkdir(parents=True, exist_ok=True)
            logger.warning("Knowledge base empty: %s", self.base_dir.resolve())
            return

        json_files = [
            p for p in sorted(self.base_dir.rglob("*.json"))
            if not p.name.endswith(".raw.json")
        ]
        if self._platform_filter:
            root_profiles = {"github", "okta", "azure"}
            if not self._platform_filter.intersection(root_profiles):
                catalogs_dir = self.base_dir / "catalogs"
                json_files = [p for p in json_files if catalogs_dir in p.parents]

        for path in json_files:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                for entry in self._parse_catalog_file(data, path):
                    if self._platform_filter and entry.platform not in self._platform_filter:
                        continue
                    self._catalog.append(entry)
            except (json.JSONDecodeError, OSError) as exc:
                logger.error("kb_load_failed file=%s error=%s", path, exc)

        logger.info(
            "kb_loaded catalogs=%d total_actions=%d",
            len(self._catalog),
            sum(len(e.action_names) for e in self._catalog),
        )
        for entry in self._catalog:
            logger.info(
                "kb_catalog platform=%s profile=%s actions=%d file=%s",
                entry.platform,
                entry.catalog_profile,
                len(entry.action_names),
                entry.source_file,
            )

    def _parse_catalog_file(self, data: dict[str, Any], path: Path) -> list[CatalogEntry]:
        if "catalogs" in data and isinstance(data["catalogs"], list):
            return [self._entry_from_dict(item, path) for item in data["catalogs"]]
        return [self._entry_from_dict(data, path)]

    def _entry_from_dict(self, data: dict[str, Any], path: Path) -> CatalogEntry:
        platform = str(data.get("platform", path.stem)).lower()
        profile = str(data.get("catalog_profile", "default")).lower()
        keywords = [str(k).lower() for k in data.get("keywords", [platform])]
        try:
            rel = str(path.relative_to(self.base_dir))
        except ValueError:
            rel = str(path)
        return CatalogEntry(
            platform=platform,
            catalog_profile=profile,
            keywords=keywords,
            action_names=self._extract_action_names(data),
            source_file=rel,
            display_name=str(data.get("display_name", platform)),
            source=str(data.get("source", "")),
        )

    @staticmethod
    def _extract_action_names(data: dict[str, Any]) -> list[str]:
        names: list[str] = []
        for key in ("actionNames", "action_names", "events", "event_names", "valid_actions"):
            raw = data.get(key)
            if isinstance(raw, list):
                for item in raw:
                    if isinstance(item, str) and item.strip():
                        names.append(item.strip())
        return list(dict.fromkeys(names))

    def detect_platforms(self, text: str) -> list[str]:
        lower = text.lower()
        matched: list[tuple[int, str]] = []
        for platform, signals in PLATFORM_SIGNALS.items():
            hits = sum(1 for s in signals if s in lower)
            if hits:
                matched.append((hits, platform))
        matched.sort(reverse=True)
        return [p for _, p in matched]

    def _active_routes(self, text: str, platforms: list[str]) -> list[RoutedProfile]:
        return self._router.route(text, platforms)

    def _entry_selected(self, entry: CatalogEntry, route: RoutedProfile) -> bool:
        if entry.platform != route.platform:
            return False
        if entry.platform in ("aws", "gcp"):
            return entry.catalog_profile in ("default", "iam")
        return entry.catalog_profile == route.catalog_profile

    def _threat_tokens(self, lower_text: str) -> set[str]:
        return {t for t in re.findall(r"[a-z0-9]{3,}", lower_text)}

    def _score_actions(
        self,
        actions: list[str],
        lower_text: str,
        tokens: set[str],
        base_score: float,
    ) -> list[tuple[float, str]]:
        results: list[tuple[float, str]] = []
        large = len(actions) > LARGE_CATALOG_THRESHOLD

        for action in actions:
            action_lower = action.lower()
            if large:
                if not any(t in action_lower for t in tokens):
                    parts = re.split(r"[\W_.]+", action_lower)
                    if not any(p in lower_text for p in parts if len(p) > 3):
                        continue
            token_hits = sum(
                1 for t in re.split(r"[\W_.]+", action_lower) if len(t) > 2 and t in lower_text
            )
            direct = 2.0 if action_lower in lower_text else 0.0
            action_score = base_score + token_hits * 0.75 + direct
            if action_score > base_score or not large:
                results.append((action_score, action))
        results.sort(key=lambda x: (-x[0], x[1]))
        return results

    def lookup(self, threat_text: str) -> GroundingResult:
        platforms = self.detect_platforms(threat_text)
        routes = self._active_routes(threat_text, platforms)
        lower_text = threat_text.lower()
        tokens = self._threat_tokens(lower_text)

        if not routes:
            routes = [RoutedProfile(p, "default", 1.0) for p in platforms[:2]]

        per_route_limit = max(1, self.max_actions // max(len(routes), 1))
        scored: list[tuple[float, str, str, str]] = []

        for route in routes:
            for entry in self._catalog:
                if not self._entry_selected(entry, route):
                    continue
                base_score = sum(2.0 for kw in entry.keywords if kw in lower_text) + route.score
                for action_score, action in self._score_actions(
                    entry.action_names, lower_text, tokens, base_score
                )[: per_route_limit * 3]:
                    scored.append((action_score, action, entry.platform, entry.source_file))

        scored.sort(key=lambda x: (-x[0], x[1]))
        seen: set[str] = set()
        allowed: list[str] = []
        sources: set[str] = set()
        match_scores: dict[str, float] = {}
        matched_platforms: set[str] = set()

        for score, action, platform, source in scored:
            if action in seen:
                continue
            seen.add(action)
            allowed.append(action)
            sources.add(source)
            match_scores[action] = score
            matched_platforms.add(platform)
            if len(allowed) >= self.max_actions:
                break

        primary = platforms[0] if platforms else (routes[0].platform if routes else None)
        profile_labels = [f"{r.platform}:{r.catalog_profile}" for r in routes]

        return GroundingResult(
            matched_platforms=sorted(matched_platforms) or platforms[:3],
            allowed_actions=allowed,
            source_files=sorted(sources),
            match_scores=match_scores,
            routed_profiles=profile_labels,
            primary_platform=primary,
        )

    @property
    def entries(self) -> list[CatalogEntry]:
        return list(self._catalog)

    @property
    def catalog_count(self) -> int:
        return len(self._catalog)

    @property
    def is_loaded(self) -> bool:
        return len(self._catalog) > 0

    def summary(self) -> str:
        platforms = sorted({e.platform for e in self._catalog})
        total = sum(len(e.action_names) for e in self._catalog)
        return (
            f"KnowledgeBase(path={self.base_dir.resolve()}, "
            f"catalogs={self.catalog_count}, platforms={platforms}, actions={total})"
        )
