# pip install pydantic

"""
Modular platform routing for knowledge-base catalog selection.

Plug-in pattern for new platforms:
  1. Add PLATFORM_SIGNALS entry in knowledge_base.py
  2. Add profile signal maps below (or new PlatformRouter method)
  3. Drop JSON catalog(s) under knowledge_base/ with catalog_profile field
"""

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# GitHub: CI/CD workflow / Actions runtime triggers (Files A / Links 1–2)
GITHUB_WORKFLOW_SIGNALS = [
    "github actions",
    "workflow",
    "workflow_dispatch",
    "workflow_run",
    "pull_request_target",
    "pull_request",
    "ci/cd",
    "pipeline",
    "runner",
    "artifact",
    "schedule",
    "repository_dispatch",
    "actions yaml",
    ".github/workflows",
    "self-hosted runner",
]

# GitHub: org audit / admin / exposure (File B / Link 3)
GITHUB_AUDIT_SIGNALS = [
    "audit log",
    "organization audit",
    "org.",
    "repo.destroy",
    "repo.public",
    "secret_scanning",
    "two-factor",
    "2fa",
    "bypass",
    "administrative",
    "organization owner",
    "codespaces",
    "oauth_application",
    "outside collaborator",
    "branch protection",
    "cb_protection",
]

# Azure: disaster recovery disruption, infra deletion, RBAC (File A / ARM admin)
AZURE_ADMIN_SIGNALS = [
    "azure",
    "microsoft.recoveryservices",
    "recoveryservices",
    "replicationfabrics",
    "replication network",
    "disaster recovery",
    "site recovery",
    "resourcegroups",
    "resource group",
    "arm template",
    "rbac",
    "role assignment",
    "role definition",
    "privilege escalation",
    "infrastructure deletion",
    "vault delete",
    "replicationfabric",
    "networkmapping",
    "microsoft.authorization",
    "delete resource",
]

# Azure: Entra ID directory, tokens, service principals (File B)
AZURE_AUTH_SIGNALS = [
    "entra id",
    "microsoft entra",
    "entra",
    "aad",
    "active directory",
    "service principal",
    "application consent",
    "delegated permission",
    "conditional access",
    "federation",
    "directory change",
    "token manipulation",
    "oauth",
    "oidc",
    "sign-in",
    "signin",
    "password reset",
    "credential",
    "add member to group",
    "app role assignment",
]

AZURE_SIGNALS = [
    "azure",
    "microsoft azure",
    "entra",
    "microsoft entra",
    "aad",
    "arm",
    "defender",
    "resource manager",
]

# Okta: authentication, session hijacking, MFA exhaustion, recovery evasion (Files A / Links 1 & 3)
OKTA_AUTH_SIGNALS = [
    "okta",
    "mfa",
    "multi-factor",
    "session hijacking",
    "session hijack",
    "identity takeover",
    "account takeover",
    "sign-in",
    "signin",
    "sign in",
    "recovery",
    "password reset",
    "self-service",
    "impersonation",
    "credential stuffing",
    "brute force",
    "factor deactivate",
    "factor enroll",
    "saml bypass",
    "sso bypass",
    "authentication",
    "user.session",
    "user.mfa",
    "user.account.recovery",
]

# Okta: directory administration, privilege grants, API tokens, policy lifecycle (File B / Link 2)
OKTA_ADMIN_SIGNALS = [
    "okta admin",
    "admin console",
    "directory administration",
    "administrative",
    "global policy",
    "policy lifecycle",
    "policy rule",
    "api token",
    "rogue token",
    "user privilege",
    "privilege grant",
    "privilege escalation",
    "super admin",
    "org policy",
    "application lifecycle",
    "system.api_token",
    "policy.lifecycle",
    "user.user_privilege",
    "group policy",
    "identity provider",
    "federation",
]

OKTA_SIGNALS = ["okta", "okta verify", "okta idp", "okta system log"]


@dataclass(frozen=True)
class RoutedProfile:
    platform: str
    catalog_profile: str
    score: float


class PlatformRouter:
    """Selects which catalog_profile(s) to load per detected platform."""

    @staticmethod
    def _score_signals(text: str, signals: list[str]) -> float:
        lower = text.lower()
        return sum(1.0 for s in signals if s in lower)

    def route_github(self, text: str) -> list[RoutedProfile]:
        workflow_score = self._score_signals(text, GITHUB_WORKFLOW_SIGNALS)
        audit_score = self._score_signals(text, GITHUB_AUDIT_SIGNALS)
        routed: list[RoutedProfile] = []

        if workflow_score == 0 and audit_score == 0:
            # Ambiguous GitHub mention — include both profiles for split grounding
            routed.append(RoutedProfile("github", "github_workflow", 0.5))
            routed.append(RoutedProfile("github", "github_audit", 0.5))
            logger.info("github_route_default both profiles (low signal)")
            return routed

        if workflow_score >= audit_score and workflow_score > 0:
            routed.append(RoutedProfile("github", "github_workflow", workflow_score))
        if audit_score > workflow_score and audit_score > 0:
            routed.append(RoutedProfile("github", "github_audit", audit_score))
        if workflow_score == audit_score and workflow_score > 0:
            if not any(r.catalog_profile == "github_workflow" for r in routed):
                routed.append(RoutedProfile("github", "github_workflow", workflow_score))
            if not any(r.catalog_profile == "github_audit" for r in routed):
                routed.append(RoutedProfile("github", "github_audit", audit_score))

        logger.info(
            "github_route workflow_score=%.1f audit_score=%.1f profiles=%s",
            workflow_score,
            audit_score,
            [r.catalog_profile for r in routed],
        )
        return routed

    def route_okta(self, text: str) -> list[RoutedProfile]:
        auth_score = self._score_signals(text, OKTA_AUTH_SIGNALS)
        admin_score = self._score_signals(text, OKTA_ADMIN_SIGNALS)
        routed: list[RoutedProfile] = []

        if auth_score == 0 and admin_score == 0:
            routed.append(RoutedProfile("okta", "okta_auth", 0.5))
            routed.append(RoutedProfile("okta", "okta_admin", 0.5))
            logger.info("okta_route_default both profiles (low signal)")
            return routed

        if auth_score >= admin_score and auth_score > 0:
            routed.append(RoutedProfile("okta", "okta_auth", auth_score))
        if admin_score > auth_score and admin_score > 0:
            routed.append(RoutedProfile("okta", "okta_admin", admin_score))
        if auth_score == admin_score and auth_score > 0:
            if not any(r.catalog_profile == "okta_auth" for r in routed):
                routed.append(RoutedProfile("okta", "okta_auth", auth_score))
            if not any(r.catalog_profile == "okta_admin" for r in routed):
                routed.append(RoutedProfile("okta", "okta_admin", admin_score))

        logger.info(
            "okta_route auth_score=%.1f admin_score=%.1f profiles=%s",
            auth_score,
            admin_score,
            [r.catalog_profile for r in routed],
        )
        return routed

    def route_azure(self, text: str) -> list[RoutedProfile]:
        admin_score = self._score_signals(text, AZURE_ADMIN_SIGNALS)
        auth_score = self._score_signals(text, AZURE_AUTH_SIGNALS)
        routed: list[RoutedProfile] = []

        if admin_score == 0 and auth_score == 0:
            routed.append(RoutedProfile("azure", "azure_admin", 0.5))
            routed.append(RoutedProfile("azure", "azure_auth", 0.5))
            logger.info("azure_route_default both profiles (low signal)")
            return routed

        if admin_score >= auth_score and admin_score > 0:
            routed.append(RoutedProfile("azure", "azure_admin", admin_score))
        if auth_score > admin_score and auth_score > 0:
            routed.append(RoutedProfile("azure", "azure_auth", auth_score))
        if admin_score == auth_score and admin_score > 0:
            if not any(r.catalog_profile == "azure_admin" for r in routed):
                routed.append(RoutedProfile("azure", "azure_admin", admin_score))
            if not any(r.catalog_profile == "azure_auth" for r in routed):
                routed.append(RoutedProfile("azure", "azure_auth", auth_score))

        logger.info(
            "azure_route admin_score=%.1f auth_score=%.1f profiles=%s",
            admin_score,
            auth_score,
            [r.catalog_profile for r in routed],
        )
        return routed

    def route(self, text: str, detected_platforms: list[str]) -> list[RoutedProfile]:
        lower = text.lower()
        routes: list[RoutedProfile] = []

        if "aws" in detected_platforms or re.search(r"\baws\b", lower):
            routes.append(RoutedProfile("aws", "iam", 1.0))
        if "gcp" in detected_platforms or "google cloud" in lower or re.search(r"\bgcp\b", lower):
            routes.append(RoutedProfile("gcp", "iam", 1.0))
        if "github" in detected_platforms or "github" in lower:
            routes.extend(self.route_github(text))
        if "okta" in detected_platforms or self._score_signals(text, OKTA_SIGNALS) > 0:
            routes.extend(self.route_okta(text))
        if "azure" in detected_platforms or self._score_signals(text, AZURE_SIGNALS) > 0:
            routes.extend(self.route_azure(text))

        return routes
