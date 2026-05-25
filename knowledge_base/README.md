# Knowledge Base — Local Event Catalogs

Authoritative action/event names are stored **locally** (no runtime GitHub URLs).

## Layout

```
knowledge_base/
├── catalogs/
│   ├── aws_iam_actions.json       # iann0036 aws/docs.json
│   └── gcp_iam_permissions.json   # iann0036 gcp/permissions.json
├── github_actions_workflow.json   # GitHub Actions trigger events (Links 1–2)
├── github_audit_logs.json         # Org audit log events (Link 3)
├── okta_auth_events.json          # Sign-in, MFA, session, recovery (Links 1 & 3)
├── okta_admin_events.json         # Policy, privileges, API tokens (Link 2)
├── azure_auth_events.json         # Entra ID identity & authentication vectors
├── azure_admin_events.json        # ARM admin, DR/replication, RBAC (iann0036)
└── ...
```

## GitHub routing

The `PlatformRouter` selects catalog profile by threat context:

| Profile | File | When |
|---------|------|------|
| `github_workflow` | `github_actions_workflow.json` | CI/CD, workflows, `pull_request_target`, runners |
| `github_audit` | `github_audit_logs.json` | Org admin, audit log, bypass, `repo.destroy`, 2FA |

AWS/GCP continue to use `catalogs/*` IAM datasets unchanged.

## Azure routing

| Profile | File | When |
|---------|------|------|
| `azure_admin` | `azure_admin_events.json` | DR disruption, replication deletion, RBAC, resource group changes |
| `azure_auth` | `azure_auth_events.json` | Entra ID directory, service principals, tokens, conditional access |

Rebuild from iann0036 provider operations:

```bash
python scripts/build_azure_catalogs.py
```

## Okta routing

| Profile | File | When |
|---------|------|------|
| `okta_auth` | `okta_auth_events.json` | Session hijacking, MFA exhaustion, sign-in/recovery evasion |
| `okta_admin` | `okta_admin_events.json` | Policy lifecycle, privileges, API tokens, directory admin |

Rebuild from the official Event Types CSV:

```bash
python scripts/build_okta_catalogs.py
```

## Refresh AWS / GCP from upstream

```bash
python scripts/sync_knowledge_base.py
```

Downloads once into `catalogs/*.raw.json`, then builds compact `*_iam_*.json` catalogs the loader reads.

## Add more platforms

Drop JSON files using this schema:

```json
{
  "platform": "okta",
  "display_name": "Okta",
  "keywords": ["okta", "oauth"],
  "actionNames": ["user.session.start", "..."]
}
```

## Attribution

AWS and GCP catalogs are derived from [iann0036/iam-dataset](https://github.com/iann0036/iam-dataset) (vendored locally via sync script).
