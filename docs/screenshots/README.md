# Screenshots — How to Add Them

This directory is intentionally empty. **No screenshots are committed to the
repository** so that the project never stores stale or fabricated UI captures.

The README section `## Product Walkthrough` references these files. To complete
the portfolio presentation, open the deployed application and capture each
screen with a modern browser (Chrome/Edge) at a window size of at least
`1440 × 900` (fullscreen), then save it under the exact file name below.

## Required captures

| # | File name                       | Where to capture in the app                                |
|---|---------------------------------|-----------------------------------------------------------|
| 1 | `01-command-center.png`         | **Overview** — dashboard with metrics, charts, active incidents |
| 2 | `02-incident-investigation.png` | **Incidents → open an incident** — timeline, evidence, recommendations |
| 3 | `03-ai-analyst.png`             | **AI Analyst** — run analysis on a sample event and capture the output |
| 4 | `04-threat-intelligence.png`    | **Threat Intelligence / Vulnerabilities** — NVD + CISA KEV view |
| 5 | `05-live-events.png`            | **Live Events** — WebSocket event stream while it is flowing |
| 6 | `06-mitre-attack.png`           | **MITRE ATT&CK** — matrix with observed / simulated status |
| 7 | `07-response-audit.png`         | **Playbooks + Audit Log** — run a simulated action, then capture the audit entry |

## Editing guidance

- Crop out any personal browser UI (bookmarks bar, extensions).
- Do **not** redact or photoshop metric values — screenshots should show what
  the running system actually displays.
- Keep the files under ~500 KB each (PNG). If a capture is large, crop the
  target region instead of scaling it down.

## Once added

Rebuild nothing — Markdown images are relative:

```markdown
![Command Center](docs/screenshots/01-command-center.png)
```

GitHub (and the Vercel preview) will render the captures automatically.
