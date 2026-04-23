# PhishGuard

A real-time phishing detection browser extension with a Python/FastAPI backend.

## Architecture

```
phishguard/        ← Chrome extension (MV3)
  content.js       ← scrapes page features, triggers analysis
  background.js    ← sends features to backend, stores result
  popup.{html,js,css}  ← UI overlay showing result and user lists

backend/           ← FastAPI server
  main.py          ← composition root: wires checks, providers, routers
  controllers/     ← HTTP route handlers
    analysis.py    ← POST /analyse
    lists.py       ← /lists CRUD
    report.py      ← POST /report
  services/
    url_analysis.py     ← orchestrator: runs the check pipeline
    report_generator.py ← LLM + WHOIS + Jinja2 → HTML/PDF
  checks/          ← detection checks (one class per rule)
    whitelist_check.py  ← Tier 0
    tier1_checks.py     ← Tier 1 hard rules
    tier2_checks.py     ← Tier 2 heuristics
    tier3_ml.py         ← Tier 3 ML model
  providers/
    blacklist.py        ← OpenPhish feed + local file fallback
    user_lists.py       ← user-defined whitelist/blacklist
  utils/
    url_features.py     ← static URL feature extraction
    whois_lookup.py     ← domain age / registrar lookup
  models/models.py      ← Pydantic request/response models
  ml/
    features.py         ← FIELD_MAP (single source of truth)
    train.py            ← model training script
    preprocessor.py     ← post-inference signal injection
  config/
    user_lists.json     ← persisted user blacklist/whitelist
  blacklist.txt         ← bundled fallback blacklist
```

## Detection Pipeline

| Tier   | Check                          | Triggers                                              |
|--------|--------------------------------|-------------------------------------------------------|
| Tier 0 | `WhitelistCheck`               | User-trusted domain → instant ALLOW (short-circuit)   |
| Tier 1 | `UserBlacklistCheck`           | User-blocked domain                                   |
| Tier 1 | `BlacklistCheck`               | Domain in OpenPhish feed or bundled blacklist         |
| Tier 1 | `IPAddressCheck`               | URL uses raw IP instead of domain                     |
| Tier 1 | `IFrameTrapCheck`              | Password field in untrusted iframe                    |
| Tier 1 | `InsecurePasswordCheck`        | Password field served over HTTP                       |
| Tier 1 | `BrandImpersonationCheck`      | Known brand name appearing in non-official domain     |
| Tier 2 | `HeuristicCheck`               | URL obfuscation, dead links, external ratio, form behaviour, auto-download, meta refresh |
| Tier 3 | `MLCheck`                      | RandomForest on 15 PhiUSIIL features + post-inference signals |

Tier 1 checks can immediately set BLOCK. Tier 2 and Tier 3 contribute to a cumulative score; thresholds are `score >= 9` → BLOCK, `score >= 6` → WARN.

## Setup

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                  # then edit and add GROQ_API_KEY
uvicorn main:app --reload
```

### Extension

1. Open `chrome://extensions`
2. Enable Developer Mode
3. Load Unpacked → select the `phishguard/` folder
4. Copy the new extension ID into `backend/.env` as `EXTENSION_ID`

## Configuration

- **User lists** — managed through the popup's Settings panel. Persisted to `backend/config/user_lists.json` via the `/lists` API.
- **Blacklist fallback** — `backend/blacklist.txt`, one domain per line. Used when the OpenPhish feed is unreachable.
- **Brand list** — defined in code in `BrandImpersonationCheck.BRANDS` and `BRAND_EXTRAS` (`backend/checks/tier1_checks.py`). Smart base-name matching means country variants (`amazon.co.uk`, `amazon.de` etc.) work without explicit listing.
- **Rate limit** — set `RATE_LIMIT` in `backend/.env` (default `60/minute`). The `/report` endpoint is fixed at `10/minute` because LLM calls are expensive.
- **CORS origin** — set `EXTENSION_ID` in `backend/.env` so CORS only accepts the right extension.

## Production Notes

- The default blacklist is the OpenPhish public feed. For higher fidelity, use a paid threat-intel feed by replacing `LiveFeedBlacklist` in `main.py`.
- Add HTTPS/TLS to the backend before any public deployment.
- The `confidence` score uses a sigmoid curve over the cumulative tier score. The ML probability is weighted at 0.6× before being added to heuristic scores to avoid scale mismatch.
- Never commit `backend/.env` — it is in `.gitignore`. If you ever accidentally commit it, **rotate every secret it contained immediately**, then run `git filter-repo` to scrub history.
