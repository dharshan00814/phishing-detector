# Project Housekeeping

## Completed
- [x] Removed duplicate root-level frontend files (served from `frontend/` instead)
- [x] Removed unused `venv/` directory (`.venv/` is the active environment)
- [x] Removed superseded `train_model.py` (use `train_models.py` — trains both URL + email models)
- [x] Removed standalone CLI tools `predict.py` and `whois_lookup.py` (logic lives in `backend/`)
- [x] Expanded suspicious keyword lists in `backend/url_analyzer.py` and `phishing_ml_model/feature_extractor.py`

## Maintenance notes
- Frontend is served by Flask from `frontend/` — do not add root-level copies.
- After changing `feature_extractor.py` keywords, retrain: `python phishing_ml_model/train_models.py`
- Vercel deploys require the `[project]` table in `pyproject.toml`; Render uses `render.yaml`.
