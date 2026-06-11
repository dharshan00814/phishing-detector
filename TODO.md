# TODO - Fix Build Failed (uv lock / pyproject issue)

- [x] Identify root cause: platform build runs `uv lock --python ...` and fails with `No project table found in: /vercel/path0/pyproject.toml`
- [x] Verify local `pyproject.toml` DOES include a `[project]` table
- [ ] Fix Vercel build: stop triggering `uv lock` (switch to a pure `pip install -r requirements.txt` build)
- [ ] Re-run failing build to confirm error is gone

