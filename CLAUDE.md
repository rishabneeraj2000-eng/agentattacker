# AgentAttacker

Automated red-teaming for LLM chatbots: a LangGraph agent fires OWASP-mapped attacks at a target bot,
a canary-based judge (plain code, no LLM) decides success, results are shown in a FastAPI + vanilla-JS site.

## Commands

```bash
python server.py                 # web app at http://localhost:8000
python -m pytest                 # full test suite (no API key needed)
python run.py --target practice  # offline CLI scan
```

## Architecture

- `attacks.py` attack templates (`{bot}`, `{secret}` placeholders), `GOAL_LABELS`
- `judge.py` canary detection incl. base64 / reversed / spaced forms
- `targets.py` Nova (vulnerable/hardened), practice, prompt, endpoint targets; `applicable()`; `build_target()`
- `redteam_agent.py` LangGraph graph (pick_next → execute → judge → mutate/report), `summarise()`, saved runs in `runs/`
- `report.py` Markdown report and `RECOMMENDATIONS`
- `server.py` REST API + serves `web/`
- `examples/sample_chatbot.py` standalone Gemini chatbot ("Byte", port 8001) for testing the endpoint target
- `web/` single-page app: `index.html`, `styles.css`, `app.js` (hash routes `#/`, `#/scan`, `#/report/<id>`, `#/reports`, `#/library`)

## Rules

- **Gemini costs quota.** Never run anything that calls Gemini (Nova targets, prompt target, mutations > 0,
  `llm.gemini()`) without asking the user first. Verify changes with the practice bot and `python -m pytest`.
- Tests must stay offline: use `FakeModel` / `FakeHTTP` / `PracticeTarget`, never a real API key.
- Do only what was asked. If you'd like to change something beyond the request, propose it and wait for approval.
- When adding an attack, give it an OWASP code and a `goal` the judge understands (`leak_secret`,
  `leak_prompt`, `exfil_email`, `hijack`).
- When changing `targets.applicable()`, mirror it in `skipReason()` in `web/app.js` (the scan page uses it to dim attacks that will be skipped).
- When adding a judge goal, add its label to `GOAL_LABELS` and its text to `RECOMMENDATIONS`; `/api/runs/{id}` uses both.

## Frontend conventions

- No framework, no build step. Plain ES2020 in `app.js`.
- Escape every server/user string with `esc()` before putting it in HTML (transcripts contain attacker text).
- Colours only via CSS variables in `:root` (`--accent`, `--accent-2`, `--red`, `--green`, …); theme is navy + crimson/coral.
- Images live in `web/img/` as SVG; reference them with `<img>` (their gradient ids collide if inlined).

## Repo hygiene

- Never commit `.env` or `runs/`.
- Keep `README.md` (test count, results table, structure) and `requirements.txt` in sync with the code.
- Regenerate `docs/screenshots/` after visible UI changes.
