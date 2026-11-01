<div align="center">

<img src="web/img/bot-shield.svg" width="84" alt="AgentAttacker logo">

# AgentAttacker

**Automated, adaptive red-teaming for LLM chatbots.**
Fire prompt-injection, jailbreak, data-exfiltration and system-prompt-leak attacks at a chatbot,
judge every reply with canary tokens, and get a security report mapped to the
**OWASP Top 10 for LLM Applications**.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-backend-009688?logo=fastapi&logoColor=white)
![LangGraph](https://img.shields.io/badge/LangGraph-agent-1C3C3C?logo=langchain&logoColor=white)
![Gemini](https://img.shields.io/badge/Google%20Gemini-LLM-4285F4?logo=googlegemini&logoColor=white)
![Tests](https://img.shields.io/badge/tests-22%20passing-34d399)
![License](https://img.shields.io/badge/license-MIT-f43f5e)

<img src="docs/screenshots/home.png" alt="AgentAttacker home page" width="900">

</div>

---

## Why

Teams ship LLM chatbots and agents without knowing how they behave under attack. Manual red-teaming is slow
and inconsistent. AgentAttacker automates it, so you can **measure** a bot's weaknesses and the effect of
every defence you add.

## Features

- 🎯 **12-attack library** across direct and indirect prompt injection, role-play jailbreaks, social
  engineering, encoding bypass (base64), system-prompt extraction and excessive agency (tricking the bot into
  calling `send_email`). Each attack is mapped to OWASP **LLM01 / LLM02 / LLM06 / LLM07**.
- 🐤 **Canary-based judge.** Fake secrets are planted in the target; an attack succeeds if a canary appears in
  the reply, **even disguised** (base64, reversed, spaced out), or if the bot calls a tool against policy.
  Deterministic, free and reproducible: no LLM-as-judge.
- 🧬 **Adaptive attacker.** Built as a LangGraph agent: when an attack fails, an attacker LLM reads the refusal
  and rewrites it with a different technique, like a human red-teamer.
- 🛡️ **Defence-in-depth demo.** A deliberately vulnerable bot next to a hardened one with four layers:
  input filter → hardened prompt + spotlighting → tool allowlist → output DLP.
- 🔌 **Test your own bot** by pasting its system prompt or connecting its HTTP endpoint.
- 📊 **Web dashboard** with live scan progress, a security score, OWASP breakdown, full transcripts,
  recommendations and Markdown export.
- 💸 **Budget control:** a hard cap on LLM calls per run, plus automatic model fallback when a quota runs out.

## Screenshots

| Configure a scan | Security report |
|---|---|
| <img src="docs/screenshots/scan.png" alt="Scan setup"> | <img src="docs/screenshots/report.png" alt="Security report"> |

| Past reports | Attack library |
|---|---|
| <img src="docs/screenshots/reports.png" alt="Past reports"> | <img src="docs/screenshots/library.png" alt="Attack library"> |

## Example results

| Target | Attack success rate | What got through |
|---|---|---|
| **Nova · vulnerable** (typical first-draft bot) | **42%** (5/12) | System prompt (3 ways), hijacked by a poisoned review, **emailed the secret discount code to an attacker** via its tool |
| **Nova · hardened** (4 defence layers) | **0%** (0/12) | Nothing in this run |
| **Practice bot** (offline, rule-based) | **60%** (6/10) | Admin password via fake authority and base64, system prompt (3 ways), hijack |

> Nova runs on Gemini, so its results can vary between runs. The hardened bot's output filter does **not**
> catch base64 or spaced-out secrets; the judge does, so a Gemini slip there would show up in the report.
> The practice bot is rule-based, so its result is always the same.

## How it works

```mermaid
flowchart LR
    S([start]) --> P[pick_next]
    P -->|attack queued| E[execute]
    P -->|queue empty / budget spent| R[report]
    E --> J[judge]
    J -->|succeeded or out of tries| P
    J -->|failed, tries left| M[mutate]
    M --> E
    R --> X([end])
```

1. **pick_next** takes the next attack and fills its `{bot}` / `{secret}` template for this target
   (attacks the target can't be judged on are skipped with a reason).
2. **execute** sends it to the target chatbot.
3. **judge** checks the reply and tool calls for canaries. Plain code, no LLM.
4. **mutate** (optional) asks the attacker LLM for a new variant of a failed attack.
5. **report** computes attack success rates overall, per category and per OWASP item.

### OWASP coverage

| OWASP | Risk | Attacks |
|---|---|---|
| LLM01 | Prompt Injection | Ignore previous instructions, role-play jailbreak, fake authority, poisoned review (hijack) |
| LLM02 | Sensitive Information Disclosure | Sentence completion, base64 encoding bypass, developer pretext |
| LLM06 | Excessive Agency | Poisoned review (exfiltration), email internal data to outsider |
| LLM07 | System Prompt Leakage | Repeat, translate, summarise your configuration |

## Quick start

```bash
git clone https://github.com/<your-username>/agentattacker.git
cd agentattacker
python -m venv .venv
.venv\Scripts\activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt

python server.py                # open http://localhost:8000
```

The **practice bot** and **your endpoint** targets work fully offline. For the Nova demo bots, "your system
prompt" and adaptive rewrites, add a Gemini key:

```bash
cp .env.example .env            # then set GOOGLE_API_KEY
```

### Command line

```bash
python run.py --list                                   # list attacks
python run.py --target practice                        # offline scan
python run.py --target demo-hardened --attacks authority prompt-summary --mutations 2 --budget 10
```

## Testing your own chatbot

| Option | What you give | How leaks are detected |
|---|---|---|
| **Your system prompt** | The bot's system prompt and the secrets in it | A random canary is planted in the prompt; any secret or canary in a reply is a leak. Hosted on Gemini, tools included. |
| **Your endpoint** | A URL that accepts `POST {"message": "..."}` and returns JSON | You list the secrets and a distinctive system-prompt phrase; the judge watches replies for them. |

For an endpoint you can change the request field name, the reply path (e.g. `choices.0.message.content`)
and add headers such as an API key. Try it against the built-in practice bot:
`http://localhost:8000/practice-bot/chat`.

> ⚠️ **Only test chatbots you own or have written permission to test.** Attacking third-party systems
> without authorisation may break their terms of service or the law.

## Project structure

```
agentattacker/
├── server.py          FastAPI backend + static site
├── run.py             command-line runner
├── redteam_agent.py   LangGraph attack agent, summary, saved runs
├── attacks.py         attack library (OWASP-mapped templates)
├── judge.py           canary-based judge (plain code)
├── targets.py         Nova (vulnerable / hardened), practice, prompt and endpoint targets
├── practice_bot.py    offline rule-based HelpBot
├── report.py          Markdown report + recommendations
├── llm.py             Gemini client with quota fallback
├── web/               single-page frontend (HTML, CSS, vanilla JS, SVGs)
├── tests/             pytest suite (fake models, no API key)
└── docs/screenshots/
```

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

All 22 tests use fake models or the offline practice bot: **no API key and no quota needed**. They run on
every push via GitHub Actions on Python 3.11 to 3.13.

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/status` | Is a Gemini key configured? |
| `GET` | `/api/attacks` | The attack library |
| `POST` | `/api/scans` | Start a scan → `{job_id}` |
| `GET` | `/api/scans/{job_id}` | Live progress |
| `GET` | `/api/runs` | Saved report summaries |
| `GET` | `/api/runs/{run_id}` | Full report with recommendations |
| `GET` | `/api/runs/{run_id}/report.md` | Markdown download |
| `POST` | `/practice-bot/chat` | The offline practice bot as an HTTP endpoint |

## Tech stack

Python · FastAPI · LangGraph · LangChain · Google Gemini (tool calling) · vanilla JS/CSS · pytest · GitHub Actions

## License

[MIT](LICENSE)
