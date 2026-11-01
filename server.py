"""
The website's BACKEND (FastAPI). The browser page (web/) talks to these URLs:

  GET  /api/status              is a Gemini key configured?
  GET  /api/attacks             the attack library
  POST /api/scans               start a scan in the background -> {job_id}
  GET  /api/scans/{job_id}      live progress of a scan
  GET  /api/runs                all saved reports (summaries)
  GET  /api/runs/{run_id}       one full report
  GET  /api/runs/{run_id}/report.md   download as Markdown
  POST /practice-bot/chat       the offline practice chatbot, usable as a test endpoint

Run:  python server.py   then open http://localhost:8000
"""
import threading
import traceback
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from attacks import ATTACKS, ATTACKS_BY_ID, GOAL_LABELS
from llm import has_llm
from practice_bot import practice_reply
from redteam_agent import get_run, load_runs, run_attacks, save_run
from report import RECOMMENDATIONS, to_markdown
from targets import applicable, build_target

WEB_DIR = Path(__file__).parent / "web"
app = FastAPI(title="AgentAttacker")
JOBS: dict[str, dict] = {}   # job_id -> live progress (kept in memory)


class ScanRequest(BaseModel):
    target: dict
    attack_ids: list[str] = Field(default_factory=lambda: [a.id for a in ATTACKS])
    mutations: int = Field(0, ge=0, le=2)
    budget: int = Field(15, ge=1, le=60)


class ChatRequest(BaseModel):
    message: str


@app.get("/api/status")
def status():
    return {"gemini_configured": has_llm()}


@app.get("/api/attacks")
def attacks():
    return [a.__dict__ for a in ATTACKS]


@app.post("/api/scans")
def start_scan(req: ScanRequest):
    try:
        target = build_target(req.target)
    except (ValueError, KeyError) as e:
        raise HTTPException(400, str(e))
    unknown = [a for a in req.attack_ids if a not in ATTACKS_BY_ID]
    if unknown or not req.attack_ids:
        raise HTTPException(400, f"Pick at least one valid attack. Unknown: {unknown}")
    needs_gemini = target.uses_gemini or req.mutations > 0
    if needs_gemini and not has_llm():
        raise HTTPException(400, "This scan needs Gemini, but GOOGLE_API_KEY is not set in .env")

    planned = [a for a in req.attack_ids if applicable(ATTACKS_BY_ID[a], target)[0]]
    job_id = uuid.uuid4().hex[:10]
    JOBS[job_id] = {"status": "running", "target": target.info(), "planned": len(planned),
                    "events": [], "run_id": None, "error": None}
    threading.Thread(target=_run_job, args=(job_id, target, req), daemon=True).start()
    return {"job_id": job_id}


def _run_job(job_id: str, target, req: ScanRequest):
    job = JOBS[job_id]

    def on_update(node, update):
        if node == "judge":
            r = update["results"][0]
            job["events"].append({"type": "result", "attack_id": r["attack_id"], "name": r["name"],
                                  "owasp": r["owasp"], "attempt": r["attempt"], "success": r["success"],
                                  "evidence": r["evidence"], "blocked_by": r["blocked_by"]})
        elif node == "mutate":
            job["events"].append({"type": "mutate"})

    try:
        attacker = None
        if req.mutations:
            from llm import gemini
            attacker = gemini(temperature=0.9)
        results, summary = run_attacks(target, req.attack_ids, attacker, req.mutations, req.budget, on_update)
        job["run_id"] = save_run(target.info(), results, summary,
                                 {"mutations": req.mutations, "budget": req.budget})
        job["status"] = "done"
    except Exception as e:   # surface any failure (quota, bad endpoint, ...) to the UI
        traceback.print_exc()
        job["status"], job["error"] = "error", f"{type(e).__name__}: {e}"[:500]


@app.get("/api/scans/{job_id}")
def scan_progress(job_id: str):
    if job_id not in JOBS:
        raise HTTPException(404, "Unknown scan")
    return JOBS[job_id]


@app.get("/api/runs")
def runs():
    return [{"id": r["id"], "time": r["time"], "target": r["target"], "settings": r.get("settings", {}),
             "summary": {k: v for k, v in r["summary"].items() if k != "per_attack"}}
            for r in reversed(load_runs())]


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str):
    run = get_run(run_id)
    if not run:
        raise HTTPException(404, "Report not found")
    failed = sorted({a["goal"] for a in run["summary"]["per_attack"].values() if a["success"]})
    run["recommendations"] = [{"goal": g, "title": GOAL_LABELS[g], "text": RECOMMENDATIONS[g]} for g in failed]
    return run


@app.get("/api/runs/{run_id}/report.md", response_class=PlainTextResponse)
def run_markdown(run_id: str):
    run = get_run(run_id)
    if not run:
        raise HTTPException(404, "Report not found")
    return PlainTextResponse(to_markdown(run), headers={
        "Content-Disposition": f'attachment; filename="agentattacker-{run_id}.md"'})


@app.post("/practice-bot/chat")
def practice_chat(req: ChatRequest):
    return {"reply": practice_reply(req.message)}


@app.get("/")
def index():
    return FileResponse(WEB_DIR / "index.html")


app.mount("/", StaticFiles(directory=WEB_DIR), name="web")


if __name__ == "__main__":
    import uvicorn
    print("AgentAttacker running at http://localhost:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)
